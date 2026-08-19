import os
import git
import tempfile
import shutil
import subprocess
import traceback
import uuid
import json
import re
import requests

from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq

from app.reporter import generate_pdf_report
from app.database import engine, get_db
from app.models import Base, Repository, Scan, Vulnerability
from app.scanner.ast_engine import scan_code_string, scan_directory
from app.tasks import run_async_scan
from app.celery_app import celery_app
from dotenv import load_dotenv

# 🟢 Data Science Benchmark Evaluation Engine ကို Import လုပ်ခြင်း
from metrics_engine import evaluate_model_metrics
from app.scanner.url_engine import extract_url_features

load_dotenv()
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Automated Code Security Scanner API")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

try:
    if GROQ_API_KEY and "gsk_" in GROQ_API_KEY:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("✅ Groq API Client successfully initialized!")
    else:
        groq_client = None
        print(f"❌ Warning: Invalid GROQ_API_KEY format or missing: '{GROQ_API_KEY[:7]}...'")
except Exception as e:
    groq_client = None
    print(f"❌ Groq Initialization Error: {e}")


class RepoScanRequest(BaseModel):
    repo_name: str
    repo_url: str


class CodeSnippetRequest(BaseModel):
    code_string: str


class AICoachRequest(BaseModel):
    vulnerability_type: str
    suggestion: str
    vulnerable_code: str


class URLScanRequest(BaseModel):
    url: str


class WebAuditRequest(BaseModel):
    url: str


def do_git_clone_and_scan(repo_url: str):
    scan_folder_name = f"scan_{uuid.uuid4().hex[:8]}"
    temp_dir = os.path.join(tempfile.gettempdir(), scan_folder_name)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"

    cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)

    if result.returncode != 0:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

        err_msg = result.stderr.strip()
        if "Could not resolve host" in err_msg or "unable to access" in err_msg or "Failed to connect" in err_msg:
            raise Exception("🌐 Internet ချိတ်ဆက်မှု မရှိသေးပါ။ ကျေးဇူးပြု၍ Internet Connection ကို စစ်ဆေးပြီးမှ ပြန်လည် စမ်းသပ်ပေးပါ။")

        raise Exception(f"Git Clone Error: {err_msg}")

    raw_issues = scan_directory(temp_dir)

    formatted_issues = []
    for issue in raw_issues:
        sev = issue.get("severity") or "HIGH"
        v_type = issue.get("vulnerability_type") or issue.get("type") or "SECURITY_RISK"
        f_path = issue.get("file_path") or issue.get("file") or "unknown_file"
        l_num = issue.get("line_number") or issue.get("line") or 1
        sugg = issue.get("suggestion") or "မလုံခြုံသော Code Pattern ကို ပြန်လည် ပြင်ဆင်ပါ။"
        vuln_code = issue.get("vulnerable_code") or issue.get("code") or issue.get("snippet") or ""
        sec_code = issue.get("secure_code") or ""

        formatted_issues.append({
            "severity": str(sev).upper(),
            "vulnerability_type": str(v_type),
            "type": str(v_type),
            "file_path": str(f_path),
            "line_number": int(l_num),
            "suggestion": str(sugg),
            "vulnerable_code": str(vuln_code),
            "secure_code": str(sec_code)
        })

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

    return formatted_issues


@app.post("/scan/git")
async def scan_git_repository(payload: RepoScanRequest, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(
        Repository.repo_url == payload.repo_url,
        Repository.repo_name == payload.repo_name
    ).first()

    if not repo:
        repo = Repository(repo_name=payload.repo_name, repo_url=payload.repo_url)
        db.add(repo)
        db.commit()
        db.refresh(repo)

    try:
        issues = await run_in_threadpool(do_git_clone_and_scan, payload.repo_url)
    except Exception as e:
        print("\n=== [DEBUG ERROR LOG START] ===")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Details: {str(e)}")
        traceback.print_exc()
        print("=== [DEBUG ERROR LOG END] ===\n")
        raise HTTPException(status_code=400, detail=str(e))

    scan_record = Scan(
        repo_id=repo.id,
        status="COMPLETED",
        total_issues=len(issues)
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    for issue in issues:
        vuln = Vulnerability(
            scan_id=scan_record.id,
            severity=issue["severity"],
            vulnerability_type=issue["vulnerability_type"],
            file_path=issue["file_path"],
            line_number=issue["line_number"],
            suggestion=issue["suggestion"],
            vulnerable_code=issue["vulnerable_code"],
            secure_code=issue["secure_code"]
        )
        db.add(vuln)

    db.commit()

    return {
        "scan_id": f"SCAN-{scan_record.id}",
        "repo_name": repo.repo_name,
        "repo_url": repo.repo_url,
        "total_issues": len(issues),
        "vulnerabilities": issues,
        "issues": issues
    }


@app.post("/scan/snippet")
def scan_code_snippet(payload: CodeSnippetRequest, db: Session = Depends(get_db)):
    try:
        raw_issues = scan_code_string(payload.code_string)

        formatted_issues = []
        for issue in raw_issues:
            sev = issue.get("severity") or "HIGH"
            v_type = issue.get("vulnerability_type") or issue.get("type") or "SECURITY_RISK"
            f_path = issue.get("file_path") or issue.get("file") or "snippet_input"
            l_num = issue.get("line_number") or issue.get("line") or 1
            sugg = issue.get("suggestion") or "မလုံခြုံသော Code Pattern ကို ပြန်လည် ပြင်ဆင်ပါ။"
            vuln_code = issue.get("vulnerable_code") or issue.get("code") or issue.get("snippet") or ""
            sec_code = issue.get("secure_code") or ""

            formatted_issues.append({
                "severity": str(sev).upper(),
                "vulnerability_type": str(v_type),
                "type": str(v_type),
                "file_path": str(f_path),
                "line_number": int(l_num),
                "suggestion": str(sugg),
                "vulnerable_code": str(vuln_code),
                "secure_code": str(sec_code)
            })

        repo = db.query(Repository).filter(Repository.repo_name == "Direct Code Snippet Audit").first()
        if not repo:
            repo = Repository(repo_name="Direct Code Snippet Audit", repo_url="N/A (Snippet)")
            db.add(repo)
            db.commit()
            db.refresh(repo)

        scan_record = Scan(
            repo_id=repo.id,
            status="COMPLETED",
            total_issues=len(formatted_issues)
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        for issue in formatted_issues:
            vuln = Vulnerability(
                scan_id=scan_record.id,
                severity=issue["severity"],
                vulnerability_type=issue["vulnerability_type"],
                file_path=issue["file_path"],
                line_number=issue["line_number"],
                suggestion=issue["suggestion"],
                vulnerable_code=issue["vulnerable_code"],
                secure_code=issue["secure_code"]
            )
            db.add(vuln)

        db.commit()

        return {
            "scan_id": f"SCAN-{scan_record.id}",
            "total_issues": len(formatted_issues),
            "vulnerabilities": formatted_issues,
            "issues": formatted_issues
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Snippet Scan Failed: {str(e)}")


# 🤖 REAL AI SECURITY COACH ENDPOINT WITH DYNAMIC MODEL FETCHING
@app.post("/api/ai-coach")
def get_ai_coach_explanation(req: AICoachRequest):
    if not groq_client:
        print("❌ Groq API client is missing or uninitialized. Falling back...")
        return get_fallback_ai_response(req)

    system_instructions = (
        "You are an elite Cyber Security Specialist and AI Security Coach.\n"
        "Analyze the given security vulnerability thoroughly.\n"
        "You MUST respond STRICTLY in a valid JSON object matching the requested schema.\n"
        "Do NOT wrap the JSON in Markdown code blocks like ```json or ```.\n"
        "Provide explanations for 'why_dangerous' and 'hacking_scenario' in clear, professional Myanmar language."
    )

    user_prompt = f"""
Vulnerability Analysis Request:
- Vulnerability Type: {req.vulnerability_type}
- Static Scanner Suggestion: {req.suggestion}
- Vulnerable Code:
{req.vulnerable_code}

Return STRICTLY this JSON layout:
{{
  "cvss_score": 9.8,
  "cvss_severity": "CRITICAL",
  "mitre_id": "T1552.001",
  "mitre_name": "Unsecured Credentials",
  "why_dangerous": "Detailed explanation in Myanmar language of why this code is dangerous.",
  "hacking_scenario": "Step-by-step exploit story in Myanmar language explaining how an attacker targets this.",
  "poc_command": "A realistic command or script line used during penetration testing",
  "recommendation": "# Refactored Production-Ready Secure Code Fix with comments"
}}
"""

    # 🟢 1. Fetch active available models dynamically from Groq
    available_models = []
    try:
        models_list = groq_client.models.list()
        available_models = [m.id for m in models_list.data if m.id]
        print(f"📋 Dynamically Fetched Groq Models: {available_models}")
    except Exception as e:
        print(f"⚠️ Failed to fetch models dynamically: {e}")

    # Fallback list if dynamic list is empty
    if not available_models:
        available_models = ["llama-3.3-70b-versatile", "llama3-8b-8192"]

    response = None
    last_error = None

    # 🟢 2. Iterate through available models
    for model_name in available_models:
        try:
            print(f"🤖 Attempting Groq AI Analysis using Model: '{model_name}'...")
            response = groq_client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_instructions},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )
            if response and response.choices:
                print(f"✅ Successfully generated response using model: '{model_name}'")
                break
        except Exception as e:
            print(f"⚠️ Model '{model_name}' failed: {e}")
            last_error = e
            continue

    if not response or not response.choices:
        print("\n================ ALL GROQ MODELS FAILED ================")
        print(f"Last Error: {last_error}")
        print("========================================================\n")
        return get_fallback_ai_response(req)

    try:
        raw_text = response.choices[0].message.content or "{}"

        # Safe Regex Parsing
        json_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        clean_json = json_match.group(0) if json_match else raw_text

        ai_data = json.loads(clean_json)

        return {
            "vulnerability_type": req.vulnerability_type,
            "cvss_score": float(ai_data.get("cvss_score", 8.5)),
            "cvss_severity": str(ai_data.get("cvss_severity", "HIGH")),
            "mitre_id": str(ai_data.get("mitre_id", "T1552")),
            "mitre_name": str(ai_data.get("mitre_name", "Unsecured Credentials")),
            "why_dangerous": str(ai_data.get("why_dangerous", "မလုံခြုံသော Code Pattern ဖြစ်ပါသည်။")),
            "hacking_scenario": str(ai_data.get("hacking_scenario", "Attacker များက ယခု Vulnerability ကို အသုံးချနိုင်ပါသည်။")),
            "poc_command": str(ai_data.get("poc_command", f"grep -ri '{req.vulnerability_type}' ./src")),
            "recommendation": str(ai_data.get("recommendation", "# ✅ Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ")),
            "remediation_logic": str(ai_data.get("recommendation", "# ✅ Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ"))
        }

    except Exception as e:
        print(f"❌ JSON Parsing Error: {e}")
        return get_fallback_ai_response(req)


def get_fallback_ai_response(req: AICoachRequest):
    vtype = req.vulnerability_type.upper()

    if "AWS" in vtype or "GITHUB" in vtype or "STRIPE" in vtype or "SECRET" in vtype or "KEY" in vtype or "PASSWORD" in vtype:
        hacking_scenario = "GitHub ပေါ် Code တင်မိလိုက်တာနဲ့ Automated Bots တွေက စက္ကန့်ပိုင်းအတွင်း Key ကို ခိုးယူပြီး Cloud Infrastructure တွေကို ဖျက်ဆီးသွားနိုင်ပါတယ်။"
        why_dangerous = "Credentials များကို Source Code ထဲ Plain Text အတိုင်း ရေးထားမိလို့ဖြစ်ပါတယ်။"
        recommendation = "# ✅ Python: Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပြီး os.getenv() ကို အသုံးပြုပါ\nimport os\nSECRET_KEY = os.getenv('SECRET_KEY')"
        poc = "grep -rn 'SECRET_KEY' ."
        mitre_id = "T1552.001"
        mitre_name = "Unsecured Credentials: Credentials In Files"
        cvss = 9.8
        sev = "CRITICAL"
    else:
        hacking_scenario = "Attacker များသည် မလုံခြုံသော System Code Pattern များကို အသုံးချ၍ Application Control ကို ရယူနိုင်ပါသည်။"
        why_dangerous = "Unsanitized User Data သို့မဟုတ် Insecure Functions များ သုံးထားခြင်းကြောင့် ဖြစ်ပါသည်။"
        recommendation = "# ✅ Secure Coding Guidelines များကို လိုက်နာပါ"
        poc = f"grep -rn '{req.vulnerability_type}' ."
        mitre_id = "T1059"
        mitre_name = "Command and Scripting Interpreter"
        cvss = 7.5
        sev = "HIGH"

    return {
        "vulnerability_type": req.vulnerability_type,
        "cvss_score": cvss,
        "cvss_severity": sev,
        "mitre_id": mitre_id,
        "mitre_name": mitre_name,
        "why_dangerous": why_dangerous,
        "hacking_scenario": hacking_scenario,
        "poc_command": poc,
        "recommendation": recommendation,
        "remediation_logic": recommendation
    }


# 🟢 DATA SCIENCE & BENCHMARK EVALUATION METRICS ENDPOINT
@app.get("/api/benchmark-metrics")
def get_benchmark_metrics():
    try:
        return evaluate_model_metrics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate metrics: {str(e)}")


@app.get("/reports/json/{scan_id}")
def export_json_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    vuln_data = [
        {
            "severity": v.severity,
            "type": v.vulnerability_type,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "suggestion": v.suggestion,
            "vulnerable_code": v.vulnerable_code,
            "secure_code": v.secure_code
        }
        for v in vulns
    ]

    return JSONResponse(content={
        "scan_id": scan.id,
        "total_issues": scan.total_issues,
        "vulnerabilities": vuln_data
    })


@app.get("/scan/history")
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    history = []
    for s in scans:
        repo = db.query(Repository).filter(Repository.id == s.repo_id).first()
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == s.id).all()

        created_at_attr = getattr(s, 'created_at', None)
        if created_at_attr and hasattr(created_at_attr, 'strftime'):
            formatted_date = created_at_attr.strftime("%Y-%m-%d %H:%M:%S")
        else:
            formatted_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        history.append({
            "scan_id": f"SCAN-{s.id}",
            "repo_name": repo.repo_name if repo else "Unknown Repo",
            "date": formatted_date,
            "type": "Git Repository Scan" if repo and repo.repo_url != "N/A (Snippet)" else "Code Snippet Audit",
            "total_issues": s.total_issues,
            "vulnerabilities": [
                {
                    "severity": v.severity,
                    "type": v.vulnerability_type,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "suggestion": v.suggestion,
                    "vulnerable_code": v.vulnerable_code,
                    "secure_code": v.secure_code
                } for v in vulns
            ]
        })
    return history


@app.delete("/scan/history/{scan_id}")
def delete_single_history(scan_id: str, db: Session = Depends(get_db)):
    try:
        clean_id = int(scan_id.replace("SCAN-", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Scan ID format")

    scan = db.query(Scan).filter(Scan.id == clean_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record မတွေ့ရှိပါ")

    db.delete(scan)
    db.commit()
    return {"message": f"Scan {scan_id} ကို အောင်မြင်စွာ ဖျက်ပြီးပါပြီ"}


@app.delete("/scan/history")
def clear_all_history(db: Session = Depends(get_db)):
    db.query(Vulnerability).delete()
    db.query(Scan).delete()
    db.commit()
    return {"message": "History အားလုံးကို ရှင်းထုတ်ပြီးပါပြီ"}


@app.post("/scan/url")
def scan_url_endpoint(payload: URLScanRequest):
    try:
        result = extract_url_features(payload.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL Feature Extraction Failed: {str(e)}")


# 🌐 LIVE WEB SECURITY AUDIT ENDPOINT
@app.post("/scan/web-audit")
def audit_web_security(payload: WebAuditRequest):
    target_url = payload.url.strip()

    # 🟢 Scheme မပါပါက https:// ကို Default တင်ပေးပါမည်။
    # သို့သော် http:// ပါပြီးသားဖြစ်ပါက http:// အတိုင်း ဆက်သွားပါမည်။
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # 🟢 GitHub Link ဖြစ်ပါက စစ်ဆေးမှု မလုပ်ဘဲ အသိပေးချက် ပြန်ထုတ်ပေးခြင်း
    if "github.com" in target_url.lower():
        return {
            "target_url": target_url,
            "status_code": 200,
            "security_score": 0,
            "security_grade": "N/A",
            "risk_score": "Invalid Target",
            "executive_summary": "GitHub URL သည် Source Code Repository ဖြစ်ပြီး Live Application မဟုတ်ပါ။ Source Code Vulnerability စစ်ဆေးရန် 'Git Repository' Tab ကို သုံးပါ။",
            "server_info": "GitHub Repository",
            "security_cards": {
                "encryption": "N/A",
                "script_protection": "N/A",
                "clickjacking_defense": "N/A",
                "strict_https": "N/A"
            },
            "recommendations": [
                {
                    "issue": "GitHub Link Provided in Web Audit",
                    "severity": "HIGH",
                    "impact": "Web Audit သည် Live Application ၏ Security Header/Cookie Configuration များကိုသာ စစ်ဆေးပါသည်။",
                    "remediation": "Live Website URL ကို ထည့်သွင်းပါ သို့မဟုတ် Git Repository Tab တွင် စစ်ဆေးပါ။"
                }
            ]
        }

    try:
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # 🟢 verify=False ထည့်ထားသဖြင့် SSL Certificate မပြည့်စုံသော သို့မဟုတ် HTTP သီးသန့် Site များတွင် SSL Error မတက်တော့ပါ။
        response = requests.get(target_url, headers=req_headers, timeout=10, allow_redirects=True, verify=False)
        headers = response.headers
        html_content = response.text.lower()

        is_ssl = target_url.startswith("https://")
        csp = headers.get("Content-Security-Policy", "Missing")
        csp_report_only = headers.get("Content-Security-Policy-Report-Only", "Missing")
        cors = headers.get("Access-Control-Allow-Origin", "Not Specified")
        x_frame = headers.get("X-Frame-Options", "Missing")
        hsts = headers.get("Strict-Transport-Security", "Missing")
        server_info = headers.get("Server", "Hidden")
        x_powered_by = headers.get("X-Powered-By", None)

        has_meta_csp = "content-security-policy" in html_content or csp_report_only != "Missing"

        domain_name = target_url.lower().replace("https://", "").replace("http://", "").split("/")[0]
        hsts_preloaded_domains = ["google.com", "youtube.com", "facebook.com", "gmail.com"]
        is_hsts_preloaded = any(domain_name == d or domain_name.endswith("." + d) for d in hsts_preloaded_domains)

        score = 100
        recommendations = []

        if not is_ssl:
            score -= 40
            recommendations.append({
                "issue": "Missing SSL/TLS Encryption",
                "severity": "CRITICAL",
                "impact": "ဒေတာများ လမ်းခုလတ်တွင် Encrypt မလုပ်ဘဲ ဖြတ်သန်းသွားသဖြင့် ကြည့်ရှုခံရနိုင်သည့် အန္တရာယ်ရှိပါသည်။",
                "remediation": "HTTPS Certificate စနစ်တကျ တပ်ဆင်ပါ။"
            })

        if csp == "Missing" and not has_meta_csp:
            score -= 15
            recommendations.append({
                "issue": "Missing Content Security Policy (CSP)",
                "severity": "MEDIUM",
                "impact": "XSS Script အန္တရာယ်များကို တားဆီးရန် Response Header သို့မဟုတ် HTML Meta Tag တွင် CSP မပါဝင်ပါ။",
                "remediation": "HTTP Response Header တွင် Content-Security-Policy ထည့်သွင်းပေးပါ။"
            })
        elif csp == "Missing" and has_meta_csp:
            recommendations.append({
                "issue": "CSP Enforced via HTML Meta Tag",
                "severity": "INFO",
                "impact": "Response Header တွင် CSP မပါသော်လည်း HTML Meta Tag အဆင့်တွင် ကာကွယ်ထားသည်ကို တွေ့ရှိရပါသည်။",
                "remediation": "Best Practice အနေဖြင့် Response Header တွင်ပါ ထည့်သွင်းရန် အကြံပြုပါသည်။"
            })

        if x_frame == "Missing":
            score -= 15
            recommendations.append({
                "issue": "Missing X-Frame-Options Header",
                "severity": "MEDIUM",
                "impact": "Clickjacking အန္တရာယ်မှ ကာကွယ်ရန် Frame Control Header လိုအပ်နေပါသည်။",
                "remediation": "Header တွင် 'X-Frame-Options: SAMEORIGIN' ထည့်သွင်းပါ။"
            })

        if cors == "*":
            score -= 20
            recommendations.append({
                "issue": "Overly Permissive CORS Policy",
                "severity": "HIGH",
                "impact": "မည်သည့် Domain မှမဆို API Resources များကို လှမ်းယူခွင့် ပေးထားပါသည်။",
                "remediation": "CORS Wildcard '*' ကို ပိတ်ပြီး သီးသန့် Domain သာ ခွင့်ပြုပါ။"
            })

        raw_cookies = response.raw.headers.getlist('Set-Cookie') if hasattr(response.raw, 'headers') else []
        if not raw_cookies and 'set-cookie' in headers:
            raw_cookies = [headers['set-cookie']]

        if raw_cookies:
            missing_http_only = False
            missing_secure = False
            missing_samesite = False

            for cookie_str in raw_cookies:
                c_lower = cookie_str.lower()
                if "httponly" not in c_lower:
                    missing_http_only = True
                if "secure" not in c_lower and is_ssl:
                    missing_secure = True
                if "samesite" not in c_lower:
                    missing_samesite = True

            if missing_http_only:
                score -= 10
                recommendations.append({
                    "issue": "Cookie Missing 'HttpOnly' Flag",
                    "severity": "MEDIUM",
                    "impact": "Client-side Script (XSS) ဖြင့် Session Cookie များကို လှမ်းယူဖတ်ရှုနိုင်ခြေ ရှိပါသည်။",
                    "remediation": "Set-Cookie Header တွင် 'HttpOnly' Flag ပါဝင်အောင် သတ်မှတ်ပါ။"
                })

            if missing_secure:
                score -= 10
                recommendations.append({
                    "issue": "Cookie Missing 'Secure' Flag",
                    "severity": "MEDIUM",
                    "impact": "Cookie များကို Unencrypted HTTP Connection များမှတစ်ဆင့် ပေးပို့မိနိုင်ခြေ ရှိပါသည်။",
                    "remediation": "Set-Cookie Header တွင် 'Secure' Flag ထည့်သွင်းပါ။"
                })

            if missing_samesite:
                score -= 5
                recommendations.append({
                    "issue": "Cookie Missing 'SameSite' Attribute",
                    "severity": "LOW",
                    "impact": "Cross-Site Request Forgery (CSRF) အန္တရာယ်များမှ ကာကွယ်နိုင်စွမ်း လျော့နည်းနိုင်ပါသည်။",
                    "remediation": "Cookie များတွင် 'SameSite=Lax' သို့မဟုတ် 'SameSite=Strict' ထည့်သွင်းပါ။"
                })

        if x_powered_by:
            score -= 5
            recommendations.append({
                "issue": "Information Disclosure (X-Powered-By Header)",
                "severity": "LOW",
                "impact": "အသုံးပြုထားသော Backend Technology/Framework အသေးစိတ်ကို ပြသနေပါသည်။",
                "remediation": "Server Configuration တွင် 'X-Powered-By' Header ကို ဖျောက်ထားပါ။"
            })

        if server_info != "Hidden" and any(char.isdigit() for char in server_info):
            score -= 5
            recommendations.append({
                "issue": "Server Version Disclosure",
                "severity": "LOW",
                "impact": "Web Server ၏ သီးသန့် Version အချက်အလက်များ တိုက်ရိုက် ပေါ်နေပါသည်။",
                "remediation": "Server Banner / Tokens များကို ဖျောက်ထားပါ။"
            })

        if hsts == "Missing" and is_ssl and not is_hsts_preloaded:
            score -= 10
            recommendations.append({
                "issue": "Missing HSTS Header (Strict HTTPS)",
                "severity": "LOW",
                "impact": "HTTP မှ HTTPS သို့ ပထမဆုံး ချိတ်ဆက်ချိန်တွင် Security Downgrade ဖြစ်နိုင်ခြေ ရှိပါသည်။",
                "remediation": "'Strict-Transport-Security: max-age=31536000' ကို ထည့်သွင်းပါ။"
            })

        # 🟢 ADDITIONAL SECURITY HEADER CHECKS
        x_content_type = headers.get("X-Content-Type-Options", "Missing")
        referrer_policy = headers.get("Referrer-Policy", "Missing")

        if x_content_type.lower() != "nosniff":
            score -= 5
            recommendations.append({
                "issue": "Missing X-Content-Type-Options Header",
                "severity": "LOW",
                "impact": "Browser များမှ MIME Sniffing လုပ်ပြီး Script မဟုတ်သော File များကို Script အဖြစ် Execute လုပ်သွားနိုင်သည့် အန္တရာယ်ရှိပါသည်။",
                "remediation": "HTTP Response Header တွင် 'X-Content-Type-Options: nosniff' ထည့်သွင်းပါ။"
            })

        if referrer_policy == "Missing":
            score -= 5
            recommendations.append({
                "issue": "Missing Referrer-Policy Header",
                "severity": "LOW",
                "impact": "User မည်သည့် Page မှ လာသည်ဆိုသော အချက်အလက် (Referrer) အပြင်ဘက်သို့ ယိုစိမ့်နိုင်ပါသည်။",
                "remediation": "Header တွင် 'Referrer-Policy: strict-origin-when-cross-origin' သတ်မှတ်ပေးပါ။"
            })

        score = max(0, score)

        if score >= 90:
            security_grade = "A+"
            risk_score = "Excellent (Secured)"
            executive_summary = "ယခု Website သည် လုံခြုံရေးဆိုင်ရာ Headers နှင့် Cookie Security Configurations များကို ကောင်းမွန်စွာ လိုက်နာထားပါသည်။"
        elif score >= 75:
            security_grade = "B"
            risk_score = "Good (Low Risk)"
            executive_summary = "အခြေခံလုံခြုံရေး ကောင်းမွန်သော်လည်း အချို့သော Cookie Flags သို့မဟုတ် Best Practice Header များ ထည့်သွင်းရန် အကြံပြုပါသည်။"
        elif score >= 50:
            security_grade = "C"
            risk_score = "Moderate Risk"
            executive_summary = "သတိပြုရန် Security Control အချို့ မရှိခြင်းနှင့် Information Disclosure များ ရှိနေပါသဖြင့် ပြင်ဆင်ရန် အကြံပြုပါသည်။"
        else:
            security_grade = "F"
            risk_score = "High Risk"
            executive_summary = "အရေးကြီး Security Control များ မရှိပါသဖြင့် အမြန်ဆုံး ပြင်ဆင်ရန် လိုအပ်ပါသည်။"

        script_prot_status = "Active (CSP Header)" if csp != "Missing" else (
            "Active (HTML Meta Tag)" if has_meta_csp else "Not Found")
        strict_https_status = "Active (HSTS Enforced)" if hsts != "Missing" else (
            "Active (HSTS Preloaded)" if is_hsts_preloaded else "Not Enforced")

        return {
            "target_url": target_url,
            "status_code": response.status_code,
            "security_score": score,
            "security_grade": security_grade,
            "risk_score": risk_score,
            "executive_summary": executive_summary,
            "server_info": server_info,
            "security_cards": {
                "encryption": "Valid (HTTPS Standard)" if is_ssl else "Insecure (HTTP Only)",
                "script_protection": script_prot_status,
                "clickjacking_defense": f"Active ({x_frame})" if x_frame != "Missing" else "Not Configured",
                "strict_https": strict_https_status
            },
            "recommendations": recommendations
        }

    except requests.exceptions.RequestException as e:
        # 🟢 HTTP 400 raise မလုပ်တော့ဘဲ Frontend UI သို့ Error Result အဖြစ် လှပစွာ ပြသနိုင်ရန် JSON ပြန်ထုတ်ပေးခြင်း
        return {
            "target_url": target_url,
            "status_code": 400,
            "security_score": 0,
            "security_grade": "F",
            "risk_score": "Unreachable Target",
            "executive_summary": f"Target URL သို့ ချိတ်ဆက်၍ မရပါ (Connection Error သို့မဟုတ် Invalid Domain ဖြစ်နိုင်ပါသည်) - {str(e)}",
            "server_info": "Unknown",
            "security_cards": {
                "encryption": "Insecure / Failed",
                "script_protection": "Not Found",
                "clickjacking_defense": "Not Configured",
                "strict_https": "Not Enforced"
            },
            "recommendations": [
                {
                    "issue": "Failed to Reach Target Domain",
                    "severity": "CRITICAL",
                    "impact": "စစ်ဆေးလိုသော URL သည် မရှိပါ သို့မဟုတ် Server ပိတ်ထားပါသည် (သို့မဟုတ် Firewall မှ Block ထားပါသည်)။",
                    "remediation": "Domain အမည်နှင့် Protocol (http/https) မှန်ကန်မှု ရှိမရှိ စစ်ဆေးပါ။"
                }
            ]
        }