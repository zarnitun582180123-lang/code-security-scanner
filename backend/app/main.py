import os
import git
import tempfile
import shutil
import subprocess
import traceback
import uuid
import json
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

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Automated Code Security Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")

try:
    groq_client = Groq(api_key=GROQ_API_KEY) if "gsk_" in GROQ_API_KEY else None
except Exception:
    groq_client = None


class RepoScanRequest(BaseModel):
    repo_name: str
    repo_url: str


class CodeSnippetRequest(BaseModel):
    code_string: str


class AICoachRequest(BaseModel):
    vulnerability_type: str
    suggestion: str
    vulnerable_code: str


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

    # Raw AST Scan Data ရယူခြင်း
    raw_issues = scan_directory(temp_dir)

    # Standardize Data Format for Frontend
    formatted_issues = []
    for issue in raw_issues:
        sev = issue.get("severity") or "HIGH"
        v_type = issue.get("vulnerability_type") or issue.get("type") or "SECURITY_RISK"
        f_path = issue.get("file_path") or issue.get("file") or "unknown_file"
        l_num = issue.get("line_number") or issue.get("line") or 1
        sugg = issue.get("suggestion") or "မလုံခြုံသော Code Pattern ကို ပြန်လည် ပြင်ဆင်ပါ။"

        formatted_issues.append({
            "severity": str(sev).upper(),
            "vulnerability_type": str(v_type),
            "type": str(v_type),
            "file_path": str(f_path),
            "line_number": int(l_num),
            "suggestion": str(sugg)
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
            suggestion=issue["suggestion"]
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

            formatted_issues.append({
                "severity": str(sev).upper(),
                "vulnerability_type": str(v_type),
                "type": str(v_type),
                "file_path": str(f_path),
                "line_number": int(l_num),
                "suggestion": str(sugg)
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
                suggestion=issue["suggestion"]
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


@app.post("/api/ai-coach")
def get_ai_coach_explanation(req: AICoachRequest):
    if not groq_client:
        return get_fallback_ai_response(req)

    try:
        prompt = f"""
        You are an expert Cyber Security Specialist and AI Security Coach.
        Analyze the following security vulnerability found in a code snippet:

        - Vulnerability Type: {req.vulnerability_type}
        - Static Suggestion: {req.suggestion}
        - Vulnerable Code Snippet:
        ```{req.vulnerable_code}```

        Please provide a professional, structured analysis in JSON format containing:
        1. "why_dangerous": Explain why this specific line/code is dangerous (in clear, natural Myanmar language).
        2. "hacking_scenario": Describe a realistic exploit scenario of how a hacker could abuse this exact code (in clear, natural Myanmar language).
        3. "recommendation": Provide the exact, production-ready SECURE FIX code snippet specifically refactored for this vulnerable code (with concise inline comments in Myanmar language).

        Return ONLY a raw JSON object with keys: "why_dangerous", "hacking_scenario", "recommendation".
        """

        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )

        ai_data = json.loads(response.choices[0].message.content)

        return {
            "vulnerability_type": req.vulnerability_type,
            "why_dangerous": ai_data.get("why_dangerous", "မလုံခြုံသော Code Pattern ဖြစ်ပါသည်။"),
            "hacking_scenario": ai_data.get("hacking_scenario", "Attacker များက ယခု Vulnerability ကို အသုံးချနိုင်ပါသည်။"),
            "recommendation": ai_data.get("recommendation", "# ✅ Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ"),
            "remediation_logic": ai_data.get("recommendation", "# ✅ Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ")
        }

    except Exception as e:
        print(f"Groq API Error: {e}")
        return get_fallback_ai_response(req)


def get_fallback_ai_response(req: AICoachRequest):
    vtype = req.vulnerability_type.upper()

    if "AWS" in vtype or "GITHUB" in vtype or "STRIPE" in vtype or "SECRET" in vtype or "KEY" in vtype or "PASSWORD" in vtype:
        hacking_scenario = "GitHub ပေါ် Code တင်မိလိုက်တာနဲ့ Automated Bots တွေက စက္ကန့်ပိုင်းအတွင်း Key ကို ခိုးယူပြီး Cloud Infrastructure တွေကို ဖျက်ဆီးသွားနိုင်ပါတယ်။"
        why_dangerous = "Credentials များကို Source Code ထဲ Plain Text အတိုင်း ရေးထားမိလို့ဖြစ်ပါတယ်။"
        recommendation = "# ✅ Python: Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပြီး os.getenv() ကို အသုံးပြုပါ\nimport os\nSECRET_KEY = os.getenv('SECRET_KEY')"
    else:
        hacking_scenario = "Attacker များသည် မလုံခြုံသော System Code Pattern များကို အသုံးချ၍ Application Control ကို ရယူနိုင်ပါသည်။"
        why_dangerous = "Unsanitized User Data သို့မဟုတ် Insecure Functions များ သုံးထားခြင်းကြောင့် ဖြစ်ပါသည်။"
        recommendation = "# ✅ Secure Coding Guidelines များကို လိုက်နာပါ"

    return {
        "vulnerability_type": req.vulnerability_type,
        "why_dangerous": why_dangerous,
        "hacking_scenario": hacking_scenario,
        "recommendation": recommendation,
        "remediation_logic": recommendation
    }


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
            "suggestion": v.suggestion
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
                    "suggestion": v.suggestion
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