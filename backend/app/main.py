import os
import json
import re
import requests
import traceback

from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from pydantic import BaseModel

from groq import Groq
from dotenv import load_dotenv

from app.reporter import generate_pdf_report
from app.database import engine, get_db, Base
from app.models import Repository, Scan, Vulnerability, AIChatMessage
from app.celery_app import celery_app

from app.routes.scan import router as scan_router

from app.scanner.url_engine import extract_url_features

from metrics_engine import evaluate_model_metrics

from typing import Optional
# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# DATABASE
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="Automated Code Security Scanner API"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROUTES
# ============================================================

# Scan routes
# /scan/git
# /scan/snippet
app.include_router(scan_router)


# ============================================================
# GROQ AI CONFIGURATION
# ============================================================

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

try:
    if GROQ_API_KEY and GROQ_API_KEY.startswith("gsk_"):
        groq_client = Groq(api_key=GROQ_API_KEY)

        print(
            "✅ Groq API Client successfully initialized!"
        )

    else:
        groq_client = None

        print(
            "❌ Warning: Invalid GROQ_API_KEY format or missing."
        )

except Exception as e:
    groq_client = None

    print(
        f"❌ Groq Initialization Error: {e}"
    )


# ============================================================
# REQUEST MODELS
# ============================================================

class AICoachRequest(BaseModel):
    vulnerability_type: str
    suggestion: str
    vulnerable_code: str


class URLScanRequest(BaseModel):
    url: str


class WebAuditRequest(BaseModel):
    url: str

class AIAgentRequest(BaseModel):
    message: str
    scan_id: Optional[int] = None
    scan_result: Optional[dict] = None

# ============================================================
# AI SECURITY COACH
# ============================================================

@app.post("/api/ai-coach")
def get_ai_coach_explanation(req: AICoachRequest):

    if not groq_client:
        print(
            "❌ Groq API client is missing or uninitialized. "
            "Falling back..."
        )

        return get_fallback_ai_response(req)

    system_instructions = (
        "You are an elite Cyber Security Specialist and AI Security Coach.\n"
        "Analyze the given security vulnerability thoroughly.\n"
        "You MUST respond STRICTLY in a valid JSON object matching the requested schema.\n"
        "Do NOT wrap the JSON in Markdown code blocks like ```json or ```.\n"
        "Provide explanations for 'why_dangerous' and "
        "'hacking_scenario' in clear, professional Myanmar language."
    )

    user_prompt = f"""
Vulnerability Analysis Request:

- Vulnerability Type:
{req.vulnerability_type}

- Static Scanner Suggestion:
{req.suggestion}

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

    # ========================================================
    # FETCH AVAILABLE GROQ MODELS
    # ========================================================

    available_models = []

    try:
        models_list = groq_client.models.list()

        available_models = [
            model.id
            for model in models_list.data
            if model.id
        ]

        print(
            f"📋 Dynamically Fetched Groq Models: "
            f"{available_models}"
        )

    except Exception as e:
        print(
            f"⚠️ Failed to fetch models dynamically: {e}"
        )

    # Fallback models
    if not available_models:
        available_models = [
            "llama-3.3-70b-versatile",
            "llama3-8b-8192",
        ]

    response = None
    last_error = None

    # ========================================================
    # TRY MODELS
    # ========================================================

    for model_name in available_models:

        try:

            print(
                f"🤖 Attempting Groq AI Analysis "
                f"using Model: '{model_name}'..."
            )

            response = groq_client.chat.completions.create(
                model=model_name,
                messages=[
                    {
                        "role": "system",
                        "content": system_instructions,
                    },
                    {
                        "role": "user",
                        "content": user_prompt,
                    },
                ],
                temperature=0.2,
                max_tokens=1500,
            )

            if response and response.choices:

                print(
                    f"✅ Successfully generated response "
                    f"using model: '{model_name}'"
                )

                break

        except Exception as e:

            print(
                f"⚠️ Model '{model_name}' failed: {e}"
            )

            last_error = e

            continue

    # ========================================================
    # ALL MODELS FAILED
    # ========================================================

    if not response or not response.choices:

        print(
            "\n================ ALL GROQ MODELS FAILED ================"
        )

        print(
            f"Last Error: {last_error}"
        )

        print(
            "========================================================\n"
        )

        return get_fallback_ai_response(req)

    # ========================================================
    # PARSE AI JSON
    # ========================================================

    try:

        raw_text = (
            response.choices[0].message.content
            or "{}"
        )

        json_match = re.search(
            r"\{.*\}",
            raw_text,
            re.DOTALL,
        )

        clean_json = (
            json_match.group(0)
            if json_match
            else raw_text
        )

        ai_data = json.loads(clean_json)

        return {
            "vulnerability_type": req.vulnerability_type,

            "cvss_score": float(
                ai_data.get(
                    "cvss_score",
                    8.5,
                )
            ),

            "cvss_severity": str(
                ai_data.get(
                    "cvss_severity",
                    "HIGH",
                )
            ),

            "mitre_id": str(
                ai_data.get(
                    "mitre_id",
                    "T1552",
                )
            ),

            "mitre_name": str(
                ai_data.get(
                    "mitre_name",
                    "Unsecured Credentials",
                )
            ),

            "why_dangerous": str(
                ai_data.get(
                    "why_dangerous",
                    "မလုံခြုံသော Code Pattern ဖြစ်ပါသည်။",
                )
            ),

            "hacking_scenario": str(
                ai_data.get(
                    "hacking_scenario",
                    "Attacker များက ယခု Vulnerability ကို "
                    "အသုံးချနိုင်ပါသည်။",
                )
            ),

            "poc_command": str(
                ai_data.get(
                    "poc_command",
                    f"grep -ri '{req.vulnerability_type}' ./src",
                )
            ),

            "recommendation": str(
                ai_data.get(
                    "recommendation",
                    "# ✅ Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ",
                )
            ),

            "remediation_logic": str(
                ai_data.get(
                    "recommendation",
                    "# ✅ Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ",
                )
            ),
        }

    except Exception as e:

        print(
            f"❌ JSON Parsing Error: {e}"
        )

        return get_fallback_ai_response(req)


# ============================================================
# AI FALLBACK RESPONSE
# ============================================================

def get_fallback_ai_response(req: AICoachRequest):

    vtype = req.vulnerability_type.upper()

    if (
        "AWS" in vtype
        or "GITHUB" in vtype
        or "STRIPE" in vtype
        or "SECRET" in vtype
        or "KEY" in vtype
        or "PASSWORD" in vtype
    ):

        hacking_scenario = (
            "GitHub ပေါ် Code တင်မိလိုက်တာနဲ့ "
            "Automated Bots တွေက စက္ကန့်ပိုင်းအတွင်း "
            "Key ကို ခိုးယူပြီး Cloud Infrastructure တွေကို "
            "ဖျက်ဆီးသွားနိုင်ပါတယ်။"
        )

        why_dangerous = (
            "Credentials များကို Source Code ထဲ "
            "Plain Text အတိုင်း ရေးထားမိလို့ဖြစ်ပါတယ်။"
        )

        recommendation = (
            "# ✅ Python: Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပြီး "
            "os.getenv() ကို အသုံးပြုပါ\n"
            "import os\n"
            "SECRET_KEY = os.getenv('SECRET_KEY')"
        )

        poc = "grep -rn 'SECRET_KEY' ."

        mitre_id = "T1552.001"

        mitre_name = (
            "Unsecured Credentials: Credentials In Files"
        )

        cvss = 9.8

        sev = "CRITICAL"

    else:

        hacking_scenario = (
            "Attacker များသည် မလုံခြုံသော "
            "System Code Pattern များကို အသုံးချ၍ "
            "Application Control ကို ရယူနိုင်ပါသည်။"
        )

        why_dangerous = (
            "Unsanitized User Data သို့မဟုတ် "
            "Insecure Functions များ သုံးထားခြင်းကြောင့် ဖြစ်ပါသည်။"
        )

        recommendation = (
            "# ✅ Secure Coding Guidelines များကို လိုက်နာပါ"
        )

        poc = (
            f"grep -rn '{req.vulnerability_type}' ."
        )

        mitre_id = "T1059"

        mitre_name = (
            "Command and Scripting Interpreter"
        )

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
        "remediation_logic": recommendation,
    }


# ============================================================
# BENCHMARK / DATA SCIENCE METRICS
# ============================================================

@app.get("/api/benchmark-metrics")
def get_benchmark_metrics():

    try:

        return evaluate_model_metrics()

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to calculate metrics: {str(e)}",
        )


# ============================================================
# JSON REPORT
# ============================================================

@app.get("/reports/json/{scan_id}")
def export_json_report(
    scan_id: int,
    db: Session = Depends(get_db),
):

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan record not found",
        )

    vulns = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.scan_id == scan_id
        )
        .all()
    )

    vuln_data = [
        {
            "severity": v.severity,
            "type": v.vulnerability_type,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "suggestion": v.suggestion,
            "vulnerable_code": v.vulnerable_code,
            "secure_code": v.secure_code,
        }
        for v in vulns
    ]

    return JSONResponse(
        content={
            "scan_id": scan.id,
            "total_issues": scan.total_issues,
            "vulnerabilities": vuln_data,
        }
    )


# ============================================================
# SCAN HISTORY
# ============================================================

@app.get("/scan/history")
def get_scan_history(
    db: Session = Depends(get_db),
):

    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .all()
    )

    history = []

    for s in scans:

        repo = (
            db.query(Repository)
            .filter(
                Repository.id == s.repo_id
            )
            .first()
        )

        vulns = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.scan_id == s.id
            )
            .all()
        )

        created_at_attr = getattr(
            s,
            "created_at",
            None,
        )

        # Your Scan model currently uses scan_date,
        # so support both fields.
        if not created_at_attr:
            created_at_attr = getattr(
                s,
                "scan_date",
                None,
            )

        if (
            created_at_attr
            and hasattr(
                created_at_attr,
                "strftime",
            )
        ):

            formatted_date = (
                created_at_attr.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

        else:

            formatted_date = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

        history.append(
            {
                "scan_id": f"SCAN-{s.id}",

                "repo_name": (
                    repo.repo_name
                    if repo
                    else "Unknown Repo"
                ),

                "date": formatted_date,

                "type": (
                    "Git Repository Scan"
                    if repo
                    and repo.repo_url != "N/A (Snippet)"
                    else "Code Snippet Audit"
                ),

                "total_issues": s.total_issues,

                "vulnerabilities": [
                    {
                        "severity": v.severity,
                        "type": v.vulnerability_type,
                        "file_path": v.file_path,
                        "line_number": v.line_number,
                        "suggestion": v.suggestion,
                        "vulnerable_code": v.vulnerable_code,
                        "secure_code": v.secure_code,
                    }
                    for v in vulns
                ],
            }
        )

    return history


# ============================================================
# DELETE SINGLE HISTORY
# ============================================================

@app.delete("/scan/history/{scan_id}")
def delete_single_history(
    scan_id: str,
    db: Session = Depends(get_db),
):

    try:

        clean_id = int(
            scan_id.replace(
                "SCAN-",
                "",
            )
        )

    except ValueError:

        raise HTTPException(
            status_code=400,
            detail="Invalid Scan ID format",
        )

    scan = (
        db.query(Scan)
        .filter(Scan.id == clean_id)
        .first()
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan record မတွေ့ရှိပါ",
        )

    db.delete(scan)

    db.commit()

    return {
        "message": (
            f"Scan {scan_id} ကို "
            "အောင်မြင်စွာ ဖျက်ပြီးပါပြီ"
        )
    }


# ============================================================
# CLEAR ALL HISTORY
# ============================================================

@app.delete("/scan/history")
def clear_all_history(
    db: Session = Depends(get_db),
):

    db.query(Vulnerability).delete()

    db.query(Scan).delete()

    db.commit()

    return {
        "message": "History အားလုံးကို ရှင်းထုတ်ပြီးပါပြီ"
    }


# ============================================================
# URL FEATURE SCAN
# ============================================================

@app.post("/scan/url")
def scan_url_endpoint(
    payload: URLScanRequest,
):

    try:

        result = extract_url_features(
            payload.url
        )

        return result

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=(
                "URL Feature Extraction Failed: "
                f"{str(e)}"
            ),
        )


# ============================================================
# LIVE WEB SECURITY AUDIT
# ============================================================

@app.post("/scan/web-audit")
def audit_web_security(
    payload: WebAuditRequest,
):

    target_url = payload.url.strip()

    # --------------------------------------------------------
    # Add HTTPS automatically when protocol is missing
    # --------------------------------------------------------

    if not target_url.startswith(
        ("http://", "https://")
    ):

        target_url = "https://" + target_url

    # --------------------------------------------------------
    # GitHub Repository Protection
    # --------------------------------------------------------

    if "github.com" in target_url.lower():

        return {
            "target_url": target_url,
            "status_code": 200,
            "security_score": 0,
            "security_grade": "N/A",
            "risk_score": "Invalid Target",

            "executive_summary": (
                "GitHub URL သည် Source Code Repository ဖြစ်ပြီး "
                "Live Application မဟုတ်ပါ။ "
                "Source Code Vulnerability စစ်ဆေးရန် "
                "'Git Repository' Tab ကို သုံးပါ။"
            ),

            "server_info": "GitHub Repository",

            "security_cards": {
                "encryption": "N/A",
                "script_protection": "N/A",
                "clickjacking_defense": "N/A",
                "strict_https": "N/A",
            },

            "recommendations": [
                {
                    "issue": "GitHub Link Provided in Web Audit",
                    "severity": "HIGH",

                    "impact": (
                        "Web Audit သည် Live Application ၏ "
                        "Security Header/Cookie Configuration "
                        "များကိုသာ စစ်ဆေးပါသည်။"
                    ),

                    "remediation": (
                        "Live Website URL ကို ထည့်သွင်းပါ "
                        "သို့မဟုတ် Git Repository Tab တွင် စစ်ဆေးပါ။"
                    ),
                }
            ],
        }

    # --------------------------------------------------------
    # WEB REQUEST
    # --------------------------------------------------------

    try:

        req_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

        response = requests.get(
            target_url,
            headers=req_headers,
            timeout=10,
            allow_redirects=True,
            verify=False,
        )

        headers = response.headers

        html_content = response.text.lower()

        is_ssl = target_url.startswith(
            "https://"
        )

        csp = headers.get(
            "Content-Security-Policy",
            "Missing",
        )

        csp_report_only = headers.get(
            "Content-Security-Policy-Report-Only",
            "Missing",
        )

        cors = headers.get(
            "Access-Control-Allow-Origin",
            "Not Specified",
        )

        x_frame = headers.get(
            "X-Frame-Options",
            "Missing",
        )

        hsts = headers.get(
            "Strict-Transport-Security",
            "Missing",
        )

        server_info = headers.get(
            "Server",
            "Hidden",
        )

        x_powered_by = headers.get(
            "X-Powered-By",
            None,
        )

        # ----------------------------------------------------
        # CSP
        # ----------------------------------------------------

        has_meta_csp = (
            "content-security-policy"
            in html_content
            or csp_report_only != "Missing"
        )

        # ----------------------------------------------------
        # DOMAIN
        # ----------------------------------------------------

        domain_name = (
            target_url.lower()
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

        hsts_preloaded_domains = [
            "google.com",
            "youtube.com",
            "facebook.com",
            "gmail.com",
        ]

        is_hsts_preloaded = any(
            domain_name == d
            or domain_name.endswith("." + d)
            for d in hsts_preloaded_domains
        )

        # ----------------------------------------------------
        # SECURITY SCORE
        # ----------------------------------------------------

        score = 100

        recommendations = []

        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        if not is_ssl:

            score -= 40

            recommendations.append(
                {
                    "issue": "Missing SSL/TLS Encryption",
                    "severity": "CRITICAL",

                    "impact": (
                        "ဒေတာများ လမ်းခုလတ်တွင် Encrypt မလုပ်ဘဲ "
                        "ဖြတ်သန်းသွားသဖြင့် ကြည့်ရှုခံရနိုင်သည့် "
                        "အန္တရာယ်ရှိပါသည်။"
                    ),

                    "remediation": (
                        "HTTPS Certificate စနစ်တကျ တပ်ဆင်ပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # CSP
        # ----------------------------------------------------

        if (
            csp == "Missing"
            and not has_meta_csp
        ):

            score -= 15

            recommendations.append(
                {
                    "issue": (
                        "Missing Content Security Policy (CSP)"
                    ),
                    "severity": "MEDIUM",

                    "impact": (
                        "XSS Script အန္တရာယ်များကို တားဆီးရန် "
                        "Response Header သို့မဟုတ် HTML Meta Tag တွင် "
                        "CSP မပါဝင်ပါ။"
                    ),

                    "remediation": (
                        "HTTP Response Header တွင် "
                        "Content-Security-Policy ထည့်သွင်းပေးပါ။"
                    ),
                }
            )

        elif (
            csp == "Missing"
            and has_meta_csp
        ):

            recommendations.append(
                {
                    "issue": (
                        "CSP Enforced via HTML Meta Tag"
                    ),
                    "severity": "INFO",

                    "impact": (
                        "Response Header တွင် CSP မပါသော်လည်း "
                        "HTML Meta Tag အဆင့်တွင် "
                        "ကာကွယ်ထားသည်ကို တွေ့ရှိရပါသည်။"
                    ),

                    "remediation": (
                        "Best Practice အနေဖြင့် "
                        "Response Header တွင်ပါ ထည့်သွင်းရန် အကြံပြုပါသည်။"
                    ),
                }
            )

        # ----------------------------------------------------
        # CLICKJACKING
        # ----------------------------------------------------

        if x_frame == "Missing":

            score -= 15

            recommendations.append(
                {
                    "issue": (
                        "Missing X-Frame-Options Header"
                    ),
                    "severity": "MEDIUM",

                    "impact": (
                        "Clickjacking အန္တရာယ်မှ ကာကွယ်ရန် "
                        "Frame Control Header လိုအပ်နေပါသည်။"
                    ),

                    "remediation": (
                        "Header တွင် "
                        "'X-Frame-Options: SAMEORIGIN' "
                        "ထည့်သွင်းပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # CORS
        # ----------------------------------------------------

        if cors == "*":

            score -= 20

            recommendations.append(
                {
                    "issue": (
                        "Overly Permissive CORS Policy"
                    ),
                    "severity": "HIGH",

                    "impact": (
                        "မည်သည့် Domain မှမဆို API Resources "
                        "များကို လှမ်းယူခွင့် ပေးထားပါသည်။"
                    ),

                    "remediation": (
                        "CORS Wildcard '*' ကို ပိတ်ပြီး "
                        "သီးသန့် Domain သာ ခွင့်ပြုပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # COOKIES
        # ----------------------------------------------------

        raw_cookies = (
            response.raw.headers.getlist("Set-Cookie")
            if hasattr(
                response.raw,
                "headers",
            )
            else []
        )

        if (
            not raw_cookies
            and "set-cookie" in headers
        ):

            raw_cookies = [
                headers["set-cookie"]
            ]

        if raw_cookies:

            missing_http_only = False
            missing_secure = False
            missing_samesite = False

            for cookie_str in raw_cookies:

                c_lower = cookie_str.lower()

                if "httponly" not in c_lower:
                    missing_http_only = True

                if (
                    "secure" not in c_lower
                    and is_ssl
                ):
                    missing_secure = True

                if "samesite" not in c_lower:
                    missing_samesite = True

            # HttpOnly
            if missing_http_only:

                score -= 10

                recommendations.append(
                    {
                        "issue": (
                            "Cookie Missing 'HttpOnly' Flag"
                        ),
                        "severity": "MEDIUM",

                        "impact": (
                            "Client-side Script (XSS) ဖြင့် "
                            "Session Cookie များကို "
                            "လှမ်းယူဖတ်ရှုနိုင်ခြေ ရှိပါသည်။"
                        ),

                        "remediation": (
                            "Set-Cookie Header တွင် "
                            "'HttpOnly' Flag ပါဝင်အောင် သတ်မှတ်ပါ။"
                        ),
                    }
                )

            # Secure
            if missing_secure:

                score -= 10

                recommendations.append(
                    {
                        "issue": (
                            "Cookie Missing 'Secure' Flag"
                        ),
                        "severity": "MEDIUM",

                        "impact": (
                            "Cookie များကို Unencrypted HTTP "
                            "Connection များမှတစ်ဆင့် "
                            "ပေးပို့မိနိုင်ခြေ ရှိပါသည်။"
                        ),

                        "remediation": (
                            "Set-Cookie Header တွင် "
                            "'Secure' Flag ထည့်သွင်းပါ။"
                        ),
                    }
                )

            # SameSite
            if missing_samesite:

                score -= 5

                recommendations.append(
                    {
                        "issue": (
                            "Cookie Missing 'SameSite' Attribute"
                        ),
                        "severity": "LOW",

                        "impact": (
                            "Cross-Site Request Forgery (CSRF) "
                            "အန္တရာယ်များမှ ကာကွယ်နိုင်စွမ်း "
                            "လျော့နည်းနိုင်ပါသည်။"
                        ),

                        "remediation": (
                            "Cookie များတွင် 'SameSite=Lax' "
                            "သို့မဟုတ် 'SameSite=Strict' "
                            "ထည့်ပါ။"
                        ),
                    }
                )

        # ----------------------------------------------------
        # X-POWERED-BY
        # ----------------------------------------------------

        if x_powered_by:

            score -= 5

            recommendations.append(
                {
                    "issue": (
                        "Information Disclosure "
                        "(X-Powered-By Header)"
                    ),
                    "severity": "LOW",

                    "impact": (
                        "အသုံးပြုထားသော Backend "
                        "Technology/Framework အသေးစိတ်ကို "
                        "ပြသနေပါသည်။"
                    ),

                    "remediation": (
                        "Server Configuration တွင် "
                        "'X-Powered-By' Header ကို ဖျောက်ထားပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # SERVER VERSION
        # ----------------------------------------------------

        if (
            server_info != "Hidden"
            and any(
                char.isdigit()
                for char in server_info
            )
        ):

            score -= 5

            recommendations.append(
                {
                    "issue": "Server Version Disclosure",
                    "severity": "LOW",

                    "impact": (
                        "Web Server ၏ သီးသန့် Version "
                        "အချက်အလက်များ တိုက်ရိုက် ပေါ်နေပါသည်။"
                    ),

                    "remediation": (
                        "Server Banner / Tokens များကို "
                        "ဖျောက်ထားပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # HSTS
        # ----------------------------------------------------

        if (
            hsts == "Missing"
            and is_ssl
            and not is_hsts_preloaded
        ):

            score -= 10

            recommendations.append(
                {
                    "issue": (
                        "Missing HSTS Header "
                        "(Strict HTTPS)"
                    ),
                    "severity": "LOW",

                    "impact": (
                        "HTTP မှ HTTPS သို့ ပထမဆုံး ချိတ်ဆက်ချိန်တွင် "
                        "Security Downgrade ဖြစ်နိုင်ခြေ ရှိပါသည်။"
                    ),

                    "remediation": (
                        "'Strict-Transport-Security: "
                        "max-age=31536000' ကို ထည့်သွင်းပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # X-CONTENT-TYPE-OPTIONS
        # ----------------------------------------------------

        x_content_type = headers.get(
            "X-Content-Type-Options",
            "Missing",
        )

        referrer_policy = headers.get(
            "Referrer-Policy",
            "Missing",
        )

        if x_content_type.lower() != "nosniff":

            score -= 5

            recommendations.append(
                {
                    "issue": (
                        "Missing X-Content-Type-Options Header"
                    ),
                    "severity": "LOW",

                    "impact": (
                        "Browser များမှ MIME Sniffing လုပ်ပြီး "
                        "Script မဟုတ်သော File များကို "
                        "Script အဖြစ် Execute လုပ်သွားနိုင်သည့် "
                        "အန္တရာယ်ရှိပါသည်။"
                    ),

                    "remediation": (
                        "HTTP Response Header တွင် "
                        "'X-Content-Type-Options: nosniff' "
                        "ထည့်သွင်းပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # REFERRER POLICY
        # ----------------------------------------------------

        if referrer_policy == "Missing":

            score -= 5

            recommendations.append(
                {
                    "issue": (
                        "Missing Referrer-Policy Header"
                    ),
                    "severity": "LOW",

                    "impact": (
                        "User မည်သည့် Page မှ လာသည်ဆိုသော "
                        "အချက်အလက် (Referrer) အပြင်ဘက်သို့ "
                        "ယိုစိမ့်နိုင်ပါသည်။"
                    ),

                    "remediation": (
                        "Header တွင် "
                        "'Referrer-Policy: "
                        "strict-origin-when-cross-origin' "
                        "သတ်မှတ်ပေးပါ။"
                    ),
                }
            )

        # ----------------------------------------------------
        # FINAL SCORE
        # ----------------------------------------------------

        score = max(
            0,
            score,
        )

        # ----------------------------------------------------
        # SECURITY GRADE
        # ----------------------------------------------------

        if score >= 90:

            security_grade = "A+"
            risk_score = "Excellent (Secured)"

            executive_summary = (
                "ယခု Website သည် လုံခြုံရေးဆိုင်ရာ "
                "Headers နှင့် Cookie Security Configurations "
                "များကို ကောင်းမွန်စွာ လိုက်နာထားပါသည်။"
            )

        elif score >= 75:

            security_grade = "B"
            risk_score = "Good (Low Risk)"

            executive_summary = (
                "အခြေခံလုံခြုံရေး ကောင်းမွန်သော်လည်း "
                "အချို့သော Cookie Flags သို့မဟုတ် "
                "Best Practice Header များ ထည့်သွင်းရန် "
                "အကြံပြုပါသည်။"
            )

        elif score >= 50:

            security_grade = "C"
            risk_score = "Moderate Risk"

            executive_summary = (
                "သတိပြုရန် Security Control အချို့ မရှိခြင်းနှင့် "
                "Information Disclosure များ ရှိနေပါသဖြင့် "
                "ပြင်ဆင်ရန် အကြံပြုပါသည်။"
            )

        else:

            security_grade = "F"
            risk_score = "High Risk"

            executive_summary = (
                "အရေးကြီး Security Control များ မရှိပါသဖြင့် "
                "အမြန်ဆုံး ပြင်ဆင်ရန် လိုအပ်ပါသည်။"
            )

        # ----------------------------------------------------
        # SECURITY CARD STATUS
        # ----------------------------------------------------

        script_prot_status = (
            "Active (CSP Header)"
            if csp != "Missing"
            else (
                "Active (HTML Meta Tag)"
                if has_meta_csp
                else "Not Found"
            )
        )

        strict_https_status = (
            "Active (HSTS Enforced)"
            if hsts != "Missing"
            else (
                "Active (HSTS Preloaded)"
                if is_hsts_preloaded
                else "Not Enforced"
            )
        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {
            "target_url": target_url,

            "status_code": response.status_code,

            "security_score": score,

            "security_grade": security_grade,

            "risk_score": risk_score,

            "executive_summary": executive_summary,

            "server_info": server_info,

            "security_cards": {
                "encryption": (
                    "Valid (HTTPS Standard)"
                    if is_ssl
                    else "Insecure (HTTP Only)"
                ),

                "script_protection": script_prot_status,

                "clickjacking_defense": (
                    f"Active ({x_frame})"
                    if x_frame != "Missing"
                    else "Not Configured"
                ),

                "strict_https": strict_https_status,
            },

            "recommendations": recommendations,
        }

    # ========================================================
    # REQUEST ERROR
    # ========================================================

    except requests.exceptions.RequestException as e:

        return {
            "target_url": target_url,

            "status_code": 400,

            "security_score": 0,

            "security_grade": "F",

            "risk_score": "Unreachable Target",

            "executive_summary": (
                "Target URL သို့ ချိတ်ဆက်၍ မရပါ "
                "(Connection Error သို့မဟုတ် Invalid Domain ဖြစ်နိုင်ပါသည်) "
                f"- {str(e)}"
            ),

            "server_info": "Unknown",

            "security_cards": {
                "encryption": "Insecure / Failed",
                "script_protection": "Not Found",
                "clickjacking_defense": "Not Configured",
                "strict_https": "Not Enforced",
            },

            "recommendations": [
                {
                    "issue": "Failed to Reach Target Domain",
                    "severity": "CRITICAL",

                    "impact": (
                        "စစ်ဆေးလိုသော URL သည် မရှိပါ "
                        "သို့မဟုတ် Server ပိတ်ထားပါသည် "
                        "(သို့မဟုတ် Firewall မှ Block ထားပါသည်)။"
                    ),

                    "remediation": (
                        "Domain အမည်နှင့် Protocol "
                        "(http/https) မှန်ကန်မှု ရှိမရှိ စစ်ဆေးပါ။"
                    ),
                }
            ],
        }
@app.post("/api/ai-agent")
def ai_security_agent(
    req: AIAgentRequest,
    db: Session = Depends(get_db)
):
    # ============================================================
    # CHECK GROQ
    # ============================================================

    if not groq_client:
        return {
            "response": (
                "AI Agent ကို လက်ရှိအသုံးပြုလို့မရသေးပါ။ "
                "Groq API connection ကို စစ်ဆေးပါ။"
            )
        }

    # ============================================================
    # NORMALIZE SCAN ID
    # ============================================================

    scan_id_int = None

    if req.scan_result:
        raw_scan_id = req.scan_result.get("scan_id")

        if raw_scan_id is not None:
            scan_id_value = str(raw_scan_id)

            if scan_id_value.startswith("SCAN-"):
                scan_id_value = scan_id_value.replace(
                    "SCAN-", "", 1
                )

            try:
                scan_id_int = int(scan_id_value)
            except ValueError:
                scan_id_int = None

    # ============================================================
    # LOAD PREVIOUS CONVERSATION
    # IMPORTANT:
    # Load BEFORE saving current user message
    # to avoid sending the current message twice.
    # ============================================================

    chat_history = []

    if scan_id_int is not None:

        previous_messages = (
            db.query(AIChatMessage)
            .filter(
                AIChatMessage.scan_id == scan_id_int
            )
            .order_by(
                AIChatMessage.created_at.asc()
            )
            .limit(30)
            .all()
        )

        for msg in previous_messages:

            role = (
                "assistant"
                if msg.role == "agent"
                else "user"
            )

            chat_history.append({
                "role": "assistant" if role == "agent" else "user",
                "content": msg.content[:4000],
            })
    chat_history = chat_history[-10:]
    # ============================================================
    # SAVE CURRENT USER MESSAGE
    # ============================================================

    if scan_id_int is not None:

        user_chat = AIChatMessage(
            scan_id=scan_id_int,
            role="user",
            content=req.message[:4000]
        )

        db.add(user_chat)
        db.commit()

    # ============================================================
    # BUILD SCAN CONTEXT
    # ============================================================

    scan_context = None

    if req.scan_result:

        vulnerabilities = req.scan_result.get(
            "vulnerabilities",
            []
        )

        compact_vulnerabilities = []

        for v in vulnerabilities[:10]:

            compact_vulnerabilities.append({

                "type": str(
                    v.get(
                        "vulnerability_type",
                        v.get("type", "UNKNOWN")
                    )
                )[:120],

                "severity": str(
                    v.get("severity", "UNKNOWN")
                )[:30],

                "cvss_score": v.get(
                    "cvss_score",
                    None
                ),

                "file": str(
                    v.get("file_path", "")
                )[:200],

                "line": v.get(
                    "line_number",
                    None
                ),

                "suggestion": str(
                    v.get("suggestion", "")
                )[:500],

                "vulnerable_code": str(
                    v.get("vulnerable_code", "")
                )[:1000],

                "secure_code": str(
                    v.get("secure_code", "")
                )[:1000],
            })

        scan_context = {
            "scan_id": req.scan_result.get(
                "scan_id",
                "N/A"
            ),

            "repository": req.scan_result.get(
                "repo_name",
                "N/A"
            ),

            "total_issues": req.scan_result.get(
                "total_issues",
                0
            ),

            "vulnerabilities": compact_vulnerabilities,
        }

    # ============================================================
    # SYSTEM PROMPT
    # ============================================================

    system_prompt = """
You are SecureCode AI Agent.

You are a real conversational AI assistant specialized in
software development, cybersecurity, code security, and
SecureCode SAST.

Your job is to understand the user's CURRENT intent first.

IMPORTANT BEHAVIOR:

1. GENERAL CONVERSATION
- Respond naturally to greetings, casual conversation,
  personal questions, learning questions, programming questions,
  and general topics.
- Do NOT force cybersecurity or vulnerability answers into
  unrelated conversations.

2. CONVERSATION MEMORY
- Use previous conversation messages as context.
- Remember facts explicitly provided by the user during
  the conversation.
- If the user says:
  "ငါ့နာမည် ဇာနည်ထွန်း"
  and later asks:
  "ငါ့သိလား"
  answer using the previous conversation.
- Never invent personal information.
- If the information is not present in the conversation,
  say that you do not know.

3. SCAN CONTEXT
- A scan result may be provided.
- DO NOT automatically use it for every question.
- Use scan information ONLY when the current question is
  related to:
  vulnerabilities, security findings, scan results,
  repository security, remediation, code security,
  or the scanned project.
- If the question is unrelated to the scan, ignore the scan.

4. CYBERSECURITY
- You are allowed to explain cybersecurity concepts,
  ethical hacking, defensive security, vulnerabilities,
  secure coding, penetration-testing concepts, and
  security best practices.
- For harmful or clearly malicious requests, do not provide
  actionable instructions that enable real-world compromise.
  Redirect toward legal, defensive, or lab-based learning.

5. PROGRAMMING
- Answer programming questions normally.
- Provide code when useful or requested.
- Do not force security explanations into ordinary
  programming questions.

6. RESPONSE STYLE
- Respond naturally and directly.
- Do not always use the security format.
- Do not mention scan findings unless relevant.
- Do not repeat the user's question.
- Match the response length to the user's question.
- Simple questions should receive short answers.
- Casual conversation should feel natural and conversational.
- Detailed questions should receive a complete explanation.
- Do not unnecessarily make responses long.
- Do not stop or truncate an answer just to satisfy a word limit.
- Finish the explanation completely before ending the response.
- Respond in the user's language when possible.

7. SECURITY FORMAT
ONLY use this format when the user is actually asking about
a vulnerability or security finding:

🔴 Risk: ...

🛠️ Fix:
- ...
- ...
- ...

🎯 Priority: ...

8. PERSONAL QUESTIONS
If the user asks:
"ငါ့သိလား"
"ငါ့ကိုသိလား"
"Who am I?"
use conversation history.

If the user previously provided their name, use it naturally.

9. AMBIGUOUS QUESTIONS
If the user says something broad such as:
"ငါသိချင်တာရှိတယ်"
"မေးစရာရှိတယ်"
respond naturally and ask what they want to know.

Do NOT guess that they are asking about a vulnerability.

10. NEVER INVENT SCAN FINDINGS
Only discuss vulnerabilities that actually exist
in the provided scan context.

11. RESPONSE COMPLETENESS
- Always prioritize a complete and useful answer.
- If the user asks for "အသေးစိတ်", provide sufficient detail.
- If the user asks a simple question, keep the answer short.
- If the answer requires multiple steps, explain them in order.
- Never cut an explanation in the middle of a sentence.
- Do not add unrelated information just to make the response longer.

LANGUAGE REQUIREMENT:

You MUST respond to the user in Burmese (Myanmar language).

The user-facing explanation, title, description, risk explanation,
impact, remediation steps, and recommendations MUST be written in Burmese.

Do NOT respond in Thai, Chinese, Japanese, Korean, Vietnamese,
or any other language unless the user explicitly requests that language.

Technical terms, programming keywords, function names, variable names,
file names, vulnerability IDs, and code MUST remain in English.

If you provide code comments, keep code comments in English unless
the user explicitly asks for Burmese comments.

Never mix multiple natural languages in the same response.
"""

    # ============================================================
    # BUILD USER MESSAGE
    # ============================================================

    safe_user_message = req.message[:4000]

    user_prompt = f"""
    CURRENT USER MESSAGE:
    {safe_user_message}

    CURRENT SCAN CONTEXT:
    {scan_context if scan_context else "No scan context provided."}

    Use the conversation history to understand the user's intent.

    Answer the current message naturally and completely.
    Keep simple questions short.
    Provide more detail when the user asks for details.
    Do not force security-related formatting unless the question is about security.
    Do not stop in the middle of an explanation.
    
    Answer in Burmese language.
Keep technical terms and code in English.
Do not use Thai, Chinese, Japanese, or other languages.
    """

    # ============================================================
    # DEBUG
    # ============================================================

    print(
        f"📦 AI REQUEST SIZE: "
        f"{len(system_prompt.encode('utf-8')) + len(user_prompt.encode('utf-8'))} bytes"
    )

    print("🧠 CHAT HISTORY SENT TO AI:")

    print(
        json.dumps(
            chat_history,
            ensure_ascii=False,
            indent=2
        )
    )

    # ============================================================
    # CALL GROQ
    # ============================================================

    try:

        print(
            "🤖 AI AGENT: Processing user request..."
        )

        # --------------------------------------------------------
        # GET AVAILABLE MODELS
        # --------------------------------------------------------

        models_list = groq_client.models.list()

        available_models = [
            model.id
            for model in models_list.data
            if model.id
        ]

        print(
            f"📋 AI AGENT AVAILABLE MODELS: "
            f"{available_models}"
        )

        # --------------------------------------------------------
        # PREFERRED MODELS
        # --------------------------------------------------------

        preferred_models = [
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
        ]

        selected_model = None

        for preferred in preferred_models:

            if preferred in available_models:

                selected_model = preferred
                break

        if not selected_model and available_models:

            selected_model = available_models[0]

        if not selected_model:

            raise Exception(
                "No available Groq chat model found."
            )

        print(
            f"🤖 AI AGENT MODEL: {selected_model}"
        )

        # ========================================================
        # BUILD AI MESSAGES
        # ========================================================

        ai_messages = [
            {
                "role": "system",
                "content": system_prompt,
            }
        ]

        # Add previous conversation
        ai_messages.extend(chat_history)

        # Add current user request
        ai_messages.append({
            "role": "user",
            "content": user_prompt,
        })

        # ========================================================
        # GROQ REQUEST
        # ========================================================

        response = groq_client.chat.completions.create(
            model=selected_model,
            messages=ai_messages,
            temperature=0.4,
            max_completion_tokens=2000,
        )

        if not response or not response.choices:
            raise Exception(
                "AI Agent returned empty response"
            )

        print(
            "🛑 FINISH REASON:",
            response.choices[0].finish_reason
        )

        print(
            "📊 COMPLETION TOKENS:",
            response.usage.completion_tokens
            if response.usage
            else "N/A"
        )

        agent_response = (
                response.choices[0].message.content
                or "AI Agent response မရရှိပါ။"
        )

        agent_response = agent_response.strip()

        print("🧠 FULL AI RESPONSE:")
        print(agent_response)

        print(
            "🧠 RESPONSE LENGTH:",
            len(agent_response)
        )

        print(
            "✅ AI AGENT: Response generated successfully"
        )

        # ========================================================
        # SAVE AI RESPONSE
        # ========================================================

        if scan_id_int is not None:

            agent_chat = AIChatMessage(
                scan_id=scan_id_int,
                role="agent",
                content=agent_response[:4000]
            )

            db.add(agent_chat)
            db.commit()

        # ========================================================
        # RESPONSE
        # ========================================================

        return {
            "response": agent_response,
            "agent": "SecureCode AI Agent",
            "scan_context_used": bool(
                scan_context
            ),
            "history_used": len(chat_history) > 0,
        }

    # ============================================================
    # ERROR HANDLING
    # ============================================================

    except Exception as e:

        print(
            f"❌ AI AGENT ERROR: {e}"
        )

        traceback.print_exc()

        return {
            "response": (
                "AI Agent မှ response ထုတ်ပေးရာတွင် "
                "အမှားတစ်ခု ဖြစ်ပေါ်ခဲ့ပါသည်။"
            ),
            "error": str(e),
        }

@app.get("/api/ai-agent/history/{scan_id}")
def get_ai_chat_history(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan_id_value = str(scan_id)

    if scan_id_value.startswith("SCAN-"):
        scan_id_value = scan_id_value.replace("SCAN-", "", 1)

    try:
        scan_id_int = int(scan_id_value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid scan_id"
        )

    messages = (
        db.query(AIChatMessage)
        .filter(AIChatMessage.scan_id == scan_id_int)
        .order_by(AIChatMessage.created_at.asc())
        .all()
    )

    return {
        "scan_id": scan_id_int,
        "messages": [
            {
                "id": msg.id,
                "role": msg.role,
                "content": msg.content,
                "created_at": msg.created_at.isoformat()
                if msg.created_at else None,
            }
            for msg in messages
        ],
    }
# ============================================================
# CLEAR AI AGENT CHAT HISTORY
# ============================================================

@app.delete("/api/ai-agent/history/{scan_id}")
def clear_ai_chat_history(
    scan_id: str,
    db: Session = Depends(get_db)
):
    scan_id_value = str(scan_id)

    # Support both "28" and "SCAN-28"
    if scan_id_value.startswith("SCAN-"):
        scan_id_value = scan_id_value.replace("SCAN-", "", 1)

    try:
        scan_id_int = int(scan_id_value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid scan_id"
        )

    deleted_count = (
        db.query(AIChatMessage)
        .filter(AIChatMessage.scan_id == scan_id_int)
        .delete(synchronize_session=False)
    )

    db.commit()

    return {
        "success": True,
        "deleted_count": deleted_count,
        "scan_id": scan_id_int,
        "message": "AI Agent chat history cleared successfully."
    }

