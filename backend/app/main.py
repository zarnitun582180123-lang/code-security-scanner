import os
import git
import tempfile
import shutil
import subprocess
import traceback
import uuid
from fastapi import FastAPI, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

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
    allow_origins=["*"],  # Frontend နေရာမရွေး ခေါ်ယူခွင့်ပြုခြင်း
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RepoScanRequest(BaseModel):
    repo_name: str
    repo_url: str


class CodeSnippetRequest(BaseModel):
    code_string: str


# --- NEW: AI Security Coach Request Model ---
class AICoachRequest(BaseModel):
    vulnerability_type: str
    suggestion: str
    vulnerable_code: str


# Background Thread ထဲမှာ သီးသန့် run ရန် Helper Function
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
        raise Exception(f"Git Clone Error: {result.stderr.strip()}")

    # Scan directory
    issues = scan_directory(temp_dir)

    # Cleanup
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

    return issues


@app.post("/scan/git")
async def scan_git_repository(payload: RepoScanRequest, db: Session = Depends(get_db)):
    # 1. Repo ရှိ/မရှိ စစ်မယ်
    repo = db.query(Repository).filter(Repository.repo_url == payload.repo_url).first()
    if not repo:
        repo = Repository(repo_name=payload.repo_name, repo_url=payload.repo_url)
        db.add(repo)
        db.commit()
        db.refresh(repo)

    try:
        # 2. FastAPI Threadpool သုံးပြီး Background Thread ထဲမှာ Run ခိုင်းခြင်း
        issues = await run_in_threadpool(do_git_clone_and_scan, payload.repo_url)
    except Exception as e:
        print("\n=== [DEBUG ERROR LOG START] ===")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Details: {str(e)}")
        traceback.print_exc()
        print("=== [DEBUG ERROR LOG END] ===\n")
        raise HTTPException(status_code=400, detail=f"Scan Failed: {str(e)}")

    # 3. Scan Record DB ထဲ သိမ်းမယ်
    scan_record = Scan(
        repo_id=repo.id,
        status="COMPLETED",
        total_issues=len(issues)
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    # 4. Vulnerabilities DB ထဲ ထည့်သိမ်းမယ်
    for issue in issues:
        vuln = Vulnerability(
            scan_id=scan_record.id,
            severity=issue.get("severity", "MEDIUM"),
            vulnerability_type=issue.get("type", "UNKNOWN"),
            file_path=issue.get("file_path", "unknown"),
            line_number=issue.get("line_number", 0),
            suggestion=issue.get("suggestion", "")
        )
        db.add(vuln)

    db.commit()

    return {
        "scan_id": scan_record.id,
        "repo_name": repo.repo_name,
        "repo_url": repo.repo_url,
        "total_issues": len(issues),
        "vulnerabilities": issues
    }


# --- Code Snippet Direct Scan Endpoint ---
@app.post("/scan/snippet")
def scan_code_snippet(payload: CodeSnippetRequest):
    try:
        issues = scan_code_string(payload.code_string)
        return {
            "total_issues": len(issues),
            "vulnerabilities": issues
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Snippet Scan Failed: {str(e)}")


# --- 🤖 NEW: AI Security Coach Endpoint ---
@app.post("/api/ai-coach")
def get_ai_coach_explanation(req: AICoachRequest):
    vtype = req.vulnerability_type.upper()

    if "COMMAND_INJECTION" in vtype:
        hacking_scenario = "Attacker က HTTP Request parameter ထဲကနေတစ်ဆင့် OS Commands တွေ ရိုက်ထည့်ပြီး Server တစ်ခုလုံးကို Remote Code Execution (RCE) နဲ့ အပိုင်စီးသွားနိုင်ပါတယ်။"
        why_dangerous = "Input Validation မလုပ်ဘဲ OS Level Functions (exec, system) တွေကို တိုက်ရိုက် ခေါ်သုံးထားလို့ဖြစ်ပါတယ်။"
        fix_logic = "escapeshellcmd() သို့မဟုတ် escapeshellarg() သုံးပြီး Input ကို Clean လုပ်ပါ။ သို့မဟုတ် Language Native Functions ကို အစားထိုးသုံးပါ။"
    elif "SQL_INJECTION" in vtype:
        hacking_scenario = "Attacker က URL / Form Field ထဲ ' OR '1'='1 စတဲ့ Malicious SQL Code တွေ ထည့်ပြီး Database ထဲက User Passwords တွေကို ခိုးယူသွားနိုင်ပါတယ်။"
        why_dangerous = "User Input ကို SQL Statement ထဲ String Concatenation (+) နဲ့ တိုက်ရိုက် ရောစပ်ရေးသားထားလို့ဖြစ်ပါတယ်။"
        fix_logic = "SQL Queries တွေမှာ Prepared Statements (PDO / Parameterized Queries) တွေကို မဖြစ်မနေ အသုံးပြုရပါမည်။"
    elif "SECRET" in vtype or "KEY" in vtype or "PASSWORD" in vtype:
        hacking_scenario = "GitHub ပေါ် Code တင်မိလိုက်တာနဲ့ Automated Bots တွေက စက္ကန့်ပိုင်းအတွင်း Key ကို ခိုးယူပြီး AWS/Database တွေကို ဖျက်ဆီးသွားနိုင်ပါတယ်။"
        why_dangerous = "Credentials များကို Source Code ထဲ Plain Text အတိုင်း ရေးထားမိလို့ဖြစ်ပါတယ်။"
        fix_logic = "Secrets များကို .env ဖိုင်ထဲ ရွှေ့ပါ။ os.getenv() သို့မဟုတ် $_ENV ဖြင့်သာ လှမ်းယူသုံးပြီး .gitignore ထဲ .env ထည့်ပါ။"
    else:
        hacking_scenario = "Attacker များသည် မလုံခြုံသော System Code Pattern များကို အသုံးချ၍ Application Control ကို ရယူနိုင်ပါသည်။"
        why_dangerous = "Unsanitized User Data သို့မဟုတ် Insecure Functions များ သုံးထားခြင်းကြောင့် ဖြစ်ပါသည်။"
        fix_logic = "Input Validation နှင့် Secure Coding Guidelines များကို လိုက်နာပါ။"

    return {
        "vulnerability_type": req.vulnerability_type,
        "why_dangerous": why_dangerous,
        "hacking_scenario": hacking_scenario,
        "remediation_logic": fix_logic
    }


@app.post("/scan/async")
def scan_repository_async(payload: RepoScanRequest):
    task = run_async_scan.delay(payload.repo_name, payload.repo_url)
    return {
        "message": "Scan task submitted successfully to Background Worker!",
        "task_id": task.id,
        "status": "PROCESSING"
    }


@app.get("/scan/status/{task_id}")
def get_scan_status(task_id: str):
    task_result = celery_app.AsyncResult(task_id)

    if task_result.ready():
        return {
            "task_id": task_id,
            "status": task_result.status,
            "result": task_result.result
        }
    else:
        return {
            "task_id": task_id,
            "status": task_result.status,
            "message": "Scan is still running in the background..."
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


@app.get("/reports/pdf/{scan_id}")
def export_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    repo = db.query(Repository).filter(Repository.id == scan.repo_id).first()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

    pdf_buffer = generate_pdf_report(
        scan_id=scan.id,
        repo_name=repo.repo_name if repo else "Unknown",
        total_issues=scan.total_issues,
        vulnerabilities=vulns
    )

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security_report_scan_{scan_id}.pdf"}
    )