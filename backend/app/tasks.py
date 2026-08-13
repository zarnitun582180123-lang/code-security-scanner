import os
import git
import tempfile
import shutil
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Repository, Scan, Vulnerability
from app.scanner.ast_engine import scan_directory


@celery_app.task
def run_async_scan(repo_name: str, repo_url: str):
    db = SessionLocal()
    try:
        # 1. Repo ရှိ/မရှိ စစ်မည်
        repo = db.query(Repository).filter(Repository.repo_url == repo_url).first()
        if not repo:
            repo = Repository(repo_name=repo_name, repo_url=repo_url)
            db.add(repo)
            db.commit()
            db.refresh(repo)

        # 2. Temp directory သို့ Clone ဆွဲမည်
        temp_dir = tempfile.mkdtemp()

        # Background Celery Worker မှာ Git Login Popup မတက်အောင် ပိတ်သည့် Code
        os.environ["GIT_TERMINAL_PROMPT"] = "0"

        git.Repo.clone_from(repo_url, temp_dir)

        # 3. Scan ဖတ်မည်
        issues = scan_directory(temp_dir)

        # 4. Record DB ထဲ သိမ်းမည်
        scan_record = Scan(
            repo_id=repo.id,
            status="COMPLETED",
            total_issues=len(issues)
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        # 5. Vulnerabilities များကို Null-Safe ပြုလုပ်၍ DB ထဲ သိမ်းမည်
        for issue in issues:
            sev = issue.get("severity") or "MEDIUM"
            v_type = issue.get("vulnerability_type") or issue.get("type") or "UNKNOWN"
            f_path = issue.get("file_path") or issue.get("file") or "unknown"
            l_num = issue.get("line_number") or issue.get("line") or 0

            vuln = Vulnerability(
                scan_id=scan_record.id,
                severity=str(sev),
                vulnerability_type=str(v_type),
                file_path=str(f_path),
                line_number=int(l_num),
                suggestion=str(issue.get("suggestion", ""))
            )
            db.add(vuln)

        db.commit()

        # 6. DB ထဲ သိမ်းပြီးမှ Temp Folder ကို ဖျက်မည်
        shutil.rmtree(temp_dir, ignore_errors=True)

        return {"status": "SUCCESS", "scan_id": scan_record.id, "total_issues": len(issues)}

    except Exception as e:
        db.rollback()
        # Temp folder ကျန်ခဲ့ပါက ရှင်းထုတ်ပေးခြင်း
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        return {"status": "FAILED", "error": str(e)}
    finally:
        db.close()