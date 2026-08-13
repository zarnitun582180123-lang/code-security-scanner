import os
import shutil
import tempfile
import uuid
import subprocess
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import Scan, Vulnerability, Repository
from app.scanner.ast_engine import scan_directory


@celery_app.task(name="app.tasks.run_async_scan")
def run_async_scan(scan_id: int, repo_url: str):
    db = SessionLocal()
    scan_record = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan_record:
        db.close()
        return {"status": "FAILED", "reason": "Scan record not found"}

    scan_folder_name = f"scan_{uuid.uuid4().hex[:8]}"
    temp_dir = os.path.join(tempfile.gettempdir(), scan_folder_name)

    try:
        scan_record.status = "RUNNING"
        db.commit()

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"

        cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)

        if result.returncode != 0:
            raise Exception(f"Git Clone Failed: {result.stderr.strip()}")

        issues = scan_directory(temp_dir)

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

        scan_record.status = "COMPLETED"
        scan_record.total_issues = len(issues)
        db.commit()

        return {
            "status": "SUCCESS",
            "scan_id": scan_id,
            "total_issues": len(issues)
        }

    except Exception as e:
        scan_record.status = "FAILED"
        db.commit()
        return {
            "status": "FAILED",
            "error": str(e)
        }

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        db.close()