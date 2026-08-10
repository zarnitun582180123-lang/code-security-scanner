import os
from celery import Celery
from app.scanner.ast_engine import scan_code_string

# Redis Broker URL
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("scanner_tasks", broker=REDIS_URL, backend=REDIS_URL)


@celery_app.task
def process_background_scan(code_content: str, file_path: str):
    """ Background မှာ Scan အလုပ်လုပ်ပေးမယ့် Celery Task """
    print(f"[*] Background scanning started for: {file_path}")
    issues = scan_code_string(code_content, file_path)
    print(f"[+] Scan completed for {file_path}. Found {len(issues)} issues.")

    return {
        "file_path": file_path,
        "total_issues": len(issues),
        "vulnerabilities": issues
    }