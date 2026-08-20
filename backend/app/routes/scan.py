import traceback

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Repository, Scan, Vulnerability
from app.scanner.ast_engine import scan_code_string
from app.services.git_service import do_git_clone_and_scan


router = APIRouter(
    prefix="/scan",
    tags=["Scanning"],
)


class RepoScanRequest(BaseModel):
    repo_name: str
    repo_url: str


class CodeSnippetRequest(BaseModel):
    code_string: str


def format_scan_issues(raw_issues: list, default_file_path: str):
    """
    Convert scanner output into a consistent API response format.
    """

    formatted_issues = []

    for issue in raw_issues:
        sev = issue.get("severity") or "HIGH"

        v_type = (
            issue.get("vulnerability_type")
            or issue.get("type")
            or "SECURITY_RISK"
        )

        f_path = (
            issue.get("file_path")
            or issue.get("file")
            or default_file_path
        )

        l_num = (
            issue.get("line_number")
            or issue.get("line")
            or 1
        )

        sugg = (
            issue.get("suggestion")
            or "မလုံခြုံသော Code Pattern ကို ပြန်လည် ပြင်ဆင်ပါ။"
        )

        vuln_code = (
            issue.get("vulnerable_code")
            or issue.get("code")
            or issue.get("snippet")
            or ""
        )

        sec_code = issue.get("secure_code") or ""

        formatted_issues.append(
            {
                "severity": str(sev).upper(),
                "vulnerability_type": str(v_type),
                "type": str(v_type),
                "file_path": str(f_path),
                "line_number": int(l_num),
                "suggestion": str(sugg),
                "vulnerable_code": str(vuln_code),
                "secure_code": str(sec_code),
            }
        )

    return formatted_issues


@router.post("/git")
async def scan_git_repository(
    payload: RepoScanRequest,
    db: Session = Depends(get_db),
):
    """
    Clone and scan a Git repository.
    """

    repo = (
        db.query(Repository)
        .filter(
            Repository.repo_url == payload.repo_url,
            Repository.repo_name == payload.repo_name,
        )
        .first()
    )

    if not repo:
        repo = Repository(
            repo_name=payload.repo_name,
            repo_url=payload.repo_url,
        )

        db.add(repo)
        db.commit()
        db.refresh(repo)

    try:
        issues = await run_in_threadpool(
            do_git_clone_and_scan,
            payload.repo_url,
        )

    except Exception as e:
        print("\n=== [DEBUG ERROR LOG START] ===")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Details: {str(e)}")
        traceback.print_exc()
        print("=== [DEBUG ERROR LOG END] ===\n")

        raise HTTPException(
            status_code=400,
            detail=str(e),
        )

    scan_record = Scan(
        repo_id=repo.id,
        status="COMPLETED",
        total_issues=len(issues),
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
            secure_code=issue["secure_code"],
        )

        db.add(vuln)

    db.commit()

    return {
        "scan_id": f"SCAN-{scan_record.id}",
        "repo_name": repo.repo_name,
        "repo_url": repo.repo_url,
        "total_issues": len(issues),
        "vulnerabilities": issues,
        "issues": issues,
    }


@router.post("/snippet")
def scan_code_snippet(
    payload: CodeSnippetRequest,
    db: Session = Depends(get_db),
):
    """
    Scan directly submitted source code.
    """

    try:
        raw_issues = scan_code_string(
            payload.code_string,
            file_path="snippet_input",
        )

        formatted_issues = format_scan_issues(
            raw_issues,
            default_file_path="snippet_input",
        )

        repo = (
            db.query(Repository)
            .filter(
                Repository.repo_name == "Direct Code Snippet Audit"
            )
            .first()
        )

        if not repo:
            repo = Repository(
                repo_name="Direct Code Snippet Audit",
                repo_url="N/A (Snippet)",
            )

            db.add(repo)
            db.commit()
            db.refresh(repo)

        scan_record = Scan(
            repo_id=repo.id,
            status="COMPLETED",
            total_issues=len(formatted_issues),
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
                secure_code=issue["secure_code"],
            )

            db.add(vuln)

        db.commit()

        return {
            "scan_id": f"SCAN-{scan_record.id}",
            "total_issues": len(formatted_issues),
            "vulnerabilities": formatted_issues,
            "issues": formatted_issues,
        }

    except Exception as e:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail=f"Snippet Scan Failed: {str(e)}",
        )