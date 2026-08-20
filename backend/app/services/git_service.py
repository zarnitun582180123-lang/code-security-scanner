import os
import shutil
import subprocess
import tempfile
import uuid

from app.scanner.ast_engine import scan_directory


def do_git_clone_and_scan(repo_url: str):
    """
    Clone a Git repository into a temporary directory,
    scan the repository using the SAST engine,
    format the findings, then remove the temporary directory.
    """

    scan_folder_name = f"scan_{uuid.uuid4().hex[:8]}"
    temp_dir = os.path.join(tempfile.gettempdir(), scan_folder_name)

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "never"

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        repo_url,
        temp_dir,
    ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        if result.returncode != 0:
            err_msg = result.stderr.strip()

            if any(
                error_text in err_msg
                for error_text in [
                    "Could not resolve host",
                    "unable to access",
                    "Failed to connect",
                ]
            ):
                raise Exception(
                    "🌐 Internet ချိတ်ဆက်မှု မရှိသေးပါ။ "
                    "ကျေးဇူးပြု၍ Internet Connection ကို စစ်ဆေးပြီးမှ "
                    "ပြန်လည် စမ်းသပ်ပေးပါ။"
                )

            raise Exception(f"Git Clone Error: {err_msg}")

        raw_issues = scan_directory(temp_dir)

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
                or "unknown_file"
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

    finally:
        # Scan ပြီးတာနဲ့ temporary cloned repository ကို ဖျက်မယ်
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)