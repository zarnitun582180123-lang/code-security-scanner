import ast
import os
import re

SECURITY_PATTERNS = [
    {
        "id": "AWS_KEY",
        "type": "HARDCODED_AWS_KEY",
        "severity": "CRITICAL",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "suggestion": "AWS Access Key များကို Source Code ထဲတွင် ရေးသားခြင်းမှ ရှောင်ကြဉ်ပါ။ Environment Variables (os.getenv) သို့မဟုတ် Secret Manager ကို အသုံးပြုပါ။"
    },
    {
        "id": "GENERIC_SECRET",
        "type": "HARDCODED_SECRET",
        "severity": "HIGH",
        "regex": r"(?i)(secret[_\-]?key|api[_\-]?key|password|passwd|auth[_\-]?token)\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
        "suggestion": "အရေးကြီးသော Secret Key/Password များကို Code ထဲတွင် Hardcode မရေးဘဲ .env ဖိုင်ထဲတွင် သိမ်းဆည်းပါ။"
    },
    {
        "id": "COMMAND_INJECTION",
        "type": "COMMAND_INJECTION_RISK",
        "severity": "CRITICAL",
        "regex": r"(os\.system|subprocess\.Popen|subprocess\.call|eval|exec)\s*\(",
        "suggestion": "User Input များကို os.system သို့မဟုတ် eval/exec ထဲသို့ တိုက်ရိုက် မထည့်ပါနှင့်။ subprocess.run([], check=True) ကို Array ဖြင့် သုံးပါ။"
    }
]


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path="snippet"):
        self.file_path = file_path
        self.issues = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.issues.append({
                    "severity": "CRITICAL",
                    "vulnerability_type": "DANGEROUS_EVAL_EXEC",
                    "file_path": self.file_path,
                    "line_number": node.lineno,
                    "suggestion": f"Dangerous function '{node.func.id}()' detected. Dynamic Code Execution သည် Remote Code Execution (RCE) ကို ဖြစ်ပေါ်စေနိုင်ပါသည်။"
                })

        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                if node.func.attr == 'system':
                    self.issues.append({
                        "severity": "CRITICAL",
                        "vulnerability_type": "OS_SYSTEM_COMMAND_INJECTION",
                        "file_path": self.file_path,
                        "line_number": node.lineno,
                        "suggestion": "os.system() ကို အသုံးမပြုပါနှင့်။ Command Injection ဖြစ်နိုင်ခြေရှိသဖြင့် subprocess Module ကို Argument List ဖြင့် ပြောင်းလဲသုံးပါ။"
                    })

        self.generic_visit(node)


def scan_code_string(code_string: str, file_path: str = "snippet") -> list:
    issues = []

    lines = code_string.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        for pattern in SECURITY_PATTERNS:
            if re.search(pattern["regex"], line):
                issues.append({
                    "severity": pattern["severity"],
                    "vulnerability_type": pattern["type"],
                    "file_path": file_path,
                    "line_number": line_idx,
                    "suggestion": pattern["suggestion"]
                })

    try:
        tree = ast.parse(code_string)
        visitor = SecurityASTVisitor(file_path=file_path)
        visitor.visit(tree)

        for ast_issue in visitor.issues:
            if not any(i["line_number"] == ast_issue["line_number"] and i["vulnerability_type"] == ast_issue[
                "vulnerability_type"] for i in issues):
                issues.append(ast_issue)

    except SyntaxError:
        pass
    except Exception as e:
        print(f"AST Parsing Error in {file_path}: {e}")

    return issues


def scan_directory(directory_path: str) -> list:
    all_issues = []

    for root, _, files in os.walk(directory_path):
        for file in files:
            if ".git" in root or file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.zip', '.tar', '.gz', '.pyc', '.db')):
                continue

            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, directory_path)

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    file_issues = scan_code_string(content, file_path=relative_path)
                    all_issues.extend(file_issues)
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")

    return all_issues