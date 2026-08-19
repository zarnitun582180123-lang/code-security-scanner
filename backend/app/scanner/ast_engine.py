import ast
import os
import re

# Directory / Folder များကို Ignore လုပ်ရန် Filter သတ်မှတ်ချက်
EXCLUDED_DIRS = {
    'frontend',
    'node_modules',
    '.next',
    'dist',
    'build',
    '.git',
    '__pycache__',
    'venv',
    '.venv'
}

# 🟢 Support ပြုလုပ်ပေးထားသော Extensions များ
SUPPORTED_EXTENSIONS = {
    '.py',
    '.js', '.jsx', '.ts', '.tsx',
    '.php',
    '.html', '.xaml',
    '.kts', '.kt',
    '.txt', '.env', '.json', '.yaml', '.yml'
}

# 🟢 Security Regex Patterns (Multi-language Support)
SECURITY_PATTERNS = [
    {
        "id": "AWS_KEY",
        "type": "HARDCODED_AWS_KEY",
        "severity": "CRITICAL",
        "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "suggestion": "AWS Access Key များကို Source Code ထဲတွင် ရေးသားခြင်းမှ ရှောင်ကြဉ်ပါ။ Environment Variables သို့မဟုတ် Secret Manager ကို အသုံးပြုပါ။",
        "secure_code_template": "import os\nAWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')"
    },
    {
        "id": "GENERIC_SECRET",
        "type": "HARDCODED_SECRET",
        "severity": "HIGH",
        "regex": r"(?i)(secret[_\-]?key|api[_\-]?key|password|passwd|auth[_\-]?token|private[_\-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
        "suggestion": "အရေးကြီးသော Secret Key/Password များကို Code ထဲတွင် Hardcode မရေးဘဲ .env ဖိုင်ထဲတွင် သိမ်းဆည်းပါ။",
        "secure_code_template": "import os\nSECRET_KEY = os.environ.get('SECRET_KEY')"
    },
    {
        "id": "COMMAND_INJECTION",
        "type": "COMMAND_INJECTION_RISK",
        "severity": "CRITICAL",
        "regex": r"(os\.system|subprocess\.Popen|subprocess\.call|eval|exec|shell_exec|passthru|system)\s*\(",
        "suggestion": "User Input များကို os.system/exec/eval ထဲသို့ တိုက်ရိုက် မထည့်ပါနှင့်။ Command Injection ဖြစ်ပွားနိုင်ပါသည်။",
        "secure_code_template": "import subprocess\nsubprocess.run(['command', 'arg'], check=True)"
    },
    {
        "id": "PHP_SQL_INJECTION",
        "type": "PHP_SQL_INJECTION_RISK",
        "severity": "CRITICAL",
        "regex": r"(mysqli_query|pg_query|mysql_query)\s*\(\s*\$.*?\$(?:_GET|_POST|_REQUEST)",
        "suggestion": "PHP ထဲတွင် User Input များကို SQL Query ထဲ တိုက်ရိုက်မဆက်ပါနှင့်။ Prepared Statements / PDO ကို အသုံးပြုပါ။",
        "secure_code_template": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $id]);"
    },
    {
        "id": "REACT_XSS_RISK",
        "type": "DANGEROUS_INNER_HTML_XSS",
        "severity": "HIGH",
        "regex": r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
        "suggestion": "React/TSX ထဲတွင် dangerouslySetInnerHTML သုံးခြင်းသည် Cross-Site Scripting (XSS) ဖြစ်စေနိုင်ပါသည်။ DOMPurify စာကြည့်တိုက်ဖြင့် Sanitize လုပ်ပါ။",
        "secure_code_template": "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />"
    },
    {
        "id": "INSECURE_HTTP_LINK",
        "type": "INSECURE_HTTP_PROTOCOL",
        "severity": "MEDIUM",
        "regex": r"http://[a-zA-Z0-9\.\-]+",
        "suggestion": "မလုံခြုံသော Plain HTTP Protocol ကို သုံးထားပါသည်။ Encrypted HTTPS ချိတ်ဆက်မှုကိုသာ အသုံးပြုပါ။",
        "secure_code_template": "https://your-secure-domain.com"
    }
]


def extract_line(source_code: str, line_no: int) -> str:
    """
    Source Code ထဲက သက်ဆိုင်ရာ line number ရှိ တကယ့် code အစစ်ကို ထုတ်ပေးသည်။
    """
    lines = source_code.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, source_code: str, file_path: str = "snippet"):
        self.source_code = source_code
        self.file_path = file_path
        self.issues = []

    def visit_Call(self, node):
        line_no = node.lineno
        actual_code = extract_line(self.source_code, line_no)

        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.issues.append({
                    "severity": "CRITICAL",
                    "vulnerability_type": "DANGEROUS_EVAL_EXEC",
                    "file_path": self.file_path,
                    "line_number": line_no,
                    "vulnerable_code": actual_code,
                    "secure_code": "# Avoid using eval/exec. Use safest methods or ast.literal_eval if parsing data safely.\n# Example:\nimport ast\nsafe_data = ast.literal_eval(user_input_str)",
                    "suggestion": f"Dangerous function '{node.func.id}()' detected. Dynamic Code Execution သည် Remote Code Execution (RCE) ကို ဖြစ်ပေါ်စေနိုင်ပါသည်။"
                })

        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                if node.func.attr == 'system':
                    self.issues.append({
                        "severity": "CRITICAL",
                        "vulnerability_type": "OS_SYSTEM_COMMAND_INJECTION",
                        "file_path": self.file_path,
                        "line_number": line_no,
                        "vulnerable_code": actual_code,
                        "secure_code": "import subprocess\nsubprocess.run(['cmd', 'arg'], check=True)",
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
                    "vulnerable_code": line.strip(),  # Regex မိသွားသည့် တကယ့် Code စာကြောင်းအစစ်
                    "secure_code": pattern.get("secure_code_template", ""),
                    "suggestion": pattern["suggestion"]
                })

    # Python File ဖြစ်မှသာ Python AST Visitor ဖြင့် တိကျစွာ ထပ်မံစစ်ဆေးမည်
    if file_path.endswith('.py') or file_path == "snippet":
        try:
            tree = ast.parse(code_string)
            visitor = SecurityASTVisitor(source_code=code_string, file_path=file_path)
            visitor.visit(tree)

            for ast_issue in visitor.issues:
                # Check for duplicates based on line_number and vulnerability_type
                if not any(i["line_number"] == ast_issue["line_number"] and i["vulnerability_type"] == ast_issue["vulnerability_type"] for i in issues):
                    issues.append(ast_issue)

        except SyntaxError:
            pass
        except Exception as e:
            print(f"AST Parsing Error in {file_path}: {e}")

    return issues


def scan_directory(directory_path: str) -> list:
    all_issues = []

    for root, dirs, files in os.walk(directory_path):
        # EXCLUDED_DIRS ထဲပါဝင်သော Frontend/Node_modules/Git စသည့် folder များကို Scan မဖတ်ပါ
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            ext = os.path.splitext(file)[1].lower()

            # SUPPORTED_EXTENSIONS ထဲ ပါဝင်သော File များကိုသာ စစ်ဆေးပါမည်
            if ext not in SUPPORTED_EXTENSIONS:
                continue

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