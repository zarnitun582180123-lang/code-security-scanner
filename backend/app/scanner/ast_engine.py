import ast
import os
import re


# ==========================================
# 1. AST VISITOR FOR PYTHON CODE ANALYSIS
# ==========================================
class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.issues = []

    def visit_Call(self, node):
        # eval() သို့မဟုတ် exec() ခေါ်ယူထားခြင်းကို စစ်ဆေးခြင်း (RCE Risk)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ['eval', 'exec']:
                self.issues.append({
                    "file_path": self.file_path,
                    "line_number": node.lineno,
                    "type": "DANGEROUS_CODE_EXECUTION",
                    "severity": "HIGH",
                    "suggestion": f"Avoid using {func_name}(). It poses severe security risks."
                })
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Variable name ထဲတွင် Secret / Password ပါပြီး String ဖြစ်နေပါက Hardcoded Secret အဖြစ် သတ်မှတ်ခြင်း
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(key in var_name for key in ['secret', 'password', 'token', 'api_key', 'private_key']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value.strip()) > 0:
                            self.issues.append({
                                "file_path": self.file_path,
                                "line_number": node.lineno,
                                "type": "HARDCODED_SECRET",
                                "severity": "CRITICAL",
                                "suggestion": "Do not hardcode secrets. Use environment variables (e.g., os.getenv()) instead."
                            })
        self.generic_visit(node)


# ==========================================
# 2. REGEX ENGINE FOR MULTI-LANGUAGE SCAN
# ==========================================
def scan_with_regex(file_path, content):
    issues = []

    # Updated Patterns: Quotes ပါတာရော၊ မပါတာပါ (.env / API Keys / Database URLs) အကုန်မိအောင် ပြင်ထားသည်
    patterns = [
        # Code Execution & Command Injection
        (r'eval\s*\(', "CRITICAL", "DANGEROUS_CODE_EXECUTION",
         "Avoid using eval(). It allows arbitrary code execution."),
        (r'exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(', "HIGH", "COMMAND_INJECTION_RISK",
         "Avoid direct OS command execution functions like exec(), system(), or shell_exec()."),

        # Hardcoded Secrets & Secrets in .env / Code (Supports quoted & unquoted strings)
        (r'(?i)(database_url|aws_secret_access_key|stripe_secret_key|api[_-]?key|secret|password|db_pass)\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
         "CRITICAL", "HARDCODED_SECRET",
         "Do not hardcode secrets or credentials in code/files. Store them securely."),

        # SQL Injection
        (r'SELECT\s+.*\s+FROM\s+.*\$', "HIGH", "SQL_INJECTION_RISK",
         "Avoid direct variable interpolation in SQL queries. Use Prepared Statements.")
    ]

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        # Comment ရေးထားတဲ့ စာကြောင်းတွေကို ကျော်မယ်
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue

        for pattern, severity, issue_type, suggestion in patterns:
            if re.search(pattern, line):
                issues.append({
                    "file_path": file_path,
                    "line_number": line_num,
                    "type": issue_type,
                    "severity": severity,
                    "suggestion": suggestion
                })
                break  # စာကြောင်းတစ်ကြောင်းမှာ Issue တစ်ခုမိရင် နောက် Pattern ဆက်မစစ်တော့ဘဲ ကျော်မည်

    return issues


# ==========================================
# 3. SINGLE CODE STRING SCANNER (FOR MAIN.PY)
# ==========================================
def scan_code_string(code_string):
    """
    Direct code snippet ဖတ်ရန် function
    """
    all_issues = []

    # 1. AST နဲ့ အရင် စစ်ကြည့်မည် (Python Code ဖြစ်ခဲ့ရင်)
    try:
        tree = ast.parse(code_string)
        visitor = SecurityASTVisitor("snippet.py")
        visitor.visit(tree)
        all_issues.extend(visitor.issues)
    except Exception:
        pass  # Python Code မဟုတ်ရင် (PHP, .env, JS) AST ကို ကျော်သွားမည်

    # 2. Regex Engine ဖြင့် ထပ်မံ စစ်ဆေးမည်
    regex_issues = scan_with_regex("snippet.py", code_string)

    # 3. Duplicate Issue များကို ဖယ်ထုတ်ခြင်း (Line Number & Type တူရင် ခေါက်ထုတ်မည်)
    existing_keys = {(i["line_number"], i["type"]) for i in all_issues}
    for r in regex_issues:
        if (r["line_number"], r["type"]) not in existing_keys:
            all_issues.append(r)

    return all_issues


# ==========================================
# 4. MAIN DIRECTORY SCANNER FUNCTION
# ==========================================
def scan_directory(dir_path):
    all_issues = []

    ignore_dirs = [
        '.git', 'vendor', 'node_modules', '__pycache__',
        'dist', 'build', 'storage', 'public/uploads', 'assets', 'images'
    ]

    for root, dirs, files in os.walk(dir_path):
        if any(skip in root for skip in ignore_dirs):
            continue

        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, dir_path)

            if file.endswith('.py'):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        source_code = f.read()

                    # AST Visitor
                    tree = ast.parse(source_code, filename=rel_path)
                    visitor = SecurityASTVisitor(rel_path)
                    visitor.visit(tree)

                    # Regex Check
                    regex_issues = scan_with_regex(rel_path, source_code)

                    combined = visitor.issues.copy()
                    existing_keys = {(i["line_number"], i["type"]) for i in combined}
                    for r in regex_issues:
                        if (r["line_number"], r["type"]) not in existing_keys:
                            combined.append(r)

                    all_issues.extend(combined)
                except Exception:
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            source_code = f.read()
                        all_issues.extend(scan_with_regex(rel_path, source_code))
                    except Exception:
                        pass

            elif file.endswith(('.php', '.js', '.env', '.json', '.config')):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    file_issues = scan_with_regex(rel_path, content)
                    all_issues.extend(file_issues)
                except Exception as e:
                    print(f"Error reading {rel_path}: {e}")

    return all_issues