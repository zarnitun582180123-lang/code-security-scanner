from app.scanner.ast_engine import scan_code_string


def scan(code: str, file_path: str = "snippet"):
    return scan_code_string(code, file_path=file_path)


def vulnerability_types(results):
    return {issue["vulnerability_type"] for issue in results}


def test_hardcoded_aws_key():
    code = 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'

    results = scan(code)

    assert "HARDCODED_AWS_KEY" in vulnerability_types(results)


def test_hardcoded_secret():
    code = 'db_password = "SuperSecretPassword123"'

    results = scan(code)

    assert "HARDCODED_SECRET" in vulnerability_types(results)


def test_eval_is_detected():
    code = "result = eval(user_input)"

    results = scan(code)

    assert "DANGEROUS_EVAL_EXEC" in vulnerability_types(results)


def test_exec_is_detected():
    code = "exec(user_input)"

    results = scan(code)

    assert "DANGEROUS_EVAL_EXEC" in vulnerability_types(results)


def test_os_system_is_detected():
    code = 'os.system("whoami")'

    results = scan(code)

    assert "OS_SYSTEM_COMMAND_INJECTION" in vulnerability_types(results)


def test_php_sql_injection_pattern():
    code = 'mysqli_query($conn, $_GET["id"])'

    results = scan(code, "index.php")

    assert "PHP_SQL_INJECTION_RISK" in vulnerability_types(results)


def test_react_dangerous_inner_html():
    code = """
<div dangerouslySetInnerHTML={{ __html: userContent }} />
"""

    results = scan(code, "Component.jsx")

    assert "DANGEROUS_INNER_HTML_XSS" in vulnerability_types(results)


def test_insecure_http():
    code = 'url = "http://example.com/api"'

    results = scan(code)

    assert "INSECURE_HTTP_PROTOCOL" in vulnerability_types(results)


def test_issue_schema():
    code = 'password = "SuperSecretPassword123"'

    results = scan(code)

    assert results

    required_fields = {
        "severity",
        "vulnerability_type",
        "file_path",
        "line_number",
        "vulnerable_code",
        "secure_code",
        "suggestion",
    }

    for issue in results:
        assert required_fields.issubset(issue.keys())


def test_secure_code_has_no_findings():
    code = """
import os

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
SECRET_KEY = os.getenv("SECRET_KEY")

def hello():
    return "Hello SecureCode"
"""

    results = scan(code)

    assert results == []


# ============================================================
# Phase 2 Security Tests
# ============================================================

def test_python_sql_injection():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'

    results = scan(code)

    assert "PYTHON_SQL_INJECTION_RISK" in vulnerability_types(results)


def test_javascript_sql_injection():
    code = 'db.query(`SELECT * FROM users WHERE id = ${req.query.id}`)'

    results = scan(code, "server.js")

    assert "JAVASCRIPT_SQL_INJECTION_RISK" in vulnerability_types(results)


def test_node_command_injection():
    code = 'child_process.exec(userInput)'

    results = scan(code, "server.js")

    assert "NODE_COMMAND_INJECTION_RISK" in vulnerability_types(results)


def test_path_traversal():
    code = 'open("../secrets/config.txt")'

    results = scan(code)

    assert "PATH_TRAVERSAL_RISK" in vulnerability_types(results)


def test_md5_is_detected():
    code = "digest = hashlib.md5(data).hexdigest()"

    results = scan(code)

    assert "WEAK_HASH_MD5" in vulnerability_types(results)


def test_sha1_is_detected():
    code = "digest = hashlib.sha1(data).hexdigest()"

    results = scan(code)

    assert "WEAK_HASH_SHA1" in vulnerability_types(results)


def test_secure_sql_query_not_flagged():
    code = """
cursor.execute(
    "SELECT * FROM users WHERE id = ?",
    (user_id,)
)
"""

    results = scan(code)

    assert "PYTHON_SQL_INJECTION_RISK" not in vulnerability_types(results)


def test_sha256_not_flagged_as_weak_hash():
    code = "digest = hashlib.sha256(data).hexdigest()"

    results = scan(code)

    assert "WEAK_HASH_MD5" not in vulnerability_types(results)

    assert "WEAK_HASH_SHA1" not in vulnerability_types(results)

def test_ssrf_requests():
    code = "requests.get(req.query.url)"

    results = scan(code, "server.py")

    assert "SSRF_RISK" in vulnerability_types(results)


def test_ssrf_urllib():
    code = "urllib.request.urlopen(user_input)"

    results = scan(code, "server.py")

    assert "SSRF_RISK" in vulnerability_types(results)


def test_dom_xss_innerhtml():
    code = "element.innerHTML = userInput"

    results = scan(code, "app.js")

    assert "DOM_XSS_INNERHTML" in vulnerability_types(results)


def test_dom_xss_document_write():
    code = "document.write(userInput)"

    results = scan(code, "app.js")

    assert "DOM_XSS_INNERHTML" in vulnerability_types(results)


def test_pickle_deserialization():
    code = "data = pickle.loads(user_input)"

    results = scan(code)

    assert "INSECURE_DESERIALIZATION_PICKLE" in vulnerability_types(results)


def test_yaml_unsafe_load():
    code = "data = yaml.load(user_input)"

    results = scan(code)

    assert "INSECURE_YAML_DESERIALIZATION" in vulnerability_types(results)


def test_des_crypto():
    code = "cipher = DES.new(key)"

    results = scan(code)

    assert "WEAK_CRYPTO_DES" in vulnerability_types(results)


def test_rc4_crypto():
    code = "cipher = ARC4.new(key)"

    results = scan(code)

    assert "WEAK_CRYPTO_RC4" in vulnerability_types(results)


def test_github_token():
    code = 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"'

    results = scan(code)

    assert "HARDCODED_GITHUB_TOKEN" in vulnerability_types(results)


def test_jwt_secret():
    code = 'JWT_SECRET = "SuperLongJwtSecret12345"'

    results = scan(code)

    assert "HARDCODED_JWT_SECRET" in vulnerability_types(results)


def test_safe_yaml_not_flagged():
    code = "data = yaml.safe_load(user_input)"

    results = scan(code)

    assert "INSECURE_YAML_DESERIALIZATION" not in vulnerability_types(results)


def test_text_content_not_xss():
    code = "element.textContent = userInput"

    results = scan(code)

    assert "DOM_XSS_INNERHTML" not in vulnerability_types(results)