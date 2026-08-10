from app.scanner.ast_engine import scan_code_string

# စမ်းသပ်ရန် Vulnerability ပါသော Python Code Snippet
vulnerable_code = """
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
db_password = "SuperSecretPassword123"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(query)
"""

# Scan ဖတ်ခြင်း
results = scan_code_string(vulnerable_code)

# ရလဒ် ထုတ်ပြခြင်း
print("--- Scan Results ---")
for issue in results:
    print(f"[{issue['severity']}] Line {issue['line_number']}: {issue['type']}")
    print(f"Suggestion: {issue['suggestion']}\n")