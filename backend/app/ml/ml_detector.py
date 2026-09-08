import os
import joblib


# ============================================================
# ISVS ML DETECTOR
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "support_vector_machine_isvs_model.pkl"
)

_model = None


def load_model():
    global _model

    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"ISVS ML model not found: {MODEL_PATH}"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


# ============================================================
# CWE KNOWLEDGE
# ============================================================

CWE_RULES = [
    {
        "keywords": [
            "os.system(",
            "subprocess.call(",
            "subprocess.run(",
            "subprocess.Popen("
        ],
        "cwe": "CWE-78",
        "name": "OS Command Injection",
        "risk": "HIGH",
        "recommendation":
            "Avoid passing untrusted user input directly to operating-system "
            "commands. Use safe subprocess APIs with argument lists and validate input."
    },

    {
        "keywords": [
            "eval(",
            "exec("
        ],
        "cwe": "CWE-95",
        "name": "Improper Control of Generation of Code",
        "risk": "CRITICAL",
        "recommendation":
            "Avoid eval() and exec() on untrusted input. Use safer parsing "
            "methods such as ast.literal_eval() when appropriate."
    },

    {
        "keywords": [
            "yaml.load("
        ],
        "cwe": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "risk": "HIGH",
        "recommendation":
            "Use safe YAML loading such as yaml.safe_load() for untrusted data."
    },

    {
        "keywords": [
            "pickle.loads(",
            "pickle.load("
        ],
        "cwe": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "risk": "HIGH",
        "recommendation":
            "Do not deserialize untrusted data with pickle. Use a safe "
            "serialization format and validate input."
    },

    {
        "keywords": [
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE "
        ],
        "cwe": "CWE-89",
        "name": "SQL Injection",
        "risk": "HIGH",
        "recommendation":
            "Use parameterized queries or ORM query parameters instead of "
            "building SQL statements from untrusted input."
    },

    {
        "keywords": [
            "requests.get(",
            "requests.post("
        ],
        "cwe": "CWE-918",
        "name": "Server-Side Request Forgery",
        "risk": "HIGH",
        "recommendation":
            "Validate and restrict user-controlled URLs. Use an allowlist "
            "and block internal or private network destinations."
    }
]


def detect_cwe(code):
    code_lower = code.lower()

    for rule in CWE_RULES:
        for keyword in rule["keywords"]:
            if keyword.lower() in code_lower:
                return rule

    return {
        "cwe": "ML-DETECTED",
        "name": "Machine Learning Detected Vulnerability",
        "risk": "MEDIUM",
        "recommendation":
            "Review this source code using the complete ISVS AST and "
            "rule-based security scanner."
    }


# ============================================================
# PREDICTION
# ============================================================

def predict_vulnerability(code: str):

    if not code or not code.strip():
        raise ValueError("Source code cannot be empty.")

    model = load_model()

    prediction = int(model.predict([code])[0])

    confidence = None

    try:
        score = float(model.decision_function([code])[0])

        # Presentation-only confidence score.
        confidence = 1 / (1 + abs(score))
        confidence = round(confidence * 100, 2)

    except Exception:
        confidence = None

    if prediction == 1:

        cwe = detect_cwe(code)

        return {
            "prediction": "VULNERABLE",
            "label": 1,
            "vulnerability": cwe["name"],
            "cwe": cwe["cwe"],
            "risk_level": cwe["risk"],
            "confidence": confidence,
            "recommendation": cwe["recommendation"],
            "model": "Support Vector Machine"
        }

    return {
        "prediction": "SAFE",
        "label": 0,
        "vulnerability": "No vulnerability detected by ML model",
        "cwe": "N/A",
        "risk_level": "LOW",
        "confidence": confidence,
        "recommendation":
            "No vulnerability was detected by the ML classifier. "
            "Run the complete ISVS AST/rule-based scanner for additional verification.",
        "model": "Support Vector Machine"
    }