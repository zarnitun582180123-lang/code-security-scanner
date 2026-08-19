import os
import re
from app.scanner.ast_engine import scan_code_string

# Ground Truth Dataset: သိရှိပြီးသား Vulnerable Code များနှင့် Safe Code များ
BENCHMARK_DATASET = [
    {
        "id": "BM01",
        "name": "Hardcoded AWS Access Key",
        "code": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nprint('Connected')",
        "expected_has_vulnerability": True,
        "expected_type": "HARDCODED_AWS_KEY"
    },
    {
        "id": "BM02",
        "name": "Hardcoded Secret Key",
        "code": "SECRET_KEY = 'my_super_secret_key_123'\napp.config['SECRET_KEY'] = SECRET_KEY",
        "expected_has_vulnerability": True,
        "expected_type": "HARDCODED_SECRET"
    },
    {
        "id": "BM03",
        "name": "Safe Environment Variable Use",
        "code": "import os\nSECRET_KEY = os.getenv('SECRET_KEY')\nprint(SECRET_KEY)",
        "expected_has_vulnerability": False,
        "expected_type": None
    },
    {
        "id": "BM04",
        "name": "Dangerous Eval Injection",
        "code": "user_input = input()\nresult = eval(user_input)",
        "expected_has_vulnerability": True,
        "expected_type": "DANGEROUS_EVAL_EXEC"
    },
    {
        "id": "BM05",
        "name": "Safe Subprocess Command",
        "code": "import subprocess\nsubprocess.run(['ls', '-l'], check=True)",
        "expected_has_vulnerability": False,
        "expected_type": None
    },
    {
        "id": "BM06",
        "name": "OS System Command Injection",
        "code": "import os\ncmd = 'ls ' + input_arg\nos.system(cmd)",
        "expected_has_vulnerability": True,
        "expected_type": "OS_SYSTEM_COMMAND_INJECTION"
    }
]

def evaluate_model_metrics():
    """
    Ground Truth Dataset ဖြင့် AST Scanner ၏ Accuracy, Precision, Recall, F1-Score ကို တွက်ချက်သည်။
    """
    tp = 0  # True Positive: Vulnerability ရှိတာကို Scanner က မှန်အောင်မိတယ်
    fp = 0  # False Positive: Safe Code ကို Scanner က Vulnerability ပါတယ်လို့ မှားပြတယ်
    tn = 0  # True Negative: Safe Code ကို Scanner က Safe အဖြစ် မှန်မှန်ကန်ကန် သတ်မှတ်တယ်
    fn = 0  # False Negative: Vulnerability ပါတာကို Scanner က မမိဘဲ လွတ်သွားတယ်

    detailed_results = []

    for item in BENCHMARK_DATASET:
        detected_issues = scan_code_string(item["code"], file_path=item["id"])
        detected_has_vuln = len(detected_issues) > 0

        actual = item["expected_has_vulnerability"]
        predicted = detected_has_vuln

        status = ""
        if actual and predicted:
            tp += 1
            status = "TP (True Positive)"
        elif not actual and predicted:
            fp += 1
            status = "FP (False Positive)"
        elif not actual and not predicted:
            tn += 1
            status = "TN (True Negative)"
        elif actual and not predicted:
            fn += 1
            status = "FN (False Negative)"

        detailed_results.append({
            "id": item["id"],
            "name": item["name"],
            "expected": actual,
            "detected": predicted,
            "status": status,
            "detected_issues_count": len(detected_issues)
        })

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "confusion_matrix": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "total_samples": total
        },
        "metrics": {
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1_score * 100, 2)
        },
        "benchmark_details": detailed_results
    }