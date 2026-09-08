
import os
import re
from app.scanner.ast_engine import scan_code_string


# ============================================================
# ISVS BENCHMARK DATASET
# Ground Truth Dataset
# ============================================================
#
# expected_has_vulnerability:
#     True  = Vulnerable Code
#     False = Safe Code
#
# expected_type:
#     Expected vulnerability type
#
# This dataset is used to evaluate the ISVS AST / Rule-Based
# Security Scanner using standard classification metrics.
# ============================================================

BENCHMARK_DATASET = [

    # --------------------------------------------------------
    # BM01 - Hardcoded AWS Access Key
    # --------------------------------------------------------
    {
        "id": "BM01",
        "name": "Hardcoded AWS Access Key",
        "code": (
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
            "print('Connected')"
        ),
        "expected_has_vulnerability": True,
        "expected_type": "HARDCODED_AWS_KEY"
    },

    # --------------------------------------------------------
    # BM02 - Hardcoded Secret
    # --------------------------------------------------------
    {
        "id": "BM02",
        "name": "Hardcoded Secret Key",
        "code": (
            "SECRET_KEY = 'my_super_secret_key_123'\n"
            "app.config['SECRET_KEY'] = SECRET_KEY"
        ),
        "expected_has_vulnerability": True,
        "expected_type": "HARDCODED_SECRET"
    },

    # --------------------------------------------------------
    # BM03 - Safe Environment Variable
    # --------------------------------------------------------
    {
        "id": "BM03",
        "name": "Safe Environment Variable Use",
        "code": (
            "import os\n"
            "SECRET_KEY = os.getenv('SECRET_KEY')\n"
            "print(SECRET_KEY)"
        ),
        "expected_has_vulnerability": False,
        "expected_type": None
    },

    # --------------------------------------------------------
    # BM04 - Dangerous Eval Injection
    # --------------------------------------------------------
    {
        "id": "BM04",
        "name": "Dangerous Eval Injection",
        "code": (
            "user_input = input()\n"
            "result = eval(user_input)"
        ),
        "expected_has_vulnerability": True,
        "expected_type": "DANGEROUS_EVAL_EXEC"
    },

    # --------------------------------------------------------
    # BM05 - Safe Subprocess Command
    # --------------------------------------------------------
    {
        "id": "BM05",
        "name": "Safe Subprocess Command",
        "code": (
            "import subprocess\n"
            "subprocess.run(['ls', '-l'], check=True)"
        ),
        "expected_has_vulnerability": False,
        "expected_type": None
    },

    # --------------------------------------------------------
    # BM06 - OS System Command Injection
    # --------------------------------------------------------
    {
        "id": "BM06",
        "name": "OS System Command Injection",
        "code": (
            "import os\n"
            "cmd = 'ls ' + input_arg\n"
            "os.system(cmd)"
        ),
        "expected_has_vulnerability": True,
        "expected_type": "OS_SYSTEM_COMMAND_INJECTION"
    },
]


# ============================================================
# METRIC CALCULATION HELPERS
# ============================================================

def calculate_accuracy(tp, fp, tn, fn):
    """
    Accuracy:
        (TP + TN) / Total
    """
    total = tp + fp + tn + fn

    if total == 0:
        return 0.0

    return (tp + tn) / total


def calculate_precision(tp, fp):
    """
    Precision:
        TP / (TP + FP)

    Measures how many detected vulnerabilities
    were actually vulnerabilities.
    """
    denominator = tp + fp

    if denominator == 0:
        return 0.0

    return tp / denominator


def calculate_recall(tp, fn):
    """
    Recall:
        TP / (TP + FN)

    Measures how many actual vulnerabilities
    were successfully detected.
    """
    denominator = tp + fn

    if denominator == 0:
        return 0.0

    return tp / denominator


def calculate_f1(precision, recall):
    """
    F1 Score:
        2 * (Precision * Recall) /
        (Precision + Recall)
    """
    denominator = precision + recall

    if denominator == 0:
        return 0.0

    return 2 * (precision * recall) / denominator


def calculate_sensitivity(tp, fn):
    """
    Sensitivity is equivalent to Recall.

        Sensitivity = TP / (TP + FN)
    """
    denominator = tp + fn

    if denominator == 0:
        return 0.0

    return tp / denominator


def calculate_specificity(tn, fp):
    """
    Specificity:
        TN / (TN + FP)

    Measures how well the scanner correctly
    identifies safe code.
    """
    denominator = tn + fp

    if denominator == 0:
        return 0.0

    return tn / denominator


# ============================================================
# MAIN BENCHMARK EVALUATION
# ============================================================

def evaluate_model_metrics():
    """
    Evaluate the ISVS AST / Rule-Based Security Scanner
    against the Ground Truth Benchmark Dataset.

    Returns:
        - Confusion Matrix
        - Accuracy
        - Precision
        - Recall
        - F1 Score
        - Sensitivity
        - Specificity
        - Benchmark details
    """

    # --------------------------------------------------------
    # Confusion Matrix Counters
    # --------------------------------------------------------

    tp = 0  # True Positive
    fp = 0  # False Positive
    tn = 0  # True Negative
    fn = 0  # False Negative

    detailed_results = []


    # ========================================================
    # RUN SCANNER AGAINST EVERY DATASET SAMPLE
    # ========================================================

    for item in BENCHMARK_DATASET:

        try:
            # Run the existing ISVS AST / Rule-Based Scanner
            detected_issues = scan_code_string(
                item["code"],
                file_path=item["id"]
            )

        except Exception as exc:
            # If scanner fails on a sample, treat it as
            # a detection failure instead of crashing
            # the entire benchmark.

            detected_issues = []

            detailed_results.append({
                "id": item["id"],
                "name": item["name"],
                "expected": item["expected_has_vulnerability"],
                "detected": False,
                "status": "SCAN_ERROR",
                "detected_issues_count": 0,
                "error": str(exc)
            })

            # A scanner error on a vulnerable sample
            # is considered a False Negative.
            if item["expected_has_vulnerability"]:
                fn += 1
            else:
                tn += 1

            continue


        # ----------------------------------------------------
        # Convert scanner result into binary classification
        # ----------------------------------------------------

        detected_has_vulnerability = len(detected_issues) > 0

        actual = item["expected_has_vulnerability"]
        predicted = detected_has_vulnerability


        # ----------------------------------------------------
        # Determine Confusion Matrix Category
        # ----------------------------------------------------

        if actual and predicted:

            # Vulnerable code correctly detected
            tp += 1
            status = "TP (True Positive)"

        elif not actual and predicted:

            # Safe code incorrectly flagged
            fp += 1
            status = "FP (False Positive)"

        elif not actual and not predicted:

            # Safe code correctly identified
            tn += 1
            status = "TN (True Negative)"

        else:

            # Vulnerable code missed by scanner
            fn += 1
            status = "FN (False Negative)"


        # ----------------------------------------------------
        # Extract detected vulnerability types
        # ----------------------------------------------------

        detected_types = []

        for issue in detected_issues:

            if isinstance(issue, dict):

                issue_type = (
                    issue.get("type")
                    or issue.get("vulnerability_type")
                    or issue.get("rule")
                    or issue.get("name")
                )

                if issue_type:
                    detected_types.append(str(issue_type))

            else:
                detected_types.append(str(issue))


        # ----------------------------------------------------
        # Save detailed benchmark result
        # ----------------------------------------------------

        detailed_results.append({
            "id": item["id"],
            "name": item["name"],
            "expected": actual,
            "expected_type": item["expected_type"],
            "detected": predicted,
            "detected_types": detected_types,
            "status": status,
            "detected_issues_count": len(detected_issues)
        })


    # ========================================================
    # TOTAL SAMPLES
    # ========================================================

    total = tp + fp + tn + fn


    # ========================================================
    # CALCULATE METRICS
    # ========================================================

    accuracy = calculate_accuracy(
        tp,
        fp,
        tn,
        fn
    )

    precision = calculate_precision(
        tp,
        fp
    )

    recall = calculate_recall(
        tp,
        fn
    )

    f1_score = calculate_f1(
        precision,
        recall
    )

    sensitivity = calculate_sensitivity(
        tp,
        fn
    )

    specificity = calculate_specificity(
        tn,
        fp
    )


    # ========================================================
    # RETURN COMPLETE BENCHMARK REPORT
    # ========================================================

    return {

        # ----------------------------------------------------
        # Dataset Information
        # ----------------------------------------------------

        "dataset": {
            "name": "ISVS Ground Truth Benchmark Dataset",
            "total_samples": total,
            "vulnerable_samples": tp + fn,
            "safe_samples": tn + fp
        },


        # ----------------------------------------------------
        # Algorithm Information
        # ----------------------------------------------------

        "algorithm": {
            "name": "AST-Based Rule Classification",
            "type": "Static Application Security Testing (SAST)",
            "engine": "ISVS AST / Rule-Based Scanner"
        },


        # ----------------------------------------------------
        # Confusion Matrix
        # ----------------------------------------------------

        "confusion_matrix": {

            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,

            "total_samples": total
        },


        # ----------------------------------------------------
        # Classification Metrics
        # Values are returned as percentages.
        # ----------------------------------------------------

        "metrics": {

            "accuracy": round(
                accuracy * 100,
                2
            ),

            "precision": round(
                precision * 100,
                2
            ),

            "recall": round(
                recall * 100,
                2
            ),

            "f1_score": round(
                f1_score * 100,
                2
            ),

            "sensitivity": round(
                sensitivity * 100,
                2
            ),

            "specificity": round(
                specificity * 100,
                2
            )
        },


        # ----------------------------------------------------
        # Raw Metric Values
        # Useful for charts / visualization
        # ----------------------------------------------------

        "raw_metrics": {

            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "sensitivity": sensitivity,
            "specificity": specificity
        },


        # ----------------------------------------------------
        # Benchmark Sample-by-Sample Results
        # ----------------------------------------------------

        "benchmark_details": detailed_results
    }


# ============================================================
# OPTIONAL CONSOLE TEST
# ============================================================
#
# Run:
#
#     python metrics_engine.py
#
# to see the benchmark metrics directly in PowerShell.
# ============================================================

if __name__ == "__main__":

    results = evaluate_model_metrics()

    print("\n" + "=" * 60)
    print("ISVS SECURITY SCANNER BENCHMARK")
    print("=" * 60)

    print("\nDataset:")
    print(
        f"  Total Samples     : "
        f"{results['dataset']['total_samples']}"
    )

    print(
        f"  Vulnerable Samples: "
        f"{results['dataset']['vulnerable_samples']}"
    )

    print(
        f"  Safe Samples      : "
        f"{results['dataset']['safe_samples']}"
    )


    print("\nAlgorithm:")
    print(
        f"  {results['algorithm']['name']}"
    )


    print("\nConfusion Matrix:")
    print(
        f"  TP: {results['confusion_matrix']['tp']}"
    )

    print(
        f"  FP: {results['confusion_matrix']['fp']}"
    )

    print(
        f"  TN: {results['confusion_matrix']['tn']}"
    )

    print(
        f"  FN: {results['confusion_matrix']['fn']}"
    )


    print("\nClassification Metrics:")

    metrics = results["metrics"]

    print(
        f"  Accuracy    : {metrics['accuracy']}%"
    )

    print(
        f"  Precision   : {metrics['precision']}%"
    )

    print(
        f"  Recall      : {metrics['recall']}%"
    )

    print(
        f"  F1 Score    : {metrics['f1_score']}%"
    )

    print(
        f"  Sensitivity : {metrics['sensitivity']}%"
    )

    print(
        f"  Specificity : {metrics['specificity']}%"
    )


    print("\nBenchmark Details:")

    for result in results["benchmark_details"]:

        print(
            f"  {result['id']} | "
            f"{result['status']} | "
            f"Detected Issues: "
            f"{result['detected_issues_count']}"
        )


    print("\n" + "=" * 60)

