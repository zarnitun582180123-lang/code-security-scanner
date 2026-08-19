import re
import math
from urllib.parse import urlparse

# Phishing တွေမှာ အသုံးများတဲ့ Keywords များ
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'banking', 'secure',
    'signin', 'paypal', 'ebay', 'amazon', 'credential', 'wallet'
]

# URL Shorteners များ
KNOWN_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.re',
    'ow.ly', 'buff.ly', 'adf.ly', 'bit.do'
]


def calculate_entropy(text: str) -> float:
    """
    URL Entropy (Randomness) ကို တွက်ချက်သည်။
    Phishing/Malicious URL အများစုသည် Character Randomness မြင့်မားကြသည်။
    """
    if not text:
        return 0.0
    entropy = 0.0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy -= p_x * math.log(p_x, 2)
    return round(entropy, 2)


def extract_url_features(url: str) -> dict:
    """
    Data Science Lexical Feature Extraction Engine for URL Scan
    """
    raw_url = url.strip()

    # Git Repository URL ဖြစ်နေပါက သီးသန့် Flag သတ်မှတ်ပေးခြင်း
    is_git_repo = bool(re.search(r'github\.com\/[^\/]+\/[^\/]+', raw_url.lower()))
    if is_git_repo:
        return {
            "url": raw_url,
            "prediction": "GIT_REPOSITORY",
            "confidence_score": 100.0,
            "phishing_probability": 0.0,
            "is_git_repo": True,
            "suggestion": "Source Code Vulnerabilities (SAST) နှင့် API Keys များကို စစ်ဆေးရန် 'Git Repository' Tab သို့ သွားရောက် စစ်ဆေးပါ။",
            "features": {
                "has_ip_address": False,
                "url_length": len(raw_url),
                "num_subdomains": 0,
                "has_at_symbol": False,
                "hyphen_count": 0,
                "detected_keywords": [],
                "url_entropy": calculate_entropy(raw_url),
                "is_https": raw_url.lower().startswith('https://'),
                "is_shortened": False,
                "has_typosquatting": False,
                "has_double_slash_redirect": False
            }
        }

    if not raw_url.startswith(('http://', 'https://')):
        working_url = 'http://' + raw_url
    else:
        working_url = raw_url

    parsed = urlparse(working_url)
    domain = parsed.netloc
    path = parsed.path

    # Feature 1: Has IP Address instead of Domain
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    has_ip = bool(re.match(ip_pattern, domain))

    # Feature 2: URL Length Metrics
    url_length = len(working_url)
    is_long_url = url_length > 75

    # Feature 3: Suspicious Symbol Counts & Redirect
    has_at_symbol = '@' in working_url
    hyphen_count = domain.count('-')
    dot_count = domain.count('.')
    has_double_slash_redirect = '//' in path

    # Feature 4: Subdomain Count
    subdomains = domain.split('.')
    num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0

    # Feature 5: Phishing Keyword Matching
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in working_url.lower()]

    # Feature 6: Lexical Entropy
    url_entropy = calculate_entropy(working_url)

    # 🟢 Feature 7: HTTPS Check
    is_https = working_url.lower().startswith('https://')

    # 🟢 Feature 8: URL Shortener Check
    is_shortened = any(shortener in domain.lower() for shortener in KNOWN_SHORTENERS)

    # 🟢 Feature 9: Typosquatting / Character Substitution Check
    typosquatting_pattern = r'(paypa1|goog1e|micros0ft|facebo0k|app1e|paypaI|g00gle)'
    has_typosquatting = bool(re.search(typosquatting_pattern, working_url.lower()))

    # 📊 Data Science Scoring Heuristic Model (Confidence Score Calculation)
    risk_score = 0
    if has_ip: risk_score += 35
    if is_long_url: risk_score += 15
    if has_at_symbol: risk_score += 20
    if hyphen_count > 2: risk_score += 15
    if num_subdomains > 2: risk_score += 15
    if found_keywords: risk_score += len(found_keywords) * 10
    if url_entropy > 4.5: risk_score += 15

    # တိုးချဲ့ထားသော Feature သစ်များအတွက် Scoring ထည့်သွင်းခြင်း
    if not is_https: risk_score += 10
    if is_shortened: risk_score += 20
    if has_typosquatting: risk_score += 30
    if has_double_slash_redirect: risk_score += 15

    # Risk Level & Prediction Probabilities
    phishing_probability = min(risk_score, 99.9)
    if phishing_probability < 30:
        prediction = "SAFE (Legitimate)"
        confidence = round(100 - phishing_probability, 1)
    elif phishing_probability < 65:
        prediction = "SUSPICIOUS"
        confidence = round(phishing_probability, 1)
    else:
        prediction = "PHISHING (Malicious)"
        confidence = round(phishing_probability, 1)

    return {
        "url": raw_url,
        "prediction": prediction,
        "confidence_score": confidence,
        "phishing_probability": round(phishing_probability, 1),
        "is_git_repo": False,
        "features": {
            # မူလ Features အားလုံး (၁ ခုမှ မဖြုတ်ပါ)
            "has_ip_address": has_ip,
            "url_length": url_length,
            "num_subdomains": num_subdomains,
            "has_at_symbol": has_at_symbol,
            "hyphen_count": hyphen_count,
            "detected_keywords": found_keywords,
            "url_entropy": url_entropy,

            # 🟢 ဖြည့်စွက်ထားသော Features သစ်များ
            "is_https": is_https,
            "is_shortened": is_shortened,
            "has_typosquatting": has_typosquatting,
            "has_double_slash_redirect": has_double_slash_redirect
        }
    }