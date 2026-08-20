
@app.post("/scan/url")
def scan_url_endpoint(payload: URLScanRequest):
    try:
        result = extract_url_features(payload.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL Feature Extraction Failed: {str(e)}")


# 🌐 LIVE WEB SECURITY AUDIT ENDPOINT
@app.post("/scan/web-audit")
def audit_web_security(payload: WebAuditRequest):
    target_url = payload.url.strip()

    # 🟢 Scheme မပါပါက https:// ကို Default တင်ပေးပါမည်။
    # သို့သော် http:// ပါပြီးသားဖြစ်ပါက http:// အတိုင်း ဆက်သွားပါမည်။
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # 🟢 GitHub Link ဖြစ်ပါက စစ်ဆေးမှု မလုပ်ဘဲ အသိပေးချက် ပြန်ထုတ်ပေးခြင်း
    if "github.com" in target_url.lower():
        return {
            "target_url": target_url,
            "status_code": 200,
            "security_score": 0,
            "security_grade": "N/A",
            "risk_score": "Invalid Target",
            "executive_summary": "GitHub URL သည် Source Code Repository ဖြစ်ပြီး Live Application မဟုတ်ပါ။ Source Code Vulnerability စစ်ဆေးရန် 'Git Repository' Tab ကို သုံးပါ။",
            "server_info": "GitHub Repository",
            "security_cards": {
                "encryption": "N/A",
                "script_protection": "N/A",
                "clickjacking_defense": "N/A",
                "strict_https": "N/A"
            },
            "recommendations": [
                {
                    "issue": "GitHub Link Provided in Web Audit",
                    "severity": "HIGH",
                    "impact": "Web Audit သည် Live Application ၏ Security Header/Cookie Configuration များကိုသာ စစ်ဆေးပါသည်။",
                    "remediation": "Live Website URL ကို ထည့်သွင်းပါ သို့မဟုတ် Git Repository Tab တွင် စစ်ဆေးပါ။"
                }
            ]
        }

    try:
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # 🟢 verify=False ထည့်ထားသဖြင့် SSL Certificate မပြည့်စုံသော သို့မဟုတ် HTTP သီးသန့် Site များတွင် SSL Error မတက်တော့ပါ။
        response = requests.get(target_url, headers=req_headers, timeout=10, allow_redirects=True, verify=False)
        headers = response.headers
        html_content = response.text.lower()

        is_ssl = target_url.startswith("https://")
        csp = headers.get("Content-Security-Policy", "Missing")
        csp_report_only = headers.get("Content-Security-Policy-Report-Only", "Missing")
        cors = headers.get("Access-Control-Allow-Origin", "Not Specified")
        x_frame = headers.get("X-Frame-Options", "Missing")
        hsts = headers.get("Strict-Transport-Security", "Missing")
        server_info = headers.get("Server", "Hidden")
        x_powered_by = headers.get("X-Powered-By", None)

        has_meta_csp = "content-security-policy" in html_content or csp_report_only != "Missing"

        domain_name = target_url.lower().replace("https://", "").replace("http://", "").split("/")[0]
        hsts_preloaded_domains = ["google.com", "youtube.com", "facebook.com", "gmail.com"]
        is_hsts_preloaded = any(domain_name == d or domain_name.endswith("." + d) for d in hsts_preloaded_domains)

        score = 100
        recommendations = []

        if not is_ssl:
            score -= 40
            recommendations.append({
                "issue": "Missing SSL/TLS Encryption",
                "severity": "CRITICAL",
                "impact": "ဒေတာများ လမ်းခုလတ်တွင် Encrypt မလုပ်ဘဲ ဖြတ်သန်းသွားသဖြင့် ကြည့်ရှုခံရနိုင်သည့် အန္တရာယ်ရှိပါသည်။",
                "remediation": "HTTPS Certificate စနစ်တကျ တပ်ဆင်ပါ။"
            })

        if csp == "Missing" and not has_meta_csp:
            score -= 15
            recommendations.append({
                "issue": "Missing Content Security Policy (CSP)",
                "severity": "MEDIUM",
                "impact": "XSS Script အန္တရာယ်များကို တားဆီးရန် Response Header သို့မဟုတ် HTML Meta Tag တွင် CSP မပါဝင်ပါ။",
                "remediation": "HTTP Response Header တွင် Content-Security-Policy ထည့်သွင်းပေးပါ။"
            })
        elif csp == "Missing" and has_meta_csp:
            recommendations.append({
                "issue": "CSP Enforced via HTML Meta Tag",
                "severity": "INFO",
                "impact": "Response Header တွင် CSP မပါသော်လည်း HTML Meta Tag အဆင့်တွင် ကာကွယ်ထားသည်ကို တွေ့ရှိရပါသည်။",
                "remediation": "Best Practice အနေဖြင့် Response Header တွင်ပါ ထည့်သွင်းရန် အကြံပြုပါသည်။"
            })

        if x_frame == "Missing":
            score -= 15
            recommendations.append({
                "issue": "Missing X-Frame-Options Header",
                "severity": "MEDIUM",
                "impact": "Clickjacking အန္တရာယ်မှ ကာကွယ်ရန် Frame Control Header လိုအပ်နေပါသည်။",
                "remediation": "Header တွင် 'X-Frame-Options: SAMEORIGIN' ထည့်သွင်းပါ။"
            })

        if cors == "*":
            score -= 20
            recommendations.append({
                "issue": "Overly Permissive CORS Policy",
                "severity": "HIGH",
                "impact": "မည်သည့် Domain မှမဆို API Resources များကို လှမ်းယူခွင့် ပေးထားပါသည်။",
                "remediation": "CORS Wildcard '*' ကို ပိတ်ပြီး သီးသန့် Domain သာ ခွင့်ပြုပါ။"
            })

        raw_cookies = response.raw.headers.getlist('Set-Cookie') if hasattr(response.raw, 'headers') else []
        if not raw_cookies and 'set-cookie' in headers:
            raw_cookies = [headers['set-cookie']]

        if raw_cookies:
            missing_http_only = False
            missing_secure = False
            missing_samesite = False

            for cookie_str in raw_cookies:
                c_lower = cookie_str.lower()
                if "httponly" not in c_lower:
                    missing_http_only = True
                if "secure" not in c_lower and is_ssl:
                    missing_secure = True
                if "samesite" not in c_lower:
                    missing_samesite = True

            if missing_http_only:
                score -= 10
                recommendations.append({
                    "issue": "Cookie Missing 'HttpOnly' Flag",
                    "severity": "MEDIUM",
                    "impact": "Client-side Script (XSS) ဖြင့် Session Cookie များကို လှမ်းယူဖတ်ရှုနိုင်ခြေ ရှိပါသည်။",
                    "remediation": "Set-Cookie Header တွင် 'HttpOnly' Flag ပါဝင်အောင် သတ်မှတ်ပါ။"
                })

            if missing_secure:
                score -= 10
                recommendations.append({
                    "issue": "Cookie Missing 'Secure' Flag",
                    "severity": "MEDIUM",
                    "impact": "Cookie များကို Unencrypted HTTP Connection များမှတစ်ဆင့် ပေးပို့မိနိုင်ခြေ ရှိပါသည်။",
                    "remediation": "Set-Cookie Header တွင် 'Secure' Flag ထည့်သွင်းပါ။"
                })

            if missing_samesite:
                score -= 5
                recommendations.append({
                    "issue": "Cookie Missing 'SameSite' Attribute",
                    "severity": "LOW",
                    "impact": "Cross-Site Request Forgery (CSRF) အန္တရာယ်များမှ ကာကွယ်နိုင်စွမ်း လျော့နည်းနိုင်ပါသည်။",
                    "remediation": "Cookie များတွင် 'SameSite=Lax' သို့မဟုတ် 'SameSite=Strict' ထည့်သွင်းပါ။"
                })

        if x_powered_by:
            score -= 5
            recommendations.append({
                "issue": "Information Disclosure (X-Powered-By Header)",
                "severity": "LOW",
                "impact": "အသုံးပြုထားသော Backend Technology/Framework အသေးစိတ်ကို ပြသနေပါသည်။",
                "remediation": "Server Configuration တွင် 'X-Powered-By' Header ကို ဖျောက်ထားပါ။"
            })

        if server_info != "Hidden" and any(char.isdigit() for char in server_info):
            score -= 5
            recommendations.append({
                "issue": "Server Version Disclosure",
                "severity": "LOW",
                "impact": "Web Server ၏ သီးသန့် Version အချက်အလက်များ တိုက်ရိုက် ပေါ်နေပါသည်။",
                "remediation": "Server Banner / Tokens များကို ဖျောက်ထားပါ။"
            })

        if hsts == "Missing" and is_ssl and not is_hsts_preloaded:
            score -= 10
            recommendations.append({
                "issue": "Missing HSTS Header (Strict HTTPS)",
                "severity": "LOW",
                "impact": "HTTP မှ HTTPS သို့ ပထမဆုံး ချိတ်ဆက်ချိန်တွင် Security Downgrade ဖြစ်နိုင်ခြေ ရှိပါသည်။",
                "remediation": "'Strict-Transport-Security: max-age=31536000' ကို ထည့်သွင်းပါ။"
            })

        # 🟢 ADDITIONAL SECURITY HEADER CHECKS
        x_content_type = headers.get("X-Content-Type-Options", "Missing")
        referrer_policy = headers.get("Referrer-Policy", "Missing")

        if x_content_type.lower() != "nosniff":
            score -= 5
            recommendations.append({
                "issue": "Missing X-Content-Type-Options Header",
                "severity": "LOW",
                "impact": "Browser များမှ MIME Sniffing လုပ်ပြီး Script မဟုတ်သော File များကို Script အဖြစ် Execute လုပ်သွားနိုင်သည့် အန္တရာယ်ရှိပါသည်။",
                "remediation": "HTTP Response Header တွင် 'X-Content-Type-Options: nosniff' ထည့်သွင်းပါ။"
            })

        if referrer_policy == "Missing":
            score -= 5
            recommendations.append({
                "issue": "Missing Referrer-Policy Header",
                "severity": "LOW",
                "impact": "User မည်သည့် Page မှ လာသည်ဆိုသော အချက်အလက် (Referrer) အပြင်ဘက်သို့ ယိုစိမ့်နိုင်ပါသည်။",
                "remediation": "Header တွင် 'Referrer-Policy: strict-origin-when-cross-origin' သတ်မှတ်ပေးပါ။"
            })

        score = max(0, score)

        if score >= 90:
            security_grade = "A+"
            risk_score = "Excellent (Secured)"
            executive_summary = "ယခု Website သည် လုံခြုံရေးဆိုင်ရာ Headers နှင့် Cookie Security Configurations များကို ကောင်းမွန်စွာ လိုက်နာထားပါသည်။"
        elif score >= 75:
            security_grade = "B"
            risk_score = "Good (Low Risk)"
            executive_summary = "အခြေခံလုံခြုံရေး ကောင်းမွန်သော်လည်း အချို့သော Cookie Flags သို့မဟုတ် Best Practice Header များ ထည့်သွင်းရန် အကြံပြုပါသည်။"
        elif score >= 50:
            security_grade = "C"
            risk_score = "Moderate Risk"
            executive_summary = "သတိပြုရန် Security Control အချို့ မရှိခြင်းနှင့် Information Disclosure များ ရှိနေပါသဖြင့် ပြင်ဆင်ရန် အကြံပြုပါသည်။"
        else:
            security_grade = "F"
            risk_score = "High Risk"
            executive_summary = "အရေးကြီး Security Control များ မရှိပါသဖြင့် အမြန်ဆုံး ပြင်ဆင်ရန် လိုအပ်ပါသည်။"

        script_prot_status = "Active (CSP Header)" if csp != "Missing" else (
            "Active (HTML Meta Tag)" if has_meta_csp else "Not Found")
        strict_https_status = "Active (HSTS Enforced)" if hsts != "Missing" else (
            "Active (HSTS Preloaded)" if is_hsts_preloaded else "Not Enforced")

        return {
            "target_url": target_url,
            "status_code": response.status_code,
            "security_score": score,
            "security_grade": security_grade,
            "risk_score": risk_score,
            "executive_summary": executive_summary,
            "server_info": server_info,
            "security_cards": {
                "encryption": "Valid (HTTPS Standard)" if is_ssl else "Insecure (HTTP Only)",
                "script_protection": script_prot_status,
                "clickjacking_defense": f"Active ({x_frame})" if x_frame != "Missing" else "Not Configured",
                "strict_https": strict_https_status
            },
            "recommendations": recommendations
        }

    except requests.exceptions.RequestException as e:
        # 🟢 HTTP 400 raise မလုပ်တော့ဘဲ Frontend UI သို့ Error Result အဖြစ် လှပစွာ ပြသနိုင်ရန် JSON ပြန်ထုတ်ပေးခြင်း
        return {
            "target_url": target_url,
            "status_code": 400,
            "security_score": 0,
            "security_grade": "F",
            "risk_score": "Unreachable Target",
            "executive_summary": f"Target URL သို့ ချိတ်ဆက်၍ မရပါ (Connection Error သို့မဟုတ် Invalid Domain ဖြစ်နိုင်ပါသည်) - {str(e)}",
            "server_info": "Unknown",
            "security_cards": {
                "encryption": "Insecure / Failed",
                "script_protection": "Not Found",
                "clickjacking_defense": "Not Configured",
                "strict_https": "Not Enforced"
            },
            "recommendations": [
                {
                    "issue": "Failed to Reach Target Domain",
                    "severity": "CRITICAL",
                    "impact": "စစ်ဆေးလိုသော URL သည် မရှိပါ သို့မဟုတ် Server ပိတ်ထားပါသည် (သို့မဟုတ် Firewall မှ Block ထားပါသည်)။",
                    "remediation": "Domain အမည်နှင့် Protocol (http/https) မှန်ကန်မှု ရှိမရှိ စစ်ဆေးပါ။"
                }
            ]
        }