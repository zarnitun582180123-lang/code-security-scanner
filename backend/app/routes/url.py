# ============================================================
# 🌐 LIVE WEB SECURITY AUDIT
# ============================================================

from urllib.parse import urlparse
import re
import requests


@app.post("/scan/web-audit")
def audit_web_security(payload: WebAuditRequest):

    target_url = payload.url.strip()

    # --------------------------------------------------------
    # NORMALIZE URL
    # --------------------------------------------------------

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # --------------------------------------------------------
    # GITHUB REPOSITORY CHECK
    # --------------------------------------------------------

    parsed_input = urlparse(target_url)
    input_domain = (parsed_input.hostname or "").lower()

    if input_domain == "github.com" or input_domain.endswith(".github.com"):

        return {
            "target_url": target_url,
            "final_url": target_url,
            "status_code": 200,
            "security_score": 0,
            "security_grade": "N/A",
            "risk_score": "Invalid Target",
            "executive_summary": (
                "GitHub URL သည် Source Code Repository ဖြစ်ပြီး "
                "Live Application မဟုတ်ပါ။ "
                "Source Code Vulnerability စစ်ဆေးရန် "
                "'Git Repository' Tab ကို အသုံးပြုပါ။"
            ),
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
                    "severity": "INFO",
                    "impact": (
                        "Web Audit သည် Live Website ၏ "
                        "HTTP Security Headers, Cookies နှင့် "
                        "Transport Security များကို စစ်ဆေးရန်ဖြစ်ပါသည်။"
                    ),
                    "remediation": (
                        "Live Website URL ကိုထည့်သွင်းပါ။ "
                        "Source Code စစ်ဆေးရန် Git Repository Tab ကိုအသုံးပြုပါ။"
                    )
                }
            ]
        }

    # --------------------------------------------------------
    # REQUEST
    # --------------------------------------------------------

    try:

        req_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9"
        }

        response = requests.get(
            target_url,
            headers=req_headers,
            timeout=15,
            allow_redirects=True,
            verify=True
        )

        # ----------------------------------------------------
        # FINAL URL AFTER REDIRECT
        # ----------------------------------------------------

        final_url = response.url

        parsed_final = urlparse(final_url)

        final_domain = (
            parsed_final.hostname or ""
        ).lower()

        # ----------------------------------------------------
        # ACTUAL TRANSPORT
        # ----------------------------------------------------

        is_ssl = (
            parsed_final.scheme.lower() == "https"
        )

        # ----------------------------------------------------
        # RESPONSE DATA
        # ----------------------------------------------------

        headers = response.headers

        html_content = response.text or ""

        html_lower = html_content.lower()

        # ----------------------------------------------------
        # SECURITY HEADERS
        # ----------------------------------------------------

        csp = headers.get(
            "Content-Security-Policy"
        )

        csp_report_only = headers.get(
            "Content-Security-Policy-Report-Only"
        )

        cors = headers.get(
            "Access-Control-Allow-Origin"
        )

        x_frame = headers.get(
            "X-Frame-Options"
        )

        hsts = headers.get(
            "Strict-Transport-Security"
        )

        x_content_type = headers.get(
            "X-Content-Type-Options"
        )

        referrer_policy = headers.get(
            "Referrer-Policy"
        )

        permissions_policy = headers.get(
            "Permissions-Policy"
        )

        server_info = headers.get(
            "Server"
        )

        x_powered_by = headers.get(
            "X-Powered-By"
        )

        # ----------------------------------------------------
        # NORMALIZE HEADER VALUES
        # ----------------------------------------------------

        csp_value = csp.strip() if csp else None
        csp_report_only_value = (
            csp_report_only.strip()
            if csp_report_only
            else None
        )

        cors_value = cors.strip() if cors else None

        x_frame_value = (
            x_frame.strip()
            if x_frame
            else None
        )

        hsts_value = (
            hsts.strip()
            if hsts
            else None
        )

        x_content_type_value = (
            x_content_type.strip()
            if x_content_type
            else None
        )

        referrer_policy_value = (
            referrer_policy.strip()
            if referrer_policy
            else None
        )

        # ----------------------------------------------------
        # CSP DETECTION
        # ----------------------------------------------------

        has_csp = bool(csp_value)

        has_csp_report_only = bool(
            csp_report_only_value
        )

        # Actual HTML META CSP detection
        meta_csp_pattern = re.compile(
            r'<meta[^>]+'
            r'http-equiv\s*=\s*["\']?'
            r'content-security-policy'
            r'["\']?[^>]*>',
            re.IGNORECASE
        )

        has_meta_csp = bool(
            meta_csp_pattern.search(html_content)
        )

        # ----------------------------------------------------
        # CLICKJACKING PROTECTION
        # ----------------------------------------------------

        has_x_frame = bool(x_frame_value)

        csp_has_frame_ancestors = False

        if csp_value:

            csp_has_frame_ancestors = bool(
                re.search(
                    r"(?:^|;)\s*frame-ancestors\s+[^;]+",
                    csp_value,
                    re.IGNORECASE
                )
            )

        clickjacking_protected = (
            has_x_frame
            or csp_has_frame_ancestors
        )

        # ----------------------------------------------------
        # HSTS
        # ----------------------------------------------------
        #
        # IMPORTANT:
        # Do NOT use a fake hard-coded preload list.
        #
        # HSTS is considered enforced only when the
        # actual response contains Strict-Transport-Security.
        #

        is_hsts_preloaded = False

        hsts_valid = False

        if hsts_value and is_ssl:

            max_age_match = re.search(
                r"max-age\s*=\s*(\d+)",
                hsts_value,
                re.IGNORECASE
            )

            if max_age_match:

                try:
                    max_age = int(
                        max_age_match.group(1)
                    )

                    if max_age > 0:
                        hsts_valid = True

                except ValueError:
                    hsts_valid = False

        # ----------------------------------------------------
        # SCORE
        # ----------------------------------------------------

        score = 100

        recommendations = []

        # ====================================================
        # 1. HTTPS / TLS
        # ====================================================

        if not is_ssl:

            score -= 40

            recommendations.append({
                "issue": "Missing SSL/TLS Encryption",
                "severity": "CRITICAL",
                "impact": (
                    "Website သည် HTTPS မသုံးထားသောကြောင့် "
                    "Network အတွင်း Data ကို "
                    "ကြားဖြတ်ဖတ်ရှုနိုင်ခြေ ရှိပါသည်။"
                ),
                "remediation": (
                    "Valid SSL/TLS Certificate တပ်ဆင်ပြီး "
                    "HTTPS ကို အသုံးပြုပါ။"
                )
            })

        # ====================================================
        # 2. CSP
        # ====================================================

        if not has_csp:

            if has_meta_csp:

                recommendations.append({
                    "issue": "CSP Found in HTML Meta Tag",
                    "severity": "INFO",
                    "impact": (
                        "Response Header တွင် CSP မတွေ့ရသော်လည်း "
                        "HTML Meta Tag တွင် CSP တွေ့ရှိရပါသည်။"
                    ),
                    "remediation": (
                        "Best Practice အနေဖြင့် "
                        "Content-Security-Policy ကို "
                        "HTTP Response Header တွင် သတ်မှတ်ပါ။"
                    )
                })

            elif has_csp_report_only:

                score -= 15

                recommendations.append({
                    "issue": (
                        "CSP Enforcement Missing "
                        "(Report-Only Only)"
                    ),
                    "severity": "MEDIUM",
                    "impact": (
                        "CSP Report-Only သည် violation များကို "
                        "report လုပ်နိုင်သော်လည်း "
                        "browser မှ malicious resource များကို "
                        "တားဆီးပေးခြင်းမရှိပါ။"
                    ),
                    "remediation": (
                        "Content-Security-Policy Header ကို "
                        "enforced mode ဖြင့် ထည့်သွင်းပါ။"
                    )
                })

            else:

                score -= 15

                recommendations.append({
                    "issue": (
                        "Missing Content Security Policy (CSP)"
                    ),
                    "severity": "MEDIUM",
                    "impact": (
                        "XSS နှင့် malicious resource loading "
                        "အန္တရာယ်များကို လျှော့ချရန် "
                        "CSP မရှိပါ။"
                    ),
                    "remediation": (
                        "HTTP Response Header တွင် "
                        "Content-Security-Policy ထည့်သွင်းပါ။"
                    )
                })

        # ====================================================
        # 3. CLICKJACKING
        # ====================================================

        if not clickjacking_protected:

            score -= 15

            recommendations.append({
                "issue": (
                    "Missing Clickjacking Protection"
                ),
                "severity": "MEDIUM",
                "impact": (
                    "Website ကို malicious iframe ထဲတွင် "
                    "ထည့်သွင်းပြီး Clickjacking ပြုလုပ်နိုင်ခြေ "
                    "ရှိပါသည်။"
                ),
                "remediation": (
                    "X-Frame-Options: SAMEORIGIN သို့မဟုတ် "
                    "CSP frame-ancestors directive ထည့်သွင်းပါ။"
                )
            })

        # ====================================================
        # 4. CORS
        # ====================================================

        if cors_value == "*":

            score -= 20

            recommendations.append({
                "issue": "Overly Permissive CORS Policy",
                "severity": "HIGH",
                "impact": (
                    "Access-Control-Allow-Origin: * ကို "
                    "အသုံးပြုထားပါသည်။ "
                    "Cross-Origin access ကို အလွန်ကျယ်ပြန့်စွာ "
                    "ခွင့်ပြုထားနိုင်ပါသည်။"
                ),
                "remediation": (
                    "လိုအပ်သော trusted origin များကိုသာ "
                    "ခွင့်ပြုပါ။"
                )
            })

        # ====================================================
        # 5. COOKIES
        # ====================================================

        raw_cookies = []

        try:

            if (
                hasattr(response.raw, "headers")
                and hasattr(
                    response.raw.headers,
                    "getlist"
                )
            ):

                raw_cookies = (
                    response.raw.headers.getlist(
                        "Set-Cookie"
                    )
                )

        except Exception:

            raw_cookies = []

        # Fallback
        if not raw_cookies:

            set_cookie_header = headers.get(
                "Set-Cookie"
            )

            if set_cookie_header:

                raw_cookies = [
                    set_cookie_header
                ]

        # ----------------------------------------------------
        # COOKIE ANALYSIS
        # ----------------------------------------------------

        if raw_cookies:

            missing_http_only = False
            missing_secure = False
            missing_samesite = False

            for cookie_str in raw_cookies:

                cookie_lower = (
                    cookie_str.lower()
                )

                # HttpOnly
                if "httponly" not in cookie_lower:

                    missing_http_only = True

                # Secure
                if (
                    is_ssl
                    and "secure" not in cookie_lower
                ):

                    missing_secure = True

                # SameSite
                if "samesite=" not in cookie_lower:

                    missing_samesite = True

            # ------------------------------------------------
            # HttpOnly
            # ------------------------------------------------

            if missing_http_only:

                score -= 10

                recommendations.append({
                    "issue": (
                        "Cookie Missing 'HttpOnly' Flag"
                    ),
                    "severity": "MEDIUM",
                    "impact": (
                        "Client-side JavaScript မှ "
                        "Cookie ကို access လုပ်နိုင်ခြေ "
                        "ရှိပါသည်။"
                    ),
                    "remediation": (
                        "Sensitive Session Cookie များတွင် "
                        "HttpOnly flag ထည့်သွင်းပါ။"
                    )
                })

            # ------------------------------------------------
            # Secure
            # ------------------------------------------------

            if missing_secure:

                score -= 10

                recommendations.append({
                    "issue": (
                        "Cookie Missing 'Secure' Flag"
                    ),
                    "severity": "MEDIUM",
                    "impact": (
                        "HTTPS အသုံးပြုနေသော်လည်း "
                        "Cookie ကို HTTP connection မှ "
                        "ပေးပို့နိုင်ခြေ ရှိပါသည်။"
                    ),
                    "remediation": (
                        "Sensitive Cookie များတွင် "
                        "Secure flag ထည့်သွင်းပါ။"
                    )
                })

            # ------------------------------------------------
            # SameSite
            # ------------------------------------------------

            if missing_samesite:

                score -= 5

                recommendations.append({
                    "issue": (
                        "Cookie Missing 'SameSite' Attribute"
                    ),
                    "severity": "LOW",
                    "impact": (
                        "Cross-Site Request Forgery (CSRF) "
                        "အန္တရာယ်မှ ကာကွယ်မှု လျော့နည်းနိုင်ပါသည်။"
                    ),
                    "remediation": (
                        "Cookie များတွင် "
                        "SameSite=Lax သို့မဟုတ် "
                        "SameSite=Strict သတ်မှတ်ပါ။"
                    )
                })

        # ====================================================
        # 6. X-POWERED-BY
        # ====================================================

        if x_powered_by:

            score -= 5

            recommendations.append({
                "issue": (
                    "Information Disclosure "
                    "(X-Powered-By Header)"
                ),
                "severity": "LOW",
                "impact": (
                    "Backend Framework / Technology "
                    "အချက်အလက်များကို ပြသနေပါသည်။"
                ),
                "remediation": (
                    "X-Powered-By Header ကို ဖျောက်ထားပါ။"
                )
            })

        # ====================================================
        # 7. SERVER VERSION DISCLOSURE
        # ====================================================

        if server_info:

            server_has_version = bool(
                re.search(
                    r"\d+(?:\.\d+)+",
                    server_info
                )
            )

            if server_has_version:

                score -= 5

                recommendations.append({
                    "issue": "Server Version Disclosure",
                    "severity": "LOW",
                    "impact": (
                        "Web Server Version ကို "
                        "Response Header မှတစ်ဆင့် "
                        "ဖော်ပြနေပါသည်။"
                    ),
                    "remediation": (
                        "Server Banner နှင့် "
                        "Version Tokens များကို ဖျောက်ထားပါ။"
                    )
                })

        # ====================================================
        # 8. HSTS
        # ====================================================

        if is_ssl and not hsts_valid:

            score -= 10

            recommendations.append({
                "issue": (
                    "Missing or Invalid HSTS Header"
                ),
                "severity": "LOW",
                "impact": (
                    "Browser မှ HTTPS ကို အမြဲအသုံးပြုရန် "
                    "သတ်မှတ်ထားခြင်း မတွေ့ရှိပါ။"
                ),
                "remediation": (
                    "Strict-Transport-Security: "
                    "max-age=31536000; includeSubDomains "
                    "ထည့်သွင်းပါ။"
                )
            })

        # ====================================================
        # 9. X-CONTENT-TYPE-OPTIONS
        # ====================================================

        if (
            not x_content_type_value
            or x_content_type_value.lower()
            != "nosniff"
        ):

            score -= 5

            recommendations.append({
                "issue": (
                    "Missing X-Content-Type-Options Header"
                ),
                "severity": "LOW",
                "impact": (
                    "Browser MIME Sniffing အန္တရာယ် "
                    "ရှိနိုင်ပါသည်။"
                ),
                "remediation": (
                    "X-Content-Type-Options: nosniff "
                    "ထည့်သွင်းပါ။"
                )
            })

        # ====================================================
        # 10. REFERRER POLICY
        # ====================================================

        if not referrer_policy_value:

            score -= 5

            recommendations.append({
                "issue": (
                    "Missing Referrer-Policy Header"
                ),
                "severity": "LOW",
                "impact": (
                    "Referrer Information များ "
                    "လိုအပ်သည်ထက်ပို၍ ပေါက်ကြားနိုင်ပါသည်။"
                ),
                "remediation": (
                    "Referrer-Policy: "
                    "strict-origin-when-cross-origin "
                    "သတ်မှတ်ပါ။"
                )
            })

        # ====================================================
        # 11. PERMISSIONS POLICY
        # ====================================================

        if not permissions_policy:

            recommendations.append({
                "issue": (
                    "Missing Permissions-Policy Header"
                ),
                "severity": "INFO",
                "impact": (
                    "Browser Features များကို "
                    "လိုအပ်သလို ကန့်သတ်ထားခြင်း "
                    "မတွေ့ရှိပါ။"
                ),
                "remediation": (
                    "Website အသုံးပြုသည့် Browser Features "
                    "များအလိုက် Permissions-Policy "
                    "သတ်မှတ်ရန် စဉ်းစားပါ။"
                )
            })

        # ====================================================
        # FINAL SCORE
        # ====================================================

        score = max(
            0,
            min(
                100,
                score
            )
        )

        # ====================================================
        # SECURITY GRADE
        # ====================================================

        if score >= 90:

            security_grade = "A+"
            risk_score = "Excellent (Secured)"

            executive_summary = (
                "ယခု Website တွင် စစ်ဆေးနိုင်သော "
                "အခြေခံ Web Security Controls များ "
                "ကောင်းမွန်စွာ သတ်မှတ်ထားပါသည်။"
            )

        elif score >= 75:

            security_grade = "B"
            risk_score = "Good (Low Risk)"

            executive_summary = (
                "အခြေခံ Web Security Controls များ "
                "ကောင်းမွန်သော်လည်း အချို့သော "
                "Security Headers သို့မဟုတ် Cookie "
                "Security Controls များ ထပ်မံတိုးတက်ရန် လိုအပ်ပါသည်။"
            )

        elif score >= 50:

            security_grade = "C"
            risk_score = "Moderate Risk"

            executive_summary = (
                "Security Controls အချို့ မရှိခြင်းကြောင့် "
                "Web Security Risk အလယ်အလတ်အဆင့် "
                "ရှိနေပါသည်။"
            )

        elif score >= 25:

            security_grade = "D"
            risk_score = "High Risk"

            executive_summary = (
                "အရေးကြီး Security Controls အများအပြား "
                "မရှိသောကြောင့် Risk မြင့်မားနေပါသည်။"
            )

        else:

            security_grade = "F"
            risk_score = "Critical Risk"

            executive_summary = (
                "အရေးကြီး Web Security Controls များ "
                "အများအပြား မရှိပါသဖြင့် "
                "အမြန်ဆုံး ပြင်ဆင်ရန် လိုအပ်ပါသည်။"
            )

        # ====================================================
        # SECURITY CARD STATUS
        # ====================================================

        if has_csp:

            script_prot_status = (
                "Active (CSP Header)"
            )

        elif has_meta_csp:

            script_prot_status = (
                "Active (HTML Meta Tag)"
            )

        elif has_csp_report_only:

            script_prot_status = (
                "Report-Only CSP"
            )

        else:

            script_prot_status = "Not Found"

        # ----------------------------------------------------
        # Clickjacking Card
        # ----------------------------------------------------

        if has_x_frame:

            clickjacking_status = (
                f"Active ({x_frame_value})"
            )

        elif csp_has_frame_ancestors:

            clickjacking_status = (
                "Active (CSP frame-ancestors)"
            )

        else:

            clickjacking_status = "Not Configured"

        # ----------------------------------------------------
        # HSTS Card
        # ----------------------------------------------------

        if hsts_valid:

            strict_https_status = (
                "Active (HSTS Enforced)"
            )

        elif is_ssl:

            strict_https_status = (
                "Not Enforced"
            )

        else:

            strict_https_status = (
                "N/A (HTTP)"
            )

        # ====================================================
        # RETURN RESULT
        # ====================================================

        return {

            "target_url": target_url,

            "final_url": final_url,

            "status_code": response.status_code,

            "security_score": score,

            "security_grade": security_grade,

            "risk_score": risk_score,

            "executive_summary": executive_summary,

            "server_info": (
                server_info
                if server_info
                else "Hidden"
            ),

            "security_cards": {

                "encryption": (
                    "Valid (HTTPS Standard)"
                    if is_ssl
                    else
                    "Insecure (HTTP Only)"
                ),

                "script_protection":
                    script_prot_status,

                "clickjacking_defense":
                    clickjacking_status,

                "strict_https":
                    strict_https_status
            },

            "recommendations":
                recommendations
        }

    # ========================================================
    # REQUEST ERROR
    # ========================================================

    except requests.exceptions.SSLError as e:

        return {

            "target_url": target_url,

            "final_url": None,

            "status_code": 0,

            "security_score": 0,

            "security_grade": "F",

            "risk_score": "SSL/TLS Error",

            "executive_summary": (
                "Target Website ၏ SSL/TLS Certificate "
                "ကို အတည်ပြု၍ မရပါ။"
            ),

            "server_info": "Unknown",

            "security_cards": {

                "encryption":
                    "SSL/TLS Certificate Error",

                "script_protection":
                    "Not Evaluated",

                "clickjacking_defense":
                    "Not Evaluated",

                "strict_https":
                    "Not Evaluated"
            },

            "recommendations": [

                {

                    "issue":
                        "SSL/TLS Certificate Validation Failed",

                    "severity":
                        "HIGH",

                    "impact":
                        str(e),

                    "remediation":
                        (
                            "Valid SSL/TLS Certificate "
                            "တပ်ဆင်ထားခြင်း ရှိမရှိ စစ်ဆေးပါ။"
                        )
                }
            ]
        }

    except requests.exceptions.Timeout as e:

        return {

            "target_url": target_url,

            "final_url": None,

            "status_code": 0,

            "security_score": 0,

            "security_grade": "F",

            "risk_score": "Connection Timeout",

            "executive_summary":
                "Target Server မှ Response ပြန်ရန် "
                "အချိန်ကြာမြင့်နေပါသည်။",

            "server_info": "Unknown",

            "security_cards": {

                "encryption":
                    "Not Evaluated",

                "script_protection":
                    "Not Evaluated",

                "clickjacking_defense":
                    "Not Evaluated",

                "strict_https":
                    "Not Evaluated"
            },

            "recommendations": [

                {

                    "issue":
                        "Target Connection Timeout",

                    "severity":
                        "HIGH",

                    "impact":
                        str(e),

                    "remediation":
                        (
                            "Target Server Online ဖြစ်မဖြစ် "
                            "နှင့် Network Connection ကို "
                            "စစ်ဆေးပါ။"
                        )
                }
            ]
        }

    except requests.exceptions.RequestException as e:

        return {

            "target_url": target_url,

            "final_url": None,

            "status_code": 0,

            "security_score": 0,

            "security_grade": "F",

            "risk_score": "Unreachable Target",

            "executive_summary": (
                "Target URL သို့ ချိတ်ဆက်၍ မရပါ။ "
                "Domain, DNS, Firewall သို့မဟုတ် "
                "Network Configuration ပြဿနာ ဖြစ်နိုင်ပါသည်။"
            ),

            "server_info": "Unknown",

            "security_cards": {

                "encryption":
                    "Not Evaluated",

                "script_protection":
                    "Not Evaluated",

                "clickjacking_defense":
                    "Not Evaluated",

                "strict_https":
                    "Not Evaluated"
            },

            "recommendations": [

                {

                    "issue":
                        "Failed to Reach Target Domain",

                    "severity":
                        "CRITICAL",

                    "impact":
                        str(e),

                    "remediation":
                        (
                            "Domain အမည်၊ Protocol နှင့် "
                            "Network Connection မှန်ကန်မှု "
                            "ရှိမရှိ စစ်ဆေးပါ။"
                        )
                }
            ]
        }