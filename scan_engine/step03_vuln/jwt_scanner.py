import base64
import json
import re
import requests

class JWTScanner:
    """
    V6 EXPERT: Advanced JWT Security Auditor.
    Checks for none-algorithm, weak secrets, key confusion, and header injections.
    """
    def __init__(self):
        # Regex for JWT: header.payload.signature
        self.jwt_pattern = re.compile(r'ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*')
        self.sensitive_keys = ['email', 'password', 'role', 'admin', 'id', 'user_id', 'internal', 'secret', 'key', 'priv']

    def decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) < 2: return None
            
            def b64_decode(data):
                missing_padding = len(data) % 4
                if missing_padding:
                    data += '=' * (4 - missing_padding)
                return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')

            header = json.loads(b64_decode(parts[0]))
            payload = json.loads(b64_decode(parts[1]))
            return {"header": header, "payload": payload, "signature": parts[2] if len(parts) > 2 else ""}
        except Exception:
            return None

    def audit_token(self, token, source_url):
        decoded = self.decode_jwt(token)
        if not decoded: return None
        
        findings = []
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})
        
        # 1. Critical: None Algorithm
        if header.get("alg", "").lower() == "none":
            findings.append({
                "type": "JWT 'none' Algorithm",
                "severity": "critical",
                "desc": f"JWT at {source_url} uses 'none' algorithm. An attacker can modify the payload and bypass authentication by stripping the signature."
            })
            
        # 2. Key ID (kid) Injection Potential
        if "kid" in header:
            kid = str(header["kid"])
            # Check for path traversal or SQLi patterns in kid
            if "../" in kid or "/" in kid or "'" in kid or "\"" in kid:
                findings.append({
                    "type": "JWT 'kid' Parameter Injection",
                    "severity": "high",
                    "desc": f"The JWT 'kid' parameter (`{kid}`) contains suspicious characters (traversal or quotes). This may indicate vulnerability to Path Traversal or SQL Injection during key lookup."
                })

        # 3. JWK Set URL (jku) / JSON Web Key (jwk) abuse
        if "jku" in header:
            findings.append({
                "type": "JWT 'jku' Header Discovery",
                "severity": "medium",
                "desc": f"The JWT contains a 'jku' (JWK Set URL) header: `{header['jku']}`. Attackers might provide their own URL to force the server to trust their keys."
            })
        if "jwk" in header:
            findings.append({
                "type": "JWT 'jwk' Inline Key Discovery",
                "severity": "medium",
                "desc": "The JWT contains an inline 'jwk' (JSON Web Key). If not properly validated against a whitelist, this allows an attacker to sign their own tokens."
            })

        # 4. Information Disclosure
        found_sensitive = [k for k in self.sensitive_keys if k in str(payload).lower()]
        if found_sensitive:
            findings.append({
                "type": "JWT Information Disclosure",
                "severity": "low",
                "desc": f"JWT payload contains potentially sensitive keys: {', '.join(found_sensitive)}. JWTs are base64 encoded and visible to anyone holding the token."
            })
            
        # 5. Algorithm Confusion (RS256 vs HS256)
        if header.get("alg") == "RS256":
            findings.append({
                "type": "JWT Algorithm Confusion Candidate",
                "severity": "info",
                "desc": "Token uses RS256 (Asymmetric). It might be vulnerable to RS256->HS256 confusion where the public key is used as a symmetric secret."
            })
        elif header.get("alg") == "HS256":
             findings.append({
                "type": "JWT HS256 Usage",
                "severity": "info",
                "desc": "Uses HS256 (Symmetric). Secure if the secret is strong, but vulnerable to offline brute-force cracking."
            })
             
        return findings if findings else None

    def scan_text(self, text, url):
        """Scans raw text for JWTs"""
        matches = self.jwt_pattern.findall(text)
        results = []
        for m in set(matches):
            audit = self.audit_token(m, url)
            if audit:
                for a in audit:
                    a["token_preview"] = m[:40] + "..."
                results.extend(audit)
        return results

    def probe_endpoint(self, url, logger=None):
        """Probes a specific endpoint for JWTs in headers/cookies"""
        findings = []
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            
            # Check Cookies
            for cookie in r.cookies:
                if self.jwt_pattern.match(cookie.value):
                    if logger: logger(f"JWT Expert: Found JWT in cookie '{cookie.name}' at {url}", "SUCCESS")
                    audit = self.audit_token(cookie.value, url)
                    if audit: findings.extend(audit)
            
            # Check Auth Header (if reflected or in subsequent requests - though we only see once here)
            auth = r.headers.get("Authorization", "")
            if "Bearer " in auth:
                token = auth.replace("Bearer ", "").strip()
                if self.jwt_pattern.match(token):
                    audit = self.audit_token(token, url)
                    if audit: findings.extend(audit)

        except Exception as e:
            if logger: logger(f"JWT Probe Error: {e}", "DEBUG")
            
        return findings
