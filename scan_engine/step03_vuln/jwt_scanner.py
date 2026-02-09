import base64
import json
import re

class JWTScanner:
    def __init__(self):
        # Regex for JWT: header.payload.signature
        # Header/Payload always start with 'ey' (base64 encoded '{')
        self.jwt_pattern = re.compile(r'ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*')

    def decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) < 2: return None
            
            # Base64 padding fix
            def b64_decode(data):
                missing_padding = len(data) % 4
                if missing_padding:
                    data += '=' * (4 - missing_padding)
                return base64.urlsafe_b64decode(data).decode('utf-8')

            header = json.loads(b64_decode(parts[0]))
            payload = json.loads(b64_decode(parts[1]))
            return {"header": header, "payload": payload}
        except:
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
                "desc": f"JWT at {source_url} uses 'none' algorithm which allows arbitrary payload modification."
            })
            
        # 2. Information Disclosure
        sensitive_keys = ['email', 'password', 'role', 'admin', 'id', 'user_id', 'internal']
        found_sensitive = [k for k in sensitive_keys if k in str(payload).lower()]
        if found_sensitive:
            findings.append({
                "type": "JWT Information Disclosure",
                "severity": "low",
                "desc": f"JWT contains potentially sensitive keys: {', '.join(found_sensitive)}"
            })
            
        # 3. Weak Algorithm Check
        if header.get("alg") == "HS256":
             findings.append({
                "type": "JWT HS256 Usage",
                "severity": "info",
                "desc": "Uses HS256 (Symmetric). Potential for secret cracking if weak. Use 'jwt_tool' to check."
            })
             
        return findings if findings else None

    def scan_text(self, text, url):
        """Scans raw text (like JS files or response bodies) for JWTs"""
        matches = self.jwt_pattern.findall(text)
        results = []
        for m in set(matches): # unique tokens
            audit = self.audit_token(m, url)
            if audit:
                for a in audit:
                    a["token_preview"] = m[:30] + "..."
                results.extend(audit)
        return results
