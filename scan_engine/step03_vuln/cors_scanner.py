import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class CORSScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_cors(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        origin_payload = "https://evil.redops.com"
        headers = {"Origin": origin_payload}

        if logger: logger(f"🌐 CORS Audit: Testing policies on {base_url}...", "INFO")

        try:
            r = http_client.get(base_url, options=getattr(self, "options", None), headers=headers, timeout=3, allow_redirects=True)
            
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials")

            if acao:
                if acao == origin_payload and acac == 'true':
                    findings.append({
                        "title": "High: Critical CORS Misconfiguration (Reflection)",
                        "description": f"Server reflects arbitrary Origin `{origin_payload}` with `Access-Control-Allow-Credentials: true`. This allows authenticated data theft.",
                        "severity": "high",
                        "tool_source": "cors_scanner",
                        "raw_loot": base_url
                    })
                elif acao == "*" and acac == 'true':
                     findings.append({
                        "title": "High: CORS Misconfiguration (Wildcard + Creds)",
                        "description": "Server allows Wildcard Origin with Credentials. (Note: Browsers block this, but it indicates poor config).",
                        "severity": "medium",
                        "tool_source": "cors_scanner"
                    })
                elif acao == "null":
                     findings.append({
                        "title": "Medium: CORS Null Origin Allowed",
                        "description": "Server accepts `null` origin. Vulnerable to sandboxed iframe attacks.",
                        "severity": "medium",
                        "tool_source": "cors_scanner"
                    })
        except Exception:
            pass
        return findings
