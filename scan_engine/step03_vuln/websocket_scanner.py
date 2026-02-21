import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
from urllib.parse import urlparse

class WebSocketScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_websocket(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # CSWSH Check (Cross-Site WebSocket Hijacking)
        # We look for UPGRADE headers in response or JS files mentioning ws://
        # For active scan, we can try to initiate handshake with arbitrary Origin
        
        # Simple Logic: Try to upgrade connection
        ws_url = f"ws://{self.target}:{port}/ws" # generic path
        if protocol == 'https': ws_url = f"wss://{self.target}:{port}/ws"

        if logger: logger(f"🔌 WebSocket Audit: Checking CSWSH on {ws_url}...", "INFO")

        # Since 'requests' doesn't do WS fully, we check HTTP Upgrade response
        # or we rely on JS findings.
        # Here we perform a specialized check: Origin Reflection on Upgrade
        
        try:
            headers = {
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": "https://evil.redops.com"
            }
            
            # We try root or /ws
            r = http_client.get(base_url, options=getattr(self, "options", None), headers=headers, timeout=3, allow_redirects=False)
            
            if r.status_code == 101:
                # server accepted upgrade from evil origin!
                findings.append({
                    "title": "Critical: WebSocket Hijacking (CSWSH)",
                    "description": f"Server acccepted WebSocket handshake from arbitrary Origin `https://evil.redops.com`. This allows CSWSH attacks.",
                    "severity": "critical",
                    "tool_source": "websocket_scanner",
                    "raw_loot": base_url
                })
        except Exception:
            pass
            
        return findings
