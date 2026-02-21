import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import re

class DeserializationScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_deserialization(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        if logger: logger(f"🧊 Deserialization Check: Analyzing objects on {base_url}...", "INFO")

        try:
            r = http_client.get(base_url, options=getattr(self, "options", None), timeout=5)
            
            # Detect serialized Java objects (HEX pattern AC ED 00 05)
            # Or Base64 encoded Java objects (starts with rO0)
            # PHP Serialization (O:4:"User":...)
            # .NET ViewState (__VIEWSTATE)
            
            suspects = []
            
            # Check Headers/Cookies
            for k, v in r.cookies.items():
                if v.startswith("rO0") or v.startswith("H4sI"):
                    suspects.append(f"Java Object in Cookie: {k}")
            
            text_sample = r.text[:5000]
            if "rO0AB" in text_sample: 
                suspects.append("Java Object in Body")
            if "O:8:\"" in text_sample: # PHP Object signature (loose)
                suspects.append("PHP Object in Body")
                
            if suspects:
                findings.append({
                    "title": "High: Insecure Deserialization Risk",
                    "description": f"Potential serialized objects detected: {', '.join(suspects)}. If these are untrusted, it can lead to RCE.",
                    "severity": "high",
                    "tool_source": "deserialization_scanner",
                    "raw_loot": base_url
                })
        except Exception:
            pass
        return findings
