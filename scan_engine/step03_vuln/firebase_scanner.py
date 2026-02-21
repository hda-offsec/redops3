import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class FirebaseScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_firebase(self, logger=None):
        findings = []
        # Extract project name from domain or subdomains
        project_names = [self.target.split('.')[0]]
        # Common variations
        project_names.extend([f"{self.target.split('.')[0]}-dev", f"{self.target.split('.')[0]}-staging"])

        if logger: logger(f"🔥 Firebase Scanner: Checking {len(project_names)} potential buckets...", "INFO")

        for project in project_names:
            url = f"https://{project}.firebaseio.com/.json"
            try:
                r = http_client.get(url, options=getattr(self, "options", None), timeout=3)
                if r.status_code == 200:
                    findings.append({
                        "title": f"CRITICAL: Open Firebase Database ({project})",
                        "description": f"The Firebase database at `{url}` is openly accessible and returns JSON data. This is a critical data breach.",
                        "severity": "critical",
                        "tool_source": "firebase_scanner",
                        "raw_loot": url
                    })
                    if logger: logger(f"🚨 FIREBASE BREACH: {url}", "CRITICAL")
            except Exception:
                pass
        return findings
