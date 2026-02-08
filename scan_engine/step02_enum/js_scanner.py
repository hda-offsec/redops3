import re
import requests
import json
from scan_engine.helpers.process_manager import ProcessManager

class JSSecretScanner:
    def __init__(self, target):
        self.target = target
        # Common patterns for secrets
        self.patterns = {
            "Generic API Key": r'(?i)(api[_-]?key|api[_-]?token|auth[_-]?token|secret[_-]?key|access[_-]?token)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
            "Google API (AI/Firebase)": r'AIza[0-9A-Za-z-_]{35}',
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'secret_key["\']\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
            "Slack Token": r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
            "Generic Secret": r'(?i)(secret|password|passwd|pwd|private|credential)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.@#$%^&*!]{6,})["\']',
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'
        }

    def scan_url(self, url):
        """Fetches a JS file and scans it for secrets"""
        findings = []
        try:
            # Add reasonable timeout and verify=False for dev/target environments
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                for name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        match_text = match.group(0)
                        # Avoid highlighting too much for the UI, truncate if long
                        findings.append({
                            "type": name,
                            "match": match_text[:100],
                            "line_context": content[max(0, match.start()-30):min(len(content), match.end()+30)].replace("\n", " ").strip()
                        })
        except Exception:
            pass
        return findings

    def scan_list(self, urls, logger=None):
        """Scans a list of URLs and returns a summary of findings"""
        all_findings = {}
        js_urls = [u for u in urls if u.endswith('.js')]
        
        if logger: logger(f"JS Secret Scan: Auditing {len(js_urls)} JavaScript files...", "INFO")
        
        for url in js_urls:
            findings = self.scan_url(url)
            if findings:
                all_findings[url] = findings
                if logger: logger(f"💰 Found {len(findings)} potential secrets in {url}", "WARN")
                
        return all_findings
