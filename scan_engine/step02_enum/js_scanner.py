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
            "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            "Heroku API Key": r'[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            "MailChimp API Key": r'[0-9a-fA-F]{32}-us[0-9]{1,2}',
            "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24}',
            "Square Access Token": r'sqOatp-[0-9A-Za-z\-_]{22}',
            "Twilio API Key": r'SK[0-9a-fA-F]{32}'
        }
        self.endpoint_pattern = r'(?:"| \')((?:/|[a-zA-Z]+://)[^"\'\s<>]{3,})(?:"| \')'

    def scan_url(self, url):
        """Fetches a JS file and scans it for secrets and endpoints"""
        results = {"secrets": [], "endpoints": []}
        try:
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                # Scan for Secrets
                for name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        results["secrets"].append({
                            "type": name,
                            "match": match.group(0)[:100],
                            "line_context": content[max(0, match.start()-30):min(len(content), match.end()+30)].replace("\n", " ").strip()
                        })
                # Scan for Endpoints
                endpoints = re.findall(self.endpoint_pattern, content)
                for ep in endpoints:
                    # Filter for likely endpoints
                    if any(x in ep for x in ["/", "http", "api", "v1", "v2"]):
                        results["endpoints"].append(ep)
                results["endpoints"] = list(set(results["endpoints"])) # unique
        except Exception:
            pass
        return results

    def scan_list(self, urls, logger=None):
        """Scans a list of URLs and returns a summary of findings"""
        all_results = {"secrets": {}, "endpoints": []}
        js_urls = [u for u in urls if u.endswith('.js')]
        
        if logger: logger(f"JS Advanced Analysis: Auditing {len(js_urls)} JavaScript files...", "INFO")
        
        for url in js_urls:
            res = self.scan_url(url)
            if res["secrets"]:
                all_results["secrets"][url] = res["secrets"]
                if logger: logger(f"💰 Found {len(res['secrets'])} potential secrets in {url}", "WARN")
            if res["endpoints"]:
                all_results["endpoints"].extend(res["endpoints"])
                
        all_results["endpoints"] = list(set(all_results["endpoints"]))
        return all_results
