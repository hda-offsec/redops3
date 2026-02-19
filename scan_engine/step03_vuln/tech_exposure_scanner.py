import requests

class TechExposureScanner:
    def __init__(self, target):
        self.target = target
        self.sensitive_files = [
            '.env', '.env.local', '.env.bak', '.env.old', '.env.save',
            'docker-compose.yml', 'Dockerfile', 'web.config', 'phpinfo.php',
            'info.php', 'config.php.bak', 'settings.py.bak', 'wp-config.php.bak',
            '.bash_history', '.ssh/id_rsa', '.ssh/id_dsa', '.aws/credentials'
        ]

    def audit(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}/"
        
        if logger: logger(f"Advanced: Searching for technical exposure on {base_url}...", "INFO")
        
        for file in self.sensitive_files:
            url = base_url + file
            try:
                # We use a custom User-Agent to avoid some basic filter and allow_redirects=False
                r = requests.get(url, timeout=5, verify=True, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
                
                # Check if it looks like a real file (200 OK + not a generic login page)
                if r.status_code == 200:
                    content_len = len(r.content)
                    # Simple heuristic: if it's too large or too small, maybe it's a false positive (custom 404)
                    if content_len > 0 and content_len < 50000:
                        # Extra check: for .env, look for key-value patterns
                        is_likely = True
                        if '.env' in file:
                            if '=' not in r.text or '<html' in r.text.lower():
                                is_likely = False
                        
                        if is_likely:
                            if logger: logger(f"🔥 EXPOSURE FOUND: {url} ({content_len} bytes)", "CRITICAL")
                            findings.append({
                                "title": f"Technical File Exposure: {file} ({port})",
                                "description": f"A sensitive technical file was found publicly accessible: {url}\nSize: {content_len} bytes.",
                                "severity": "critical" if any(x in file for x in ['.env', '.ssh', 'aws', 'docker']) else "high",
                                "tool_source": "tech_audit"
                            })
            except Exception:
                continue
                
        return findings
