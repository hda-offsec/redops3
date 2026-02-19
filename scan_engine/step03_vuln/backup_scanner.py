import requests
from urllib.parse import urlparse

class BackupScanner:
    """
    Expert Backup & Archive Finder.
    Tests for misconfigured sensitive files like .bak, .zip, .old, etc.
    """
    def __init__(self, target):
        self.target = target
        self.common_files = [
            # Configs
            "config.php", "settings.py", "web.config", "database.yml", "env.php", "wp-config.php",
            # DBs
            "backup.sql", "dump.sql", "db.sql", "data.sql", "master.sql",
            # Code/Auth
            ".env", ".git/config", ".ssh/id_rsa", "auth.json", "credentials.json"
        ]
        self.extensions = [
            ".bak", ".old", ".save", ".tmp", "~", ".1", ".2", ".3",
            ".zip", ".tar.gz", ".tgz", ".7z", ".rar", ".bz2",
            ".swp", ".swo" # Vim swap files
        ]

    def scan_backups(self, port, protocol='http', logger=None):
        """
        Attempts to find backup files by appending extensions to common sensitive files.
        """
        findings = []
        base_url = f"{protocol}://{self.target}:{port}/"
        
        # Build targeted fuzz list
        fuzz_list = []
        for f in self.common_files:
            for ext in self.extensions:
                fuzz_list.append(f + ext)
                # Also try the file itself as it might be public
                if f not in fuzz_list: fuzz_list.append(f)

        if logger: logger(f"Backup Expert: Probing for {len(fuzz_list)} sensitive backup/archive patterns on port {port}...", "INFO")

        # Session for speed
        session = requests.Session()
        session.verify = False 
        
        found_count = 0
        for path in fuzz_list:
            # Simple UI feedback
            if found_count > 5: break # Avoid too many findings of the same type
            
            url = urljoin(base_url, path)
            try:
                # We use HEAD first to save bandwidth
                r = session.head(url, timeout=3, allow_redirects=False)
                
                # Check for 200 OK or interesting sizes
                if r.status_code == 200:
                    # Double check with GET to ensure it's not a generic 200 page
                    r_get = session.get(url, timeout=3, stream=True)
                    content_start = next(r_get.iter_content(512), b"")
                    
                    # Heuristic: If it's HTML, it might be a false positive "soft 404"
                    if b"<!DOCTYPE html" in content_start.lower() or b"<html" in content_start.lower():
                        continue
                        
                    found_count += 1
                    severity = "high"
                    if any(x in path for x in ['.env', '.sql', 'config', 'id_rsa']):
                        severity = "critical"
                    
                    findings.append({
                        "title": f"Sensitive Backup File Exposed: `{path}`",
                        "description": f"A potentially sensitive backup or archive file was found at {url}.\n\nSize: {r.headers.get('Content-Length', 'Unknown')} bytes",
                        "severity": severity,
                        "tool_source": "backup_expert",
                        "raw_loot": f"Exposed File: {url}",
                        "loot_type": "Sensitive File"
                    })
                    if logger: logger(f"💰 LOOT FOUND: Exposed backup detected at {url}", "WARN")
            except Exception:
                continue

        return findings

def urljoin(base, path):
    """Simple urljoin replacement to handle relative paths better"""
    if not base.endswith('/'): base += '/'
    return base + path
