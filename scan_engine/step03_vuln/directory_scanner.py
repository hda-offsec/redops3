from playwright.sync_api import sync_playwright
import os
import re

class DirectoryScanner:
    def __init__(self, target, scan_id, options=None):
        self.options = options
        self.target = target
        self.scan_id = scan_id
        self.screenshot_dir = f"ui/web/static/screenshots/scan_{scan_id}"
        os.makedirs(self.screenshot_dir, exist_ok=True)

    def is_directory_listing(self, html_content):
        """Detects if the page is a directory listing."""
        patterns = [
            r"<title>Index of /",
            r"<h1>Index of /",
            r"Directory Listing For",
            r"Last modified</a>",
            r"Parent Directory</a>"
        ]
        for p in patterns:
            if re.search(p, html_content, re.IGNORECASE):
                return True
        return False

    def take_screenshot(self, url, filename):
        """Takes a screenshot of the given URL."""
        path = f"{self.screenshot_dir}/{filename}.png"
        rel_path = f"screenshots/scan_{self.scan_id}/{filename}.png"
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=30000)
                page.screenshot(path=path, full_page=True)
                browser.close()
            return rel_path
        except Exception:
            return None

    def audit_endpoints(self, endpoints, logger=None):
        """
        Takes a list of endpoints (from Katana or Dirbusting) and checks for directory listing.
        """
        findings = []
        import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
        
        if logger: logger(f"Directory Audit: Checking {len(endpoints)} endpoints for index exposure...", "INFO")
        
        # Limit checking to avoid too many requests
        checked = 0
        for ep in endpoints:
            if checked > 50: break # Guardrail
            
            try:
                r = http_client.get(ep, options=getattr(self, "options", None), timeout=5)
                if self.is_directory_listing(r.text):
                    if logger: logger(f"🔥 DIRECTORY LISTING: Found at {ep}", "WARN")
                    
                    # Take screenshot
                    filename = f"dir_listing_{checked}"
                    screenshot = self.take_screenshot(ep, filename)
                    
                    findings.append({
                        "title": f"High: Directory Listing Exposure",
                        "description": f"Publicly accessible directory listing detected at `{ep}`. This can leak sensitive files, configuration data, or source code.",
                        "severity": "high",
                        "tool_source": "dir_scanner",
                        "screenshot_path": screenshot
                    })
                checked += 1
            except Exception:
                continue
                
        return findings
