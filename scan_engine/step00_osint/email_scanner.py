import requests
import re

class EmailScanner:
    def __init__(self, target):
        self.target = target
        self.email_regex = r'[a-zA-Z0-9._%+-]+@' + re.escape(self.target)

    def search_crtsh(self, logger=None):
        """Find emails in SSL certificates via crt.sh"""
        emails = set()
        try:
            url = f"https://crt.sh/?q={self.target}&output=json"
            response = requests.get(url, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('common_name', '')
                    matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}', name)
                    for email in matches:
                        if self.target in email:
                            emails.add(email)
        except Exception as e:
            if logger: logger(f"Email Search (crt.sh) failed: {e}", "WARN")
        return list(emails)

    def scan_pages(self, urls, logger=None):
        """Scrape emails from a list of URLs"""
        emails = set()
        if logger: logger(f"Email Discover: Scraping {len(urls)} pages for contact info...", "INFO")
        for url in urls[:50]: # limit to first 50 pages
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    matches = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(self.target), response.text)
                    for email in matches:
                        emails.add(email)
            except Exception:
                continue
        return list(emails)

    def scan(self, logger=None, extra_urls=None):
        if logger: logger(f"OSINT: Searching for emails associated with {self.target}...", "INFO")
        
        # Combine different sources
        findings = set()
        
        # Source 1: crt.sh
        crt_emails = self.search_crtsh(logger)
        findings.update(crt_emails)
        
        # Source 2: Scraping discovered pages
        if extra_urls:
            web_emails = self.scan_pages(extra_urls, logger)
            findings.update(web_emails)
        
        result_list = list(findings)
        if logger:
            if result_list:
                logger(f"📧 Found {len(result_list)} unique email addresses!", "SUCCESS")
            else:
                logger(f"No emails discovered for {self.target}.", "INFO")
                
        return result_list
