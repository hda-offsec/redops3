import urllib.parse

class DorkScanner:
    """
    Advanced Module: Google Dorking Automation
    Generates dork links for manual verification (to avoid automated blocking)
    or automated queries if API is available.
    """

    def __init__(self, target):
        self.target = target

    def generate_dorks(self):
        """
        Returns a list of dork objects with description and manual link.
        """
        dorks = [
            {"name": "Publicly Exposed Documents", "query": f"site:{self.target} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"},
            {"name": "Directory Listing", "query": f"site:{self.target} intitle:index.of"},
            {"name": "Configuration Files", "query": f"site:{self.target} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini"},
            {"name": "Database Files", "query": f"site:{self.target} ext:sql | ext:dbf | ext:mdb"},
            {"name": "Log Files", "query": f"site:{self.target} ext:log"},
            {"name": "Backup and Old Files", "query": f"site:{self.target} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"},
            {"name": "Login Pages", "query": f"site:{self.target} inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:auth"},
            {"name": "SQL Errors", "query": f"site:{self.target} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\""},
            {"name": "PHP Errors", "query": f"site:{self.target} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\""},
            {"name": "Cloud Storage", "query": f"site:s3.amazonaws.com \"{self.target}\""}
        ]

        results = []
        for d in dorks:
            encoded_query = urllib.parse.quote(d['query'])
            google_link = f"https://www.google.com/search?q={encoded_query}"
            results.append({
                "type": "dork",
                "name": d['name'],
                "query": d['query'],
                "link": google_link
            })
        
        return results

    def scan(self, logger=None):
        # Automated scanning of Google is blocked very quickly.
        # We generate the links for the analyst to click in the UI.
        if logger: logger("DorkScanner: Generated 10 Google Hacking queries.", "INFO")
        return self.generate_dorks()
