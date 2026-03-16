import re
from urllib.parse import urlparse
from scan_engine.helpers.http_client import get_session

class DOMXSSExpert:
    """
    Wave 5: Heuristic DOM-XSS Expert.
    Identifies risky JavaScript sinks and sources that could lead to DOM-based XSS.
    """
    
    SINKS = [
        r"innerHTML", r"outerHTML", r"document\.write", r"document\.writeln",
        r"eval\(", r"setTimeout\(", r"setInterval\(", r"Function\(",
        r"\.anchor\.set", r"\.action", r"\.src", r"jQuery\("
    ]
    
    SOURCES = [
        r"location\.hash", r"location\.search", r"location\.href", r"window\.name",
        r"document\.referrer", r"document\.URL", r"document\.documentURI"
    ]

    def __init__(self, options=None):
        self.options = options or {}

    def scan_endpoints(self, urls, logger=None):
        """
        Scans a list of URLs for DOM-XSS indicators.
        """
        if logger: logger(f"DOM-XSS Expert: Auditing {len(urls)} candidates for client-side sinks...", "INFO")
        
        findings = []
        session = get_session(self.options)
        
        # Limit to top 20 interesting URLs (HTML/JS)
        targets = [u for u in urls if any(u.endswith(ext) for ext in [".html", ".htm", ".js", "/"])]
        targets = list(set(targets))[:20]

        for url in targets:
            try:
                resp = session.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    evidence = self._analyze_text(resp.text)
                    if evidence:
                        f = {
                            "title": "Possible DOM-XSS Detected (Heuristic)",
                            "severity": "medium",
                            "confidence": "medium",
                            "description": f"Heuristic analysis identified risky JavaScript sinks fed by controllable sources in {url}.\n\n" + \
                                           f"**Evidence discovered:**\n" + "\n".join([f"- `{e}`" for e in evidence]),
                            "remediation": "Avoid using dangerous sinks like `innerHTML` or `eval`. Use safer alternatives like `textContent` and `JSON.parse`. Always sanitize data before passing it to any DOM-modifying function.",
                            "risk_scorecard": {"impact": "High", "complexity": "Medium", "likelihood": "Medium"},
                            "repro_command": f"Go to {url} and check for the following patterns in the source.",
                            "endpoint": url,
                            "metadata": {
                                "sinks_found": [s for s in self.SINKS if re.search(s, resp.text)],
                                "sources_found": [s for s in self.SOURCES if re.search(s, resp.text)]
                            }
                        }
                        findings.append(f)
            except Exception: pass
            
        return findings

    def _analyze_text(self, text):
        evidence = []
        # Check for proximity of source and sink (very simple heuristic)
        found_sources = [s for s in self.SOURCES if re.search(s, text)]
        found_sinks = [s for s in self.SINKS if re.search(s, text)]
        
        if found_sources and found_sinks:
            for source in found_sources:
                for sink in found_sinks:
                    # If both are present, it's worth reporting
                    evidence.append(f"Source '{source.replace('\\', '')}' and Sink '{sink.replace('\\', '')}' present in same file.")
        
        return evidence
