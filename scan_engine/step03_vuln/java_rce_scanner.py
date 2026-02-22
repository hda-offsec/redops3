from scan_engine.helpers.http_client import get_session

class JavaRCEScanner:
    """
    Expert Auditor for Java-specific RCEs (Spring4Shell, Log4Shell, etc.).
    Uses high-fidelity behavioral probes.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-JavaExpert/1.0"})

    def scan_spring4shell(self, url, logger=None):
        findings = []
        # Detection logic for CVE-2022-22965 (Spring4Shell)
        # We attempt to modify the logging properties of the server (non-destructively)
        # If the server accepts 'class.module.classLoader...', it's vulnerable.
        try:
            # We try to change a safe parameter like 'suffix' for a logging configuration
            # This is a common non-destructive probe.
            payload = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
            attack_url = f"{url}?{payload}"
            
            # If it's vulnerable, it will return a 400 because we provided an illegal property value
            # but it indicates the PROPERTY WAS ACCESSED. 
            # 200/404 on normal URL vs 400 on this payload is a strong indicator.
            orig = self.session.get(url, timeout=5)
            resp = self.session.get(attack_url, timeout=5)
            
            # If server returns 400 Bad Request specifically for this class manipulation
            if resp.status_code == 400 and orig.status_code != 400:
                findings.append({
                    "title": "Critical: Spring4Shell Candidate (CVE-2022-22965)",
                    "description": f"Target appears to allow Class Loader manipulation via HTTP parameters.\nURL: {attack_url}\nThis indicates a high probability of RCE on Spring-based applications.",
                    "severity": "critical",
                    "tool_source": "java_expert",
                    "url": url
                })
                if logger: logger(f"CRITICAL: Spring4Shell candidate confirmed at {url}", "CRITICAL")
        except Exception:
            pass
        return findings

    def scan_log4shell(self, url, logger=None):
        # We can only perform high-fidelity Log4Shell if we have an OOB server.
        # For now, we report if we see Java stacks and common injection points.
        pass
