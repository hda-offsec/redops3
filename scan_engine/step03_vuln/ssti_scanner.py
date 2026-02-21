from scan_engine.helpers.http_client import get_session
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

class SSTIScanner:
    """
    V6 EXPERT: Advanced SSTI Polyglot & Engine Identifier.
    Detects and identifies template engines (Jinja2, Twig, Mako, Smarty, Freemarker, etc.)
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.session = get_session(options if 'options' in locals() else (self.options if hasattr(self, 'options') else None))
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (RedOps3-SSTI-Expert)"})

    def get_payloads(self):
        """Returns a list of payloads designed to identify the specific engine."""
        return [
            # Generic detection
            {"payload": "${7*7}", "expected": "49", "engines": ["Freemarker", "Velocity", "EL"]},
            {"payload": "{{7*7}}", "expected": "49", "engines": ["Jinja2", "Twig", "Mako", "Handlebars"]},
            {"payload": "<%= 7*7 %>", "expected": "49", "engines": ["ERB", "ASP.NET"]},
            
            # Engine Specific Identification
            {"payload": "{{7*'7'}}", "expected": "7777777", "engines": ["Jinja2", "Twig"]},
            {"payload": "${7+'7'}", "expected": "14", "engines": ["Freemarker"]}, # Often fails in strict Java
            {"payload": "*{7*7}", "expected": "49", "engines": ["Thymeleaf"]},
            {"payload": "[[7*7]]", "expected": "49", "engines": ["VueJS", "Angular"]}
        ]

    def scan_endpoint(self, url, params, logger=None):
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if logger: logger(f"SSTI Expert: Auditing {url} with polyglot probes...", "INFO")

        for param_name in params:
            for probe in self.get_payloads():
                try:
                    # Construct URL with payload
                    qs = parse_qs(parsed.query)
                    qs[param_name] = [probe["payload"]]
                    test_url = f"{base}?{urlencode(qs, doseq=True)}"
                    
                    r = self.session.get(test_url, timeout=5, verify=False)
                    
                    # Detection logic: expected result must be present, but NOT the payload itself
                    if probe["expected"] in r.text and probe["payload"] not in r.text:
                        engine_guess = ", ".join(probe["engines"])
                        finding = {
                            "title": f"🔥 CRITICAL: SSTI Detected ({engine_guess})",
                            "description": (
                                f"Server-Side Template Injection confirmed on parameter `{param_name}`.\n"
                                f"The server rendered the payload `{probe['payload']}` as `{probe['expected']}`.\n\n"
                                f"**Likely Engines**: {engine_guess}"
                            ),
                            "severity": "critical",
                            "tool_source": "ssti_expert",
                            "url": test_url,
                            "payload": probe["payload"],
                            "repro_command": f"curl -G '{base}' --data-urlencode '{param_name}={probe['payload']}'"
                        }
                        findings.append(finding)
                        if logger: logger(f"💀 SSTI VULNERABILITY CONFIRMED: {engine_guess} on {param_name}", "CRITICAL")
                        break # Move to next parameter once confirmed
                except Exception as e:
                    if logger: logger(f"SSTI Probe Error on {param_name}: {e}", "DEBUG")
                    
        return findings

    def audit_all(self, endpoints_map, logger=None):
        """
        Expects a map of {url: [params]}
        """
        all_findings = []
        for url, params in endpoints_map.items():
            if not params: continue
            all_findings.extend(self.scan_endpoint(url, params, logger))
        return all_findings
