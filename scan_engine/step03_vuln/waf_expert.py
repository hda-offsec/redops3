from scan_engine.helpers.http_client import get_session

class WAFExpertScanner:
    """
    Expert Auditor for WAF/IPS Fingerprinting.
    Identifies active protection solutions via behavioral analysis and triggers.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(options)
        self.session.headers.update({"User-Agent": "RedOps3-WAFExpert/1.0"})
        # Fingerprints based on headers and response signatures
        self.waf_signatures = {
            "Cloudflare": {"headers": ["cf-ray", "__cfduid", "cf-cache-status"], "text": ["cloudflare-nginx", "cloudflare ray id"]},
            "AWS WAF": {"headers": ["x-amzn-requestid", "x-amz-cf-id"]},
            "Imperva / Incapsula": {"headers": ["x-cdn", "x-iinfo", "incap_ses", "visid_incap"], "text": ["incapsula", "imperva"]},
            "F5 BIG-IP ASM": {"headers": ["x-wa-info", "ts", "f5-cache-control"]},
            "Akamai": {"headers": ["x-akamai-transformed", "x-edgeconnect-hit", "akamai-grn"]},
            "ModSecurity": {"headers": ["x-mod-security", "mod_security-message"], "text": ["not acceptable", "mod_security"]}
        }

    def fingerprint(self, url, logger=None):
        findings = []
        if logger: logger(f"WAF Expert: Fingerprinting security stack for {url}...", "INFO")

        try:
            # 1. Baseline Request
            r = self.session.get(url, timeout=5)
            
            detected_waf = None
            for name, sig in self.waf_signatures.items():
                # Check headers
                for h in sig.get("headers", []):
                    if h.lower() in [key.lower() for key in r.headers.keys()]:
                        detected_waf = name
                        break
                if detected_waf: break
                
                # Check body text
                for t in sig.get("text", []):
                    if t.lower() in r.text.lower():
                        detected_waf = name
                        break
                if detected_waf: break

            if not detected_waf:
                # 2. Trigger Request (Illegal payload to force a WAF block)
                try:
                    trigger_url = f"{url}?waf_probe=<script>alert(1)</script> OR 1=1"
                    r_trigger = self.session.get(trigger_url, timeout=5)
                    
                    if r_trigger.status_code in [403, 406, 501, 999]:
                         # Blocked! Check if we can identify from block page
                         for name, sig in self.waf_signatures.items():
                            for t in sig.get("text", []):
                                if t.lower() in r_trigger.text.lower():
                                    detected_waf = name
                                    break
                            if detected_waf: break
                         
                         if not detected_waf: detected_waf = "Generic WAF/IPS (Blocked Probe)"
                except Exception:
                    pass

            if detected_waf:
                findings.append({
                    "title": f"Security Infrastructure Detected: {detected_waf}",
                    "description": f"The target is protected by {detected_waf}.\nURL: {url}\nAdaptive payloads should be used to bypass this layer.",
                    "severity": "info",
                    "tool_source": "waf_expert",
                    "url": url,
                    "waf_type": detected_waf
                })
                if logger: logger(f"INFO: WAF Detected -> {detected_waf}", "SUCCESS")

        except Exception as e:
            pass
            
        return findings
