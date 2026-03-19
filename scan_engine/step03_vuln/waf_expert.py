import random
import re
from scan_engine.helpers.http_client import get_session

class WAFExpertScanner:
    """
    Expert Auditor for WAF/IPS Fingerprinting.
    Identifies active protection solutions via behavioral analysis and triggers.
    V12: Ported from RedOps2 AdvancedWAFDetector.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-WAFExpert/1.0"})
        
        # Expanded WAF Fingerprints (Headers and Server signatures)
        self.waf_signatures = {
            "Cloudflare": {"headers": ["cf-ray", "__cfduid", "cf-cache-status"], "text": ["cloudflare-nginx", "cloudflare ray id"], "server": "cloudflare"},
            "Akamai": {"headers": ["x-akamai-transformed", "x-akamai-request-id", "x-edgeconnect-hit", "akamai-grn"], "server": "akamai"},
            "AWS WAF": {"headers": ["x-amzn-requestid", "x-amzn-trace-id", "x-amz-cf-id"], "server": "awswaf"},
            "Imperva / Incapsula": {"headers": ["x-cdn", "x-iinfo", "incap_ses", "visid_incap"], "text": ["incapsula", "imperva"], "server": "incapsula"},
            "F5 BIG-IP ASM": {"headers": ["x-wa-info", "ts", "f5-cache-control", "x-c-request-id"], "server": "big-ip"},
            "Citrix NetScaler": {"headers": ["ns_af", "citrix_ns_id"], "server": "netscaler"},
            "ModSecurity": {"headers": ["x-mod-security", "mod_security-message", "x-modsecurity-id"], "text": ["not acceptable", "mod_security"], "server": "mod_security"},
            "Azure WAF": {"headers": ["x-ms-request-id", "x-azure-ref"], "server": "microsoft"},
            "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "server": "sucuri"},
            "Wordfence": {"headers": ["x-wf-pro-id"], "server": "wordfence"}
        }

    def fingerprint(self, url, logger=None):
        findings = []
        if logger: logger(f"WAF Expert: Fingerprinting security stack for {url}...", "INFO")

        try:
            # 1. Passive Fingerprinting (Safe request)
            r = self.session.get(url, timeout=5, verify=False)
            
            detected_waf = None
            found_sigs = []
            
            for name, sig in self.waf_signatures.items():
                match_count = 0
                # Check headers
                for h in sig.get("headers", []):
                    if h.lower() in [key.lower() for key in r.headers.keys()]:
                        match_count += 1
                        found_sigs.append(f"Header: {h}")
                
                # Check server header
                server = r.headers.get("Server", "").lower()
                if sig.get("server") and sig["server"] in server:
                    match_count += 3
                    found_sigs.append(f"Server: {server}")

                # Check body text
                for t in sig.get("text", []):
                    if t.lower() in r.text.lower():
                        match_count += 1
                        found_sigs.append(f"Text: {t}")
                
                if match_count > 0:
                    detected_waf = name
                    break

            # 2. Behavioral Probing (Trigger Request)
            behavioral_match = False
            if not detected_waf or (self.options and self.options.get("deep_waf")):
                payloads = [
                    "/?id=1' OR '1'='1",
                    "/?q=<script>alert(1)</script>",
                    "/?file=../../../../etc/passwd"
                ]
                
                for p in payloads:
                    try:
                        trigger_url = f"{url.rstrip('/')}{p}"
                        r_trigger = self.session.get(trigger_url, timeout=5, verify=False)
                        
                        # WAFs often return 403, 406, 501, 999 or empty response
                        if r_trigger.status_code in [403, 406, 501, 999] or len(r_trigger.content) < len(r.content) * 0.5:
                            behavioral_match = True
                            if not detected_waf:
                                # Try to identify from block page
                                for name, sig in self.waf_signatures.items():
                                    for t in sig.get("text", []):
                                        if t.lower() in r_trigger.text.lower():
                                            detected_waf = name
                                            break
                                    if detected_waf: break
                                
                                if not detected_waf: 
                                    detected_waf = "Generic WAF/IPS (Blocked Probe)"
                            break
                    except Exception:
                        pass

            if detected_waf:
                desc = f"The target is protected by {detected_waf}.\n"
                if found_sigs:
                    desc += f"Detected via: {', '.join(found_sigs)}\n"
                if behavioral_match:
                    desc += "Confirmed via behavioral anomaly/blocking.\n"
                desc += "Adaptive payloads should be used to bypass this layer."

                findings.append({
                    "title": f"Security Infrastructure Detected: {detected_waf}",
                    "description": desc,
                    "severity": "info",
                    "tool_source": "waf_expert",
                    "url": url,
                    "waf_type": detected_waf,
                    "metadata": {
                        "signatures": found_sigs,
                        "behavioral_match": behavioral_match
                    }
                })
                if logger: logger(f"INFO: WAF Detected -> {detected_waf}", "SUCCESS")

        except Exception as e:
            if logger: logger(f"WAF Expert Error: {e}", "DEBUG")
            
        return findings
