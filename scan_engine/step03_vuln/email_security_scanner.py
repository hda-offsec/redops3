import dns.resolver

class EmailSecurityScanner:
    def __init__(self, target):
        self.target = target

    def scan_email_security(self, logger=None):
        findings = []
        domain = self.target
        
        if logger: logger(f"📧 Email Sec: Auditing SPF/DMARC for {domain}...", "INFO")

        try:
            # 1. SPF Check
            # Check TXT records
            spf_record = None
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if txt.startswith("v=spf1"):
                        spf_record = txt
                        break
            except Exception:
                spf_record = None

            if not spf_record:
                findings.append({
                    "title": "High: Missing SPF Record",
                    "description": f"Domain `{domain}` has no SPF record. Attackers can easily spoof emails from this domain.",
                    "severity": "high",
                    "tool_source": "email_scanner"
                })
            elif "~all" in spf_record or "+all" in spf_record:
                 findings.append({
                    "title": "Medium: Weak SPF Configuration",
                    "description": f"SPF record allows soft fail (~all) or all (+all). Spoofing might be possible.\nRecord: `{spf_record}`",
                    "severity": "medium",
                    "tool_source": "email_scanner"
                })

            # 2. DMARC Check (dmarc.domain)
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_record = None
            try:
                answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if txt.startswith("v=DMARC1"):
                        dmarc_record = txt
                        break
            except Exception:
                dmarc_record = None

            if not dmarc_record:
                findings.append({
                    "title": "High: Missing DMARC Record",
                    "description": f"Domain `{domain}` has no DMARC record. This prevents enforcement of SPF/DKIM policies.",
                    "severity": "high",
                    "tool_source": "email_scanner"
                })
            elif "p=none" in dmarc_record:
                 findings.append({
                    "title": "Medium: DMARC Policy is 'None'",
                    "description": f"DMARC policy is set to `none`. It monitors but does not block spoofed emails.\nRecord: `{dmarc_record}`",
                    "severity": "medium",
                    "tool_source": "email_scanner"
                })

        except Exception as e:
            if logger: logger(f"Email security check error: {e}", "DEBUG")
            
        return findings
