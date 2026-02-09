import re

class SecretScanner:
    def __init__(self):
        # EXPERT DICTIONARY: High-fidelity patterns used for Red Teaming
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"['\"]?[0-9a-zA-Z\/+]{40}['\"]?",
            "AWS Session Token": r"FwoGZXIvYXdzE[a-zA-Z0-9\/+]{100,}",
            "Slack Bot Token": r"xoxb-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "Slack User Token": r"xoxp-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "GitHub PAT (Classic)": r"ghp_[a-zA-Z0-9]{36}",
            "GitHub PAT (Fine-grained)": r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
            "Google Cloud API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Google OAuth Client Secret": r"GOCSPX-[a-zA-Z0-9_-]{28}",
            "Firebase Server Key": r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
            "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24}",
            "Twilio Auth Token": r"AC[a-z0-9]{32}.*[a-z0-9]{32}",
            "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "Mailgun API Key": r"key-[a-zA-Z0-9]{32}",
            "Datadog API Key": r"[a-z0-9]{32}",
            "Postman API Key": r"PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34}",
            "DigitalOcean Token": r"dop_v1_[a-z0-9]{64}",
            "Generic Private Key": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
            "Azure Connection String": r"DefaultEndpointsProtocol=http.*AccountKey=[a-zA-Z0-9+/=]{88}",
            "Database Connection": r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql)://[a-zA-Z0-9]{3,}:[a-zA-Z0-9!@#$%^&*()_+]{3,}@[a-zA-Z0-9.-]+",
            "Hardcoded Bearer Token": r"Bearer\s+[a-zA-Z0-9\-\._~+/]+=*",
            "Basic Auth Header": r"Authorization:\s+Basic\s+[a-zA-Z0-9+/=]{10,}",
            "JWT HS256/RS256": r"ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
        }

    def scan_text(self, text, source_info="Unknown"):
        findings = []
        if not text:
            return findings

        for name, pattern in self.patterns.items():
            try:
                matches = re.finditer(pattern, text, re.MULTILINE)
                for match in matches:
                    secret = match.group(0)
                    # Deduplication and length check to avoid noise
                    if len(secret) < 8: continue
                    
                    # Obfuscation for secure reporting
                    obfuscated = secret[:12] + "..." + secret[-4:] if len(secret) > 16 else "****"
                    
                    # Context extraction (100 chars around)
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end].replace('\n', ' ').strip()
                    
                    findings.append({
                        "title": f"CRITICAL: {name} Exposed",
                        "description": (
                            f"A high-value secret `{name}` was discovered in `{source_info}`.\n\n"
                            f"Validated Secret Pattern: `{obfuscated}`\n\n"
                            f"Impact: This credential allows direct unauthorized access to the target's infrastructure or services.\n\n"
                            f"Context Snippet:\n... {context} ..."
                        ),
                        "severity": "critical",
                        "tool_source": "secret_scanner"
                    })
            except Exception: continue
        return findings
