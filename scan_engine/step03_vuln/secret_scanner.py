import re

class SecretScanner:
    def __init__(self):
        # Patterns for common secrets
        self.patterns = {
            "Generic API Key": r"(?:key|api|token|secret|auth|pwd)[-_]?(?:key|api|token|secret|auth|pwd)?[\s:=]+['\"]?([a-zA-Z0-9]{16,})['\"]?",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"['\"]?[0-9a-zA-Z\/+]{40}['\"]?",
            "Slack Token": r"xoxb-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
            "Discord Webhook URL": r"https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
            "Firebase Cloud Messaging Server Key": r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
            "Password in URL": r"[a-zA-Z0-9]+://[a-zA-Z0-9]+:([a-zA-Z0-9!@#$%^&*()_+]+)@[a-zA-Z0-9.]+",
            "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
            "Database Connection String": r"(mongodb(?:\+srv)?|postgres|mysql|redis)://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+]+@[a-zA-Z0-9.-]+"
        }

    def scan_text(self, text, source_info="Unknown"):
        findings = []
        if not text:
            return findings

        for name, pattern in self.patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                secret = match.group(0)
                # Obfuscate secret in finding for report
                obfuscated = secret[:10] + "..." + secret[-4:] if len(secret) > 10 else "****"
                
                findings.append({
                    "title": f"CRITICAL: Secret Leak Detected ({name})",
                    "description": f"A potential secret was discovered in `{source_info}`.\n\nType: {name}\nSecret: `{obfuscated}`\n\nFull Context Snip:\n...{text[max(0, match.start()-50):min(len(text), match.end()+50)]}...",
                    "severity": "critical",
                    "tool_source": "secret_scanner"
                })
        return findings
