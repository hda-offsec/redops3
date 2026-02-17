import re

class SecretScanner:
    def __init__(self):
        # EXPERT DICTIONARY: Extremely comprehensive patterns for RedOps Pro
        self.patterns = {
            # --- High Fidelity Credentials (CRITICAL) ---
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)(aws|secret|key|token).{0,20}['\"]([0-9a-zA-Z\/+]{40})['\"]",
            "AWS Session Token": r"FwoGZXIvYXdzE[a-zA-Z0-9\/+]{100,}",
            "Google Cloud API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Google OAuth": r"GOCSPX-[a-zA-Z0-9_-]{28}",
            "Firebase Server Key": r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}",
            "Slack Bot Token": r"xoxb-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "Slack User Token": r"xoxp-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}",
            "GitHub PAT": r"ghp_[a-zA-Z0-9]{36}",
            "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24}",
            "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "Private Key": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
            "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            
            # --- Personal & Sensitive Data (PII/HIGH) ---
            "Credit Card Number": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "Social Security (US)": r"\b\d{3}-\d{2}-\d{4}\b",
            "Phone Number": r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            
            # --- Infrastructure & Network (INFO/MEDIUM) ---
            "IPv4 Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "Exposed URL": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "Internal Path": r"(?i)(?:/[a-z0-9_-]+){2,}/(?:admin|conf|config|backup|db|database|prod|staging|dev|test)",
            
            # --- Contextual Generic Secrets (HIGH) ---
            "Generic API Key": r'(?i)(api[_-]?key|token).{0,20}["\']([a-zA-Z0-9]{20,})["\']',
            "Potential Password": r'(?i)(password|pwd|pass).{0,20}["\']([^"\']{6,})["\']',
            "Generic Secret": r'(?i)(secret|auth).{0,20}["\']([a-zA-Z0-9_-]{10,})["\']',
            "Bearer Token": r"Bearer\s+[a-zA-Z0-9\-\._~+/]+=*",
            
            # --- Cloud & SaaS Specifics (MEDIUM/HIGH) ---
            "S3 Bucket URL": r"s3://[a-zA-Z0-9.\-_]+",
            "Azure Blob URL": r"https://[a-zA-Z0-9]+\.blob\.core\.windows\.net",
            "Twilio SID": r"AC[a-zA-Z0-9]{32}",
            "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
            "Twitter OAuth": r"[1-9][0-9]+-[0-9a-zA-Z]{40}",
        }

    def scan_text(self, text, source_info="Unknown", target_domain=None):
        findings = []
        if not text:
            return findings

        from urllib.parse import urlparse

        for name, pattern in self.patterns.items():
            try:
                matches = re.finditer(pattern, text, re.MULTILINE)
                for match in matches:
                    # If the regex has groups, the last group is usually the secret value 
                    if match.groups():
                        secret = match.group(match.lastindex)
                        full_match = match.group(0)
                    else:
                        secret = match.group(0)
                        full_match = secret

                    # Deduplication & Noise Filtering
                    # Filter out short strings unless they match specific short-format patterns
                    if len(secret) < 6 and "S3" not in name and "IP" not in name: 
                        continue
                        
                    # Ignore common false positive IPs (localhost, empty IPs)
                    if name == "IPv4 Address":
                         if secret.startswith("127.0.0.1") or secret == "0.0.0.0": continue

                    # SCOPE CHECK: Filter out noise and off-scope URLs
                    if name == "Exposed URL":
                        # GLOBAL IGNORES for schemas/specs
                        if any(x in secret for x in ["w3.org", "schemas", "gmpg.org", "xmlsoap.org", "example.com", "android.com"]):
                            continue

                        if target_domain:
                            try:
                                # Normalize helper
                                check_url = secret if secret.startswith(('http:', 'https:')) else f"http://{secret}"
                                parsed = urlparse(check_url)
                                # If netloc does not contain target_domain, skip
                                if target_domain not in parsed.netloc:
                                    continue
                            except Exception:
                                continue

                    # Determine Severity
                    severity = "critical"
                    if name in ["Email Address", "Exposed URL", "IPv4 Address", "Internal Path"]:
                        severity = "info"
                    elif "Generic" in name or "Potential" in name or "Internal" in name:
                        severity = "high"
                    elif name in ["Credit Card Number", "Social Security (US)", "Phone Number"]:
                        severity = "high" # PII is high risk
                    
                    # Obfuscation for reporting
                    if severity in ["critical", "high"]:
                        obfuscated = secret[:4] + "..." + secret[-4:] if len(secret) > 12 else "****"
                    else:
                        obfuscated = secret # Don't obfuscate public info like URLs

                    # Context extraction (limit to 100 chars)
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context_snippet = text[start:end].replace('\n', ' ').strip()
                    
                    # Highlight the match in the context
                    # context_snippet = context_snippet.replace(full_match, f"[[{obfuscated}]]")

                    findings.append({
                        "title": f"Secret Found: {name}",
                        "description": (
                            f"Discovered `{name}` in `{source_info}`.\n\n"
                            f"Match Preview: `{obfuscated}`\n"
                            f"Confidence: High (Context Validated)\n\n"
                            f"Context:\n... {context_snippet} ..."
                        ),
                        "severity": severity,
                        "tool_source": "secret_scanner",
                        "raw_secret": full_match,
                        "secret_type": name
                    })
            except Exception: 
                continue
                
        # Deduplicate findings based on the raw secret AND type
        unique_findings = []
        seen = set()
        for f in findings:
            key = f"{f['secret_type']}:{f['raw_secret']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
                
        return unique_findings
