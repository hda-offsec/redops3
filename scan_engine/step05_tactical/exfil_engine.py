import re
import hashlib

class ExfiltrationEngine:
    """
    Automated PII & Sensitive Data Exfiltration Engine.
    Analyzes 'Loot' and 'Evidence' to score impact and extract verified samples.
    """
    
    PII_SIGNATURES = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
        "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        "jwt": r'ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        "private_key": r'-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----'
    }

    def __init__(self, options=None):
        self.options = options or {}

    def score_loot(self, content, source_url=None):
        """Analyze content and return a detailed risk score with samples."""
        matches = {}
        total_score = 0
        
        for pii_type, pattern in self.PII_SIGNATURES.items():
            found = re.findall(pattern, content)
            if found:
                matches[pii_type] = {
                    "count": len(found),
                    "samples": self._mask_samples(list(set(found))[:3]) # Only 3 samples
                }
                # Scoring weights
                if pii_type == "private_key": total_score += 100
                elif pii_type == "credit_card": total_score += 50 * len(found)
                elif pii_type == "ssn": total_score += 40 * len(found)
                elif pii_type == "jwt": total_score += 20 * len(found)
                elif pii_type == "email": total_score += 5 * len(found)

        if not matches:
            return None

        severity = "info"
        if total_score > 200: severity = "critical"
        elif total_score > 100: severity = "high"
        elif total_score > 50: severity = "medium"

        return {
            "title": f"Data Exfiltration: {severity.upper()} Impact PII Leaked",
            "description": f"Sensitive data identified in exfiltration artifacts from {source_url or 'Target'}.",
            "severity": severity,
            "pii_matches": matches,
            "risk_score": total_score,
            "tool_source": "exfil_engine"
        }

    def _mask_samples(self, samples):
        masked = []
        for s in samples:
            if len(s) > 8:
                masked.append(s[:4] + "****" + s[-4:])
            else:
                masked.append("****")
        return masked
