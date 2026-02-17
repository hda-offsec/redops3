import re
import logging

class SensitiveDataMiner:
    """
    Phase 6: Sensitive Data Miner.
    Regex-based extraction of secrets, PII, and credentials.
    Ported from RedOps2 (webscan.py).
    """
    
    PATTERNS = {
        "emails": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "api_keys": r'(?i)(api[_-]?key|secret|token).{0,20}["\']([a-z0-9A-Z_-]{20,})["\']',
        "aws_keys": r'AKIA[0-9A-Z]{16}',
        "jwt_tokens": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        "google_api": r'AIza[0-9A-Za-z-_]{35}',
        "private_keys": r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
        "stripe_keys": r'sk_live_[0-9a-zA-Z]{24}',
        "slack_tokens": r'xox[baprs]-([0-9a-zA-Z]{10,48})',
        "ip_addresses": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    }

    FALSE_POSITIVES = {
        "emails": ['example.com', 'test.com', 'localhost', 'noreply', 'domain.com'],
        "api_keys": ['your_api_key', 'api_key_here', 'placeholder', 'example'],
        "jwt_tokens": ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'] # Common example JWT header
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def scan(self, content, url):
        findings = []
        
        for category, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            unique_matches = set()
            for match in matches:
                # Handle capture groups
                if isinstance(match, tuple):
                    match = next((m for m in match if m), "") # Get first non-empty
                
                match = str(match).strip()
                if not match or len(match) < 6: continue
                
                # Filter false positives
                if self._is_false_positive(category, match):
                    continue
                    
                unique_matches.add(match)
            
            if unique_matches:
                # Limit to 5 per category to avoid spam
                sample = list(unique_matches)[:5]
                findings.append({
                    "type": category,
                    "count": len(unique_matches),
                    "matches": sample,
                    "url": url
                })
        
        return findings

    def _is_false_positive(self, category, match):
        if category in self.FALSE_POSITIVES:
            for fp in self.FALSE_POSITIVES[category]:
                if fp.lower() in match.lower():
                    return True
        return False
