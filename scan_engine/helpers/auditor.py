import hashlib
from urllib.parse import urlparse
import scan_engine.helpers.http_client as http_client

class VulnerabilityAuditor:
    """
    Centralized validation engine to eliminate false positives
    and handle cross-protocol (80/443) finding duplications.
    """
    
    @staticmethod
    def get_baseline(url, options=None):
        """Fetches the baseline response for an endpoint (without payload)."""
        try:
            r = http_client.get(url, options=options, timeout=5, allow_redirects=True)
            return {"status": r.status_code, "text": r.text, "headers": r.headers}
        except Exception:
            return {"status": 0, "text": "", "headers": {}}

    @staticmethod
    def is_anomaly(baseline, response, signatures=None, require_status=200):
        """
        Validates a finding based on strict differential logic.
        1. Must match required status code (usually 200).
        2. Must NOT be an exact text match to the baseline.
        3. If signatures are provided, at least one must be in the response, but NOT in the baseline.
        """
        if response is None:
            return False
            
        if require_status and response.status_code != require_status:
            return False

        # If the page hasn't changed at all, the payload was ignored (False Positive)
        if baseline.get("text") == response.text:
            return False

        if not signatures:
            # If no specific signature, just being different is the anomaly
            return True

        response_low = response.text.lower()
        baseline_low = baseline.get("text", "").lower()

        for sig in signatures:
            sig_low = sig.lower()
            if sig_low in response_low and sig_low not in baseline_low:
                return True
                
        return False

    @staticmethod
    def deduplicate_findings(findings):
        """
        Removes identical vulnerabilities reported on both port 80 and 443.
        Prefers the HTTPS (443) finding if both exist.
        Base comparison on: url path, query parameters, tool_source, and title.
        """
        if not findings:
            return []

        unique_findings = {}
        
        for f in findings:
            # Safely extract URL or use a fallback
            url_str = f.get('url') or f.get('raw_loot') or ""
            
            if not url_str:
                # If finding has no URL, group by title
                fingerprint_hash = hashlib.md5(f.get('title', '').encode()).hexdigest()
                unique_findings[fingerprint_hash] = f
                continue

            parsed = urlparse(url_str)
            
            # Normalize the identifier: ignore scheme and port
            # e.g., /admin/dashboard?id=1|lfi_scanner|CRITICAL: LFI Detected
            norm_netloc = parsed.hostname or parsed.netloc.split(':')[0]
            norm_url = f"{norm_netloc}{parsed.path}?{parsed.query}"
            
            # Create a unique fingerprint for this specific vulnerability instance
            fingerprint = f"{norm_url}|{f.get('tool_source', '')}|{f.get('title', '')}"
            fingerprint_hash = hashlib.md5(fingerprint.encode()).hexdigest()
            
            if fingerprint_hash in unique_findings:
                # If we already have this finding, check if the current one is HTTPS
                existing_f = unique_findings[fingerprint_hash]
                existing_url = existing_f.get('url') or existing_f.get('raw_loot') or ""
                
                # Replace HTTP with HTTPS finding
                if url_str.startswith('https://') and existing_url.startswith('http://'):
                    unique_findings[fingerprint_hash] = f
            else:
                unique_findings[fingerprint_hash] = f
                
        return list(unique_findings.values())
