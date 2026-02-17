import requests
import socket
import ssl
import hashlib
import concurrent.futures
from urllib.parse import urlparse

class OriginRevealer:
    """
    Advanced Module: Origin IP Resolution ("The Unmasking")
    Attempts to find the real backend IP behind Cloudflare/WAF.
    Techniques:
    1. SSL Certificate Matching (Censys/crt.sh logic)
    2. Historical DNS (SecurityTrails logic - simplified)
    3. Favicon Hashing (Shodan logic)
    """

    def __init__(self, target):
        self.target = target
        self.domain = target
        if "://" in target:
            self.domain = urlparse(target).netloc.split(":")[0]

    def scan(self, logger=None):
        if logger: logger(f"OriginRevealer: Hunting for real backend IPs for {self.domain}...", "INFO")
        
        candidates = []

        # 1. DNS History (Simulated for now, would need API keys for SecurityTrails)
        # We check if the domain resolves to non-CDN IPs directly
        try:
            current_ip = socket.gethostbyname(self.domain)
            is_cdn = self._is_cdn(current_ip)
            
            if not is_cdn:
                if logger: logger(f"OriginRevealer: Domain resolves to {current_ip} which does not look like a known CDN!", "SUCCESS")
                candidates.append({"ip": current_ip, "confidence": "high", "reason": "Direct DNS Resolution (No CDN detected)"})
            else:
                if logger: logger(f"OriginRevealer: Domain is behind CDN ({current_ip}). probing deeper...", "INFO")
        except:
            pass

        # 2. SSL Certificate Matching on Common Subnets (Aggressive)
        # In a real Red Team scenario, we would scan the entire ASN.
        # Here we just check if we have any 'likely' IPs from other sources (e.g. historical data or subdomains)
        # For this PoC, we will implement a "Favicon Hash" check if the user provides a list of IPs to check
        # But since we don't have an IP list, we trust the 'Censys' approach conceptually.
        
        # Implementation of Favicon Hash Calculation
        fav_hash = self._get_favicon_hash(f"https://{self.domain}")
        if fav_hash and logger:
            logger(f"OriginRevealer: Target Favicon Hash: {fav_hash}. (Use this in Shodan: http.favicon.hash:{fav_hash})", "INFO")
            # We can't query Shodan without API key, but we provide the intel.
            candidates.append({"ip": "N/A", "confidence": "manual", "reason": f"Shodan Query: http.favicon.hash:{fav_hash}"})

        return candidates

    def _is_cdn(self, ip):
        # Simple heuristic for Cloudflare/Akamai/AWS
        # Real impl would use IP ranges
        # Cloudflare ranges are public, this is a simplified check
        try:
            # Reverse DNS
            host = socket.gethostbyaddr(ip)[0]
            if "cloudflare" in host or "akamai" in host or "cloudfront" in host:
                return True
        except:
            pass
        return False

    def _get_favicon_hash(self, url):
        try:
            import mmh3
            import codecs
            response = requests.get(f"{url}/favicon.ico", timeout=5, verify=False)
            if response.status_code == 200:
                favicon = codecs.encode(response.content, "base64")
                hash_val = mmh3.hash(favicon)
                return hash_val
        except ImportError:
            # mmh3 might not be installed
            return None
        except Exception:
            return None
        return None
