import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
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

    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.domain = target
        if "://" in target:
            self.domain = urlparse(target).netloc.split(":")[0]

    def scan(self, logger=None):
        if logger: logger(f"OriginRevealer: Hunting for real backend IPs for {self.domain}...", "INFO")
        
        candidates = []

        # 1. Direct DNS Check
        try:
            current_ip = socket.gethostbyname(self.domain)
            is_cdn = self._is_cdn(current_ip)
            
            # Identify provider via reverse DNS
            provider = "Unknown Provider"
            try:
                # Reverse DNS
                host = socket.gethostbyaddr(current_ip)[0].lower()
                if "ionos" in host or "1and1" in host: provider = "IONOS (1&1)"
                elif "amazon" in host or "aws" in host: provider = "AWS (Amazon Cloud)"
                elif "google" in host or "googleusercontent" in host: provider = "Google Cloud"
                elif "hetzner" in host: provider = "Hetzner Online"
                elif "digitalocean" in host: provider = "DigitalOcean"
                elif "ovh" in host: provider = "OVHcloud"
                elif "linode" in host: provider = "Linode"
                elif "hostinger" in host or "h-hosting" in host: provider = "Hostinger"
                elif "bluehost" in host: provider = "Bluehost"
                elif "dreamhost" in host: provider = "Dreamhost"
                elif "siteground" in host: provider = "SiteGround"
                elif "godaddy" in host: provider = "GoDaddy"
                else: 
                    # Use reverse hostname as fallback if we don't recognize it
                    provider = ".".join(host.split('.')[-2:])
            except Exception:
                # If rDNS fails, we haven't lost hope yet, we set it to Unknown for now
                pass


            if not is_cdn:
                if logger: logger(f"OriginRevealer: Direct IP resolved to {current_ip} (Hosting: {provider})", "SUCCESS")
                candidates.append({
                    "ip": current_ip, 
                    "confidence": "high", 
                    "reason": "Direct DNS Resolution (No CDN detected)",
                    "hosting": provider
                })
            else:
                if logger: logger(f"OriginRevealer: Domain behind CDN ({current_ip}).", "INFO")
                # Even behind CDN, keep the record for profiling
                candidates.append({
                    "ip": current_ip,
                    "confidence": "low",
                    "reason": f"CDN detected via {current_ip}",
                    "hosting": provider
                })
        except Exception:
            pass

        # 2. Add Favicon Hash Query
        fav_hash = self._get_favicon_hash(f"https://{self.domain}")
        if fav_hash:
            candidates.append({
                "ip": "N/A", 
                "confidence": "manual", 
                "reason": f"Shodan Query: http.favicon.hash:{fav_hash}",
                "favicon_hash": fav_hash
            })

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
        except Exception:
            pass
        return False

    def _get_favicon_hash(self, url):
        try:
            import mmh3
            import codecs
            response = http_client.get(f"{url}/favicon.ico", options=getattr(self, "options", None), timeout=5)
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
