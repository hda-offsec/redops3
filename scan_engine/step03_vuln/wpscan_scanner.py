import os
import shutil
from scan_engine.helpers.process_manager import ProcessManager

class WPScanScanner:
    WPSCAN_CACHE_DIR = "/tmp/wpscan/cache"

    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def check_tools(self):
        """Verifier que wpscan est installé"""
        return ProcessManager.find_binary_path("wpscan") is not None

    @staticmethod
    def _purge_cache():
        """Purge the WPScan cache to prevent 'No space left on device' errors."""
        try:
            if os.path.isdir(WPScanScanner.WPSCAN_CACHE_DIR):
                shutil.rmtree(WPScanScanner.WPSCAN_CACHE_DIR, ignore_errors=True)
        except Exception:
            pass

    def detect_wordfence(self, port, protocol='http'):
        """Detect if Wordfence is present on the target."""
        import scan_engine.helpers.http_client as http_client
        url = f"{protocol}://{self.target}:{port}"
        try:
            # Wordfence often leaves traces in headers or specific paths
            resp = http_client.get(url, options=getattr(self, "options", None), timeout=5, allow_redirects=True)
            headers_str = str(resp.headers).lower()
            cookies_str = str(resp.cookies).lower()
            
            # 1. Header checks
            if 'x-wf-id' in headers_str or 'wordfence' in headers_str:
                return True
            
            # 2. Cookie checks
            if 'wf_log_human' in cookies_str or 'wordfence' in cookies_str:
                return True
            
            # 3. Static path check (lightweight)
            wf_path = f"{url}/wp-content/plugins/wordfence/readme.txt"
            wf_resp = http_client.head(wf_path, options=getattr(self, "options", None), timeout=3)
            if wf_resp.status_code == 200:
                return True
                
        except Exception:
            pass
        return False

    def stream_scan(self, port, protocol='http', enumerate_all=False, stealth=False):
        """Scanner un site Wordpress en streaming"""
        # Purge stale cache to prevent disk-full crashes
        self._purge_cache()
        url = f"{protocol}://{self.target}:{port}"
        
        enum_flags = "vp,vt,u1-20" if enumerate_all else "p,t,u"
        
        scan_args = [
            "wpscan",
            "--url", url,
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks",
            "--enumerate", enum_flags,
        ]

        if stealth:
            # Wordfence Evasion: Throttling & Jittering
            # --throttle : Msec to wait between requests
            # --request-timeout : Seconds to wait for a request to complete
            scan_args.extend([
                "--throttle", "500",      # 0.5s delay between requests
                "--connect-timeout", "10",
                "--request-timeout", "20"
            ])
        
        return ProcessManager.stream_command(scan_args)
