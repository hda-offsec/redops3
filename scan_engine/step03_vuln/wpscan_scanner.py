import os
import shutil
from scan_engine.helpers.process_manager import ProcessManager

class WPScanScanner:
    WPSCAN_CACHE_DIR = "/tmp/wpscan/cache"

    def __init__(self, target):
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

    def stream_scan(self, port, protocol='http', enumerate_all=False):
        """Scanner un site Wordpress en streaming"""
        # Purge stale cache to prevent disk-full crashes
        self._purge_cache()
        url = f"{protocol}://{self.target}:{port}"
        
        # Commande wpscan de base
        # --random-user-agent : Eviter le blocage basique
        # --format json : On recevra du JSON pour un parsing plus facile, ou cli pour streaming
        # Pour le streaming live on va rester sur le format par defaut (cli) qui est plus parlant
        # on peut ajouter --no-banner pour cleaner
        
        enum_flags = "vp,vt,u1-20" if enumerate_all else "p,t,u"
        
        scan_args = [
            "wpscan",
            "--url", url,
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks", # Souvent utile
            "--enumerate", enum_flags, # Plugins, themes, users (plus complet si enumerate_all)
        ]
        
        return ProcessManager.stream_command(scan_args)
