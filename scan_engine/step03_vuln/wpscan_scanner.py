from scan_engine.helpers.process_manager import ProcessManager

class WPScanScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        """Verifier que wpscan est installé"""
        return ProcessManager.find_binary_path("wpscan") is not None

    def stream_scan(self, port, protocol='http'):
        """Scanner un site Wordpress en streaming"""
        url = f"{protocol}://{self.target}:{port}"
        
        # Commande wpscan de base
        # --random-user-agent : Eviter le blocage basique
        # --format json : On recevra du JSON pour un parsing plus facile, ou cli pour streaming
        # Pour le streaming live on va rester sur le format par defaut (cli) qui est plus parlant
        # on peut ajouter --no-banner pour cleaner
        
        scan_args = [
            "wpscan",
            "--url", url,
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks", # Souvent utile
            "--enumerate", "p,t,u", # Plugins, themes, users
        ]
        
        return ProcessManager.stream_command(scan_args)
