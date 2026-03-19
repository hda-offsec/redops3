import shlex
import logging
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)

NMAP_PROFILES = {
    "recon_rapide": {
        "name": "Recon rapide",
        "args": "-Pn -T4 --top-ports 1000 -sS -sV",
        "description": "Découverte rapide: hôtes vivants, ports ouverts, services, versions."
    },
    "aggressive_intel": {
        "name": "Intelligence Agressive",
        "args": "-Pn -A -T4 -v",
        "description": "Scan agressif complet: OS detection, versioning, scripts et traceroute."
    },
    "recon_services_avance": {
        "name": "Recon services avancé",
        "args": "-Pn -T4 -sS -sV --version-intensity 7",
        "description": "Fingerprint précis des services avec intensité élevée."
    },
    "os_fingerprint": {
        "name": "OS fingerprint",
        "args": "-Pn -O --osscan-guess",
        "description": "Identification du système d'exploitation par analyse de stack TCP/IP."
    },
    "vuln_vulners": {
        "name": "Audit de Vulnérabilités (Vulners)",
        "args": "-Pn -sV --script vulners",
        "description": "Corrélation des versions détectées avec les CVE connues via Vulners."
    },
    "recon_approfondi": {
        "name": "Recon approfondi",
        "args": "-Pn -sS -sV -O -p-",
        "description": "Scan complet de tous les ports TCP (1-65535)."
    },
    "udp_discovery": {
        "name": "Découverte UDP",
        "args": "-Pn -sU --top-ports 100 -T4",
        "description": "Scan UDP sur les 100 ports les plus communs."
    },
    "web_surface": {
        "name": "Analyse de Surface Web",
        "args": "-Pn -p 80,443,8000,8080,8443,9000 -sV --script http-title,http-methods,http-enum",
        "description": "Focus sur les services web et extraction de métadonnées HTTP."
    },
    "ssl_deep_audit": {
        "name": "Audit SSL/TLS Approfondi",
        "args": "-Pn -p 443,8443 --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed",
        "description": "Audit approfondi de la configuration SSL/TLS et recherche de failles critiques."
    },
    "smb_ad_discovery": {
        "name": "Énumération SMB/AD",
        "args": "-Pn -p 135,139,445 -sV --script smb-os-discovery,smb-enum-shares",
        "description": "Énumération des services SMB et identification de domaine/OS."
    },
    "nse_recon": {
        "name": "NSE reconnaissance",
        "args": "-Pn --script default,safe",
        "description": "Scripts NSE standards catégorisés comme 'safe'."
    },
    "nse_vuln": {
        "name": "NSE vuln",
        "args": "-Pn --script vuln",
        "description": "Scripts NSE de détection de vulnérabilités connues."
    }
}

INCOMPATIBLE_FLAGS = [
    ("-sT", "-sS"),
    ("-sU", "-sS"),
    ("-sU", "-sT"),
    ("-sN", "-sS"),
    ("-sF", "-sS"),
]

def validate_nmap_profile(profile_args):
    """
    Validateur pour les arguments Nmap.
    Empêche les combinaisons incompatibles et assainit les arguments.
    """
    args = profile_args.split()
    
    # Check for incompatible flags
    for flag1, flag2 in INCOMPATIBLE_FLAGS:
        if flag1 in args and flag2 in args:
            raise ValueError(f"Incompatible Nmap flags: {flag1} and {flag2}")
            
    # Sanitize: ensure no injection
    sanitized_args = []
    for arg in args:
        if any(c in arg for c in [';', '&', '|', '>', '<', '$', '(', ')']):
            logger.warning(f"Sanitized suspicious argument: {arg}")
            continue
        sanitized_args.append(arg)
        
    return " ".join(sanitized_args)

class NmapScannerAdvanced:
    def __init__(self, target, orchestrator=None):
        self.target = target
        self.orchestrator = orchestrator

    def run_profile(self, profile_name):
        if profile_name not in NMAP_PROFILES:
            raise ValueError(f"Unknown Nmap profile: {profile_name}")
            
        profile = NMAP_PROFILES[profile_name]
        args = profile["args"]
        
        # Validation
        try:
            validated_args = validate_nmap_profile(args)
        except ValueError as e:
            if self.orchestrator:
                self.orchestrator.log(f"Validation Error: {str(e)}", "ERROR")
            raise

        logger.info(f"Running Nmap {profile_name} on {self.target}")
        if self.orchestrator:
            self.orchestrator.log(f"ScanNmap: Launching profile {profile['name']}...", "INFO")
            
        # We want XML output for parsing
        cmd_list = ["nmap"] + validated_args.split() + [self.target, "-oX", "-"]
        
        return ProcessManager.stream_command(cmd_list)
