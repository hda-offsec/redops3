SCAN_PROFILES = {
    "tcp_scans": {
      "quick_10": {
        "description": "Scan ultra rapide des 10 ports TCP les plus fréquents",
        "args": "-T5 --top-ports 10 -sS",
        "estimated_duration": 5
      },
      "quick_100": {
        "description": "Scan rapide des 100 ports TCP les plus courants",
        "args": "-T4 --top-ports 100 -sS",
        "estimated_duration": 10
      },
      "quick_300": {
        "description": "Scan rapide des 300 ports TCP les plus probables",
        "args": "-T4 --top-ports 300 -sS",
        "estimated_duration": 20
      },
      "quick_1000": {
        "description": "Scan rapide des 1000 ports TCP les plus communs",
        "args": "-T4 --top-ports 1000 -sS",
        "estimated_duration": 30
      },
      "full_tcp": {
        "description": "Scan complet de tous les ports TCP",
        "args": "-T4 -p- -sS",
        "estimated_duration": 90
      },
      "tcp_service_version": {
        "description": "Scan TCP avec détection de services et versions",
        "args": "-sS -sV -T4",
        "estimated_duration": 45
      }
    },
    "udp_scans": {
      "udp_top_100": {
        "description": "Scan UDP des 100 ports les plus utilisés",
        "args": "-sU --top-ports 100 -T4",
        "estimated_duration": 70
      },
      "udp_top_300": {
        "description": "Scan UDP des 300 ports les plus courants",
        "args": "-sU --top-ports 300 -T4",
        "estimated_duration": 120
      },
      "full_udp": {
        "description": "Scan UDP exhaustif sur tous les ports",
        "args": "-sU -p- -T3",
        "estimated_duration": 300
      },
      "udp_detect_services": {
        "description": "Scan UDP avec détection de services et versions",
        "args": "-sU -sV --top-ports 100 -T3",
        "estimated_duration": 100
      }
    },
    "web_scans": {
      "web_ports": {
        "description": "Scan des ports Web typiques (80,443,8080...)",
        "args": "-T4 -p 80,443,8000,8080,8443,8888,3000,5000 -sS -sV",
        "estimated_duration": 25
      },
      "web_detect_vulns": {
        "description": "Scan Web avec détection de vulnérabilités (scripts NSE)",
        "args": "-p 80,443,8080,8443 -sV --script http-vuln* -T4",
        "estimated_duration": 60
      }
    },
    "specialized_scans": {
      "vuln_nse": {
        "description": "Scan vulnérabilités générales avec scripts NSE",
        "args": "-sV --script vuln -T4",
        "estimated_duration": 60
      },
      "os_detect": {
        "description": "Détection de l'OS, version, et services",
        "args": "-O -sV -T3",
        "estimated_duration": 80
      },
      "aggressive": {
        "description": "Scan agressif complet avec scripts et OS",
        "args": "-A -T4",
        "estimated_duration": 100
      },
      "full_optimized": {
        "description": "Scan complet optimisé pour identification",
        "args": "-sS -p- -Pn -vvv -sV --version-all -O --osscan-guess -T3",
        "estimated_duration": 150
      }
    },
    "stealth_scans": {
      "stealth_syn": {
        "description": "Scan SYN furtif (pas de handshake complet)",
        "args": "-sS -T2 -Pn",
        "estimated_duration": 60
      },
      "stealth_fragmented": {
        "description": "Scan furtif avec fragmentation des paquets",
        "args": "-sS -f --data-length 16 -T2 -Pn",
        "estimated_duration": 70
      },
      "decoy_scan": {
        "description": "Scan avec IP leurres pour masquer l'origine",
        "args": "-sS -T3 -D RND:10",
        "estimated_duration": 90
      },
      "recon_only": {
        "description": "Reconnaissance Web uniquement (pas de scan de port)",
        "args": "-sn",
        "estimated_duration": 5
      }
    },
    "custom": {
      "custom_profile": {
        "description": "Scan personnalisé défini par l'utilisateur",
        "args": "",
        "estimated_duration": 0
      }
    }
}
