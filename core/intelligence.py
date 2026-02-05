import re

class AttackVectorMapper:
    """
    The Brain of RedOps3.
    Maps discovered services/versions to specific Red Team TTPs and exploitable vectors.
    """

    @staticmethod
    def analyze_service(service_name, version, port):
        vectors = []
        
        service_name = service_name.lower()
        version = version.lower()
        
        # --- HTTP/HTTPS Logic ---
        if 'http' in service_name or port in [80, 443, 8080, 8443]:
            vectors.append({
                "category": "Web",
                "risk": "High",
                "name": "Web Application Surface",
                "description": "Port runs a web server. Potential for SQLi, XSS, RCE.",
                "action": f"Check tech stack (Wappalyzer) and fuzz directories (ffuf). Access: http://<target>:{port}"
            })
            
            if "apache" in version:
                vectors.append({
                    "category": "Web",
                    "risk": "Medium",
                    "name": "Apache Server",
                    "description": f"Apache version '{version}' detected.",
                    "action": "Check for partial content disclosure or mod_cgi vulnerabilities."
                })
                # Specific CVE Check (Example)
                if "2.4.49" in version or "2.4.50" in version:
                    vectors.append({
                        "category": "Exploit",
                        "risk": "CRITICAL",
                        "name": "CVE-2021-41773 (Path Traversal)",
                        "description": "This specific Apache version is vulnerable to RCE via Path Traversal.",
                        "action": "Attempt payload: /cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh"
                    })

            if "iis" in version:
                 vectors.append({
                    "category": "Web",
                    "risk": "Medium",
                    "name": "Microsoft IIS",
                    "description": "Windows IIS Server detected.",
                    "action": "Check for short-filenames (IIS Tilde), ViewState deserialization."
                })

        # --- SMB Logic ---
        if 'smb' in service_name or 'microsoft-ds' in service_name or port == 445:
             vectors.append({
                "category": "Infrastructure",
                "risk": "High",
                "name": "SMB Service",
                "description": "Windows File Sharing exposed.",
                "action": "Run 'crackmapexec smb' to check for SMB Signing (Relay Attack) and Null Sessions."
            })
             
        # --- RDP Logic ---
        if 'ms-wbt-server' in service_name or port == 3389:
             vectors.append({
                "category": "Access",
                "risk": "Medium",
                "name": "RDP Exposed",
                "description": "Remote Desktop Protocol is open.",
                "action": "Check for BlueKeep (if old) or attempt Password Spraying if NLA is disabled."
            })

        # --- SSH Logic ---
        if 'ssh' in service_name or port == 22:
             vectors.append({
                "category": "Access",
                "risk": "Low",
                "name": "SSH Management",
                "description": "SSH is open. Usually requires credentials.",
                "action": "Check for weak algorithmns. If version < 7.7, check user enumeration."
            })

        # --- Database Logic ---
        if 'mysql' in service_name or port == 3306:
             vectors.append({
                "category": "Database",
                "risk": "High",
                "name": "MySQL Exposed",
                "description": "Database directly exposed.",
                "action": "Attempt default creds (root/root). Check for CVE-2012-2122 (Auth Bypass) if very old."
            })
            
        return vectors
