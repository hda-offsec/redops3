from core.models import db, Finding, Suggestion

class AnalysisEngine:
    @staticmethod
    def analyze_nmap_results(scan_id, open_ports):
        """
        Analyzes open ports and generates findings and suggestions.
        """
        # Save raw finding
        finding = Finding(
            scan_id=scan_id,
            title=f"Open Ports Detected: {', '.join(str(p['port']) for p in open_ports)}",
            description=f"Nmap discovered {len(open_ports)} open ports.\nDetails: {open_ports}",
            severity="info",
            tool_source="nmap"
        )
        db.session.add(finding)
        
        # Knowledge Base Rules
        for service in open_ports:
            port = service['port']
            name = service['service_name']
            
            # Rule: Web Service
            if port in [80, 443, 8080, 8443] or 'http' in name:
                SuggestionEngine.create(scan_id, "whatweb", f"whatweb http://<target>:{port}", "Web service detected. Fingerprint technologies.")
                SuggestionEngine.create(scan_id, "gobuster", f"gobuster dir -u http://<target>:{port} -w common.txt", "Web service detected. Enumerate directories.")
            
            # Rule: SMB
            if port == 445 or 'smb' in name:
                 SuggestionEngine.create(scan_id, "enum4linux", f"enum4linux -a <target>", "SMB detected. Enumerate shares and users.")
                 
            # Rule: SSH
            if port == 22:
                 SuggestionEngine.create(scan_id, "hydra", f"hydra -l root -P rockyou.txt ssh://<target>", "SSH detected. Check for weak credentials (careful).")
                 
        db.session.commit()

class SuggestionEngine:
    @staticmethod
    def create(scan_id, tool, command, reason):
        s = Suggestion(
            scan_id=scan_id, 
            tool_name=tool, 
            command_suggestion=command, 
            reason=reason
        )
        db.session.add(s)
