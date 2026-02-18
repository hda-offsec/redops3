import shlex
import threading
import os
from datetime import datetime
from core.models import Scan, db
from core.scan_profiles import SCAN_PROFILES
from scan_engine.helpers.output_parsers import parse_nmap_open_ports
from scan_engine.helpers.process_manager import ProcessManager

# Phase Imports
from scan_engine.phases.recon import run_recon, run_dns_osint
from scan_engine.phases.intel import run_intel
from scan_engine.phases.enum import run_enum
from scan_engine.phases.vuln import run_vuln_scans, run_global_vuln_scans
from scan_engine.phases.dirbusting import run_dirbusting
from scan_engine.phases.utils import emit_progress

class ScanOrchestrator:
    def __init__(self, scan_id, target, logger_func, finding_func, suggestion_func, results_func, loot_func=None, recursion_func=None, options=None):
        self.scan_id = scan_id
        self.target = target
        self.log = logger_func 
        self.add_finding = finding_func
        self.add_suggestion = suggestion_func
        self.save_results = results_func
        self.add_loot = loot_func
        self.recursion_func = recursion_func  # New callback for spawning child scans
        self.options = options or {}

    def run_pipeline(self, profile='quick'):
        """
        Executes the logic pipeline: 
        1. Recon (Nmap, DNS, OSINT)
        2. Intel (Attack Vectors, Screenshots)
        3. Enumeration (Web, WAF, API, JS)
        4. Vulnerability (Nuclei, WPScan, Exploits)
        """
        success = True
        start_time = datetime.utcnow()
        
        try:
            # Initialize Results Structure
            results = {
                "scan_id": self.scan_id,
                "target": self.target,
                "status": "running",
                "timestamp": start_time.isoformat(),
                "commands": [],
                "phases": {
                    "recon": {"open_ports": [], "raw_output": ""},
                    "dns": {"subdomains": []},
                    "intel": {},
                    "osint": {
                        "cloud": [], "favicon": {}, "github": [], "emails": [], "dorks": [], "origin_ips": []
                    },
                    "enum": {
                        "whatweb": {"summary": {}}, "katana": {}, "waf": {}, "arjun": {}, "js_secrets": [], "api": {}, "headers": {}
                    },
                    "vuln": {
                        "nuclei": {"findings": []}, "takeover": [], "wpscan": {}, "wordpress": {}, "git": [], "backups": [], "graphql": [], "ssrf": [], "js_vulns": [], "xss": [], "redirects": [], "tech": []
                    },
                    "dirbusting": {
                        "ffuf": {"endpoints": []}
                    },
                },
                "target_info": {"wordlist": "common.txt"}
            }
            # Attach results to self for phases to modify
            self.results = results
            self.save_results(self.scan_id, self.results, overwrite=True)

            # --- PHASE 1: RECONNAISSANCE ---
            # Nmap & Port Discovery
            # (Fallback logic is handled inside run_recon)
            open_ports = run_recon(self)
            
            if not open_ports:
                self.log("No open ports found. Aborting deep scan phases.", "WARN")
                success = False
                # Continue to OSINT/DNS though? 
                # Original logic didn't abort fully, but let's proceed to DNS/OSINT mainly.
            
            # DNS & OSINT
            run_dns_osint(self)
            
            # --- PHASE 2: INTELLIGENCE ---
            # Attack Vectors & Screenshots
            run_intel(self)

            # --- PHASE 3 & 4: ENUMERATION & VULN SCANNING ---
            # Iterate over open ports
            if open_ports:
                web_ports_count = 0
                for p_info in open_ports:
                    port = p_info['port']
                    svc = p_info.get('service_name', '').lower()
                    
                    # Identify Proto
                    proto = 'https' if port in [443, 8443] or 'ssl' in svc else 'http'
                    if port == 80: proto = 'http'
                    
                    # Logic to determine if we should scan this port as web
                    is_web = 'http' in svc or port in [80, 443, 8080, 8443]
                    
                    if is_web:
                        web_ports_count += 1
                        emit_progress(self, 60, f"Enumerating Port {port}")
                        
                        # ENUMERATION
                        fingerprint = run_enum(self, port, proto)
                        
                        # VULNERABILITY
                        run_vuln_scans(self, port, proto, fingerprint_data=fingerprint)

                if web_ports_count == 0:
                     self.log("No web ports identified for detailed enumeration.", "INFO")

            # --- PHASE 5: GLOBAL VULNERABILITY SCANS ---
            run_global_vuln_scans(self)
            
            # --- PHASE 6: RECURSIVE DIRECTORY BUSTING ---
            run_dirbusting(self)

            # --- PHASE 7: RECURSIVE SUBDOMAIN SCAN (New) ---
            # Check for 'recursive' (UI checkbox) or 'recurse_subdomains' (Internal/API)
            should_recurse = self.options.get('recursive', False) or self.options.get('recurse_subdomains', False)
            
            if should_recurse and self.recursion_func:
                subdomains = self.results.get('phases', {}).get('dns', {}).get('subdomains', [])
                if subdomains:
                     self.log(f"Recursion Enabled: Scheduling scans for {len(subdomains)} subdomains...", "INFO")
                     self.recursion_func(
                         subdomains=subdomains,
                         parent_scan_id=self.scan_id,
                         current_depth=self.options.get('current_recursion_depth', 0),
                         max_depth=self.options.get('max_recursion_depth', 1)
                     )
            
        except Exception as e:
            self.log(f"Pipeline Critical Failure: {e}", "ERROR")
            success = False
        
        # FINALIZATION
        end_time = datetime.utcnow()
        duration = end_time - start_time
        
        emit_progress(self, 100, "Completed")
        self.results['status'] = "completed" if success else "failed"
        self.save_results(self.scan_id, self.results)
        
        self.log(f"Scan completed in {duration}. Status: {self.results['status']}", "SUCCESS")
        return success
