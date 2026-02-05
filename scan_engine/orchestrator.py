import threading
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.helpers.output_parsers import parse_nmap_open_ports
from core.analysis import AnalysisEngine
from datetime import datetime

class ScanOrchestrator:
    def __init__(self, scan_id, target, logger_func, finding_func, suggestion_func, results_func):
        self.scan_id = scan_id
        self.target = target
        self.log = logger_func # callback to log/emit
        self.add_finding = finding_func
        self.add_suggestion = suggestion_func
        self.save_results = results_func

    def run_pipeline(self, profile='quick'):
        """
        Executes the logic pipeline: 
        1. Run Nmap
        2. Parse Results
        3. Analyze & Suggest
        4. Trigger Next Steps (auto-recon logic can go here)
        """
        success = True
        
        try:
            # --- INITIALIZATION: Clear old ghost results ---
            self.log("Initializing local results structure...", "INFO")
            initial_results = {
                "scan_id": self.scan_id,
                "target": self.target,
                "status": "running",
                "phases": {"recon": {"open_ports": [], "raw_output": ""}}
            }
            self.save_results(self.scan_id, initial_results)
            self.log("Local workspace prepared.", "INFO")
        except Exception as e:
            self.log(f"Failed to initialize results: {str(e)}", "ERROR")
            return False

        # --- PHASE 1: Port Scan ---
        self.log(f"Phase 1: Starting Recon (Standard Nmap)...", "INFO")
        scanner = NmapScanner(self.target)

        
        if not scanner.check_tools():
            self.log("CRITICAL: 'nmap' not found in system path! Please install it.", "ERROR")
            return False

        if profile not in ['quick', 'full', 'deep', 'vuln']:
            profile = 'quick'
            
        cmd_list = scanner.command_for_profile(profile)
        self.log(f"Executing: {' '.join(cmd_list)}", "DEBUG")
        
        try:
            stream = scanner.stream_profile(profile)
        except Exception as e:
            self.log(f"Failed to start nmap: {str(e)}", "ERROR")
            return False
            
        output_buffer = []
        for event in stream:
            if event["type"] == "stdout":
                msg = event["line"].strip()
                if msg:
                    self.log(msg, "INFO")
                    output_buffer.append(msg)
            elif event["type"] == "exit":
                self.log(f"Phase 1 finished with exit code {event['code']}", "SUCCESS" if event['code'] == 0 else "WARN")
            elif event["type"] == "error":
                self.log(f"Stream error: {event['message']}", "ERROR")
                return False
            
        full_output = "\n".join(output_buffer)
        
        # --- PHASE 2: Parsing ---
        self.log("Phase 2: Parsing results...", "INFO")
        open_ports = parse_nmap_open_ports(full_output)
        self.log(f"Parsed {len(open_ports)} open ports.", "SUCCESS")
        
        # Save structured results
        results = {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": datetime.utcnow().isoformat(),
            "phases": {
                "recon": {
                    "tool": "nmap",
                    "open_ports": open_ports,
                    "raw_output": full_output
                }
            }
        }
        self.save_results(self.scan_id, results)

        # --- PHASE 3: Deep Analysis & Attack Vector Mapping ---
        self.log("Phase 3: Querying Intelligence Engine for Attack Vectors...", "INFO")
        from core.intelligence import AttackVectorMapper
        
        web_ports = []
        
        if open_ports:
            # Report open ports summary
            self.add_finding(
                title=f"Port Scan Results: {len(open_ports)} Open Ports",
                description=str(open_ports),
                severity="info",
                tool_source="nmap"
            )

            for p in open_ports:
                port = p['port']
                svc = p['service_name']
                ver = p.get('version') or ""
                
                # 1. Identify Web Ports for later phases
                if 'http' in svc or port in [80, 443, 8080, 8443]:
                    web_ports.append(port)

                # 2. Get Expert Analysis
                vectors = AttackVectorMapper.analyze_service(svc, ver, port)
                
                for v in vectors:
                    # Log actionable intelligence
                    self.log(f"[{v['category']}] {v['name']} detected on port {port}", "WARN" if v['risk'] in ['High', 'CRITICAL'] else "INFO")
                    
                    # Create highly specific suggestions/findings
                    self.add_finding(
                        title=f"{v['name']} (Port {port})",
                        description=f"{v['description']}\n\nACTIONABLE INTEL:\n{v['action']}",
                        severity=v['risk'].lower(),
                        tool_source="RedOps-Intel"
                    )
                    
                    # Convert action to suggestion if possible (simplified for now)
                    self.add_suggestion(
                        tool_name="Assessment",
                        command_suggestion=v['action'],
                        reason=f"Vector: {v['name']}"
                    )
        
        # --- PHASE 4: Auto-Enumeration (Web) ---
        if web_ports:
            self.log(f"Phase 4: Starting Auto-Recon for {len(web_ports)} web ports...", "INFO")
            from scan_engine.step02_enum.web_scanner import WebReconScanner
            
            web_scanner = WebReconScanner(self.target)
            if not web_scanner.check_tools():
                self.log("Skipping Web Recon: 'whatweb' not installed.", "WARN")
            else:
                for port in web_ports:
                    proto = 'https' if port in [443, 8443] else 'http'
                    self.log(f"Fingerprinting {proto}://{self.target}:{port} with WhatWeb...", "INFO")
                    
                    try:
                        ww_stream = web_scanner.stream_whatweb(port, proto)
                        ww_output = []
                        for event in ww_stream:
                            if event["type"] == "stdout":
                                msg = event["line"].strip()
                                if msg:
                                    self.log(msg, "INFO")
                                    ww_output.append(msg)
                            elif event["type"] == "exit":
                                self.log(f"WhatWeb on port {port} finished with code {event['code']}", "INFO")
                        
                        # Save findings from WhatWeb (simple Parsing)
                        full_ww = "\n".join(ww_output)
                        if "Title" in full_ww or "HTTPServer" in full_ww:
                            self.add_finding(
                                title=f"Web Tech Stack ({port})",
                                description=f"WhatWeb Output:\n{full_ww}",
                                severity="low",
                                tool_source="whatweb"
                            )
                            # Add to detailed results
                            if 'enum' not in results['phases']: results['phases']['enum'] = {}
                            if 'whatweb' not in results['phases']['enum']: results['phases']['enum']['whatweb'] = {'summary': {}}
                            
                            results['phases']['enum']['whatweb'][str(port)] = full_ww
                            self.save_results(self.scan_id, results) # Update results incrementally

                    except Exception as e:
                        self.log(f"Error during Web Recon on port {port}: {str(e)}", "ERROR")
        
        # --- PHASE 5: Automated Vulnerability Scanning (Nuclei) ---
        if web_ports:
            self.log(f"Phase 5: Starting Vulnerability Assessment for {len(web_ports)} targets...", "INFO")
            from scan_engine.step03_vuln.nuclei_scanner import NucleiScanner
            
            vuln_scanner = NucleiScanner(self.target)
            if not vuln_scanner.check_tools():
                self.log("Skipping Vuln Scan: 'nuclei' not installed. Install with 'brew install nuclei'", "WARN")
                # Add Suggestion to install
                self.add_suggestion(
                     tool_name="setup",
                     command_suggestion="brew install nuclei",
                     reason="Automated vulnerability assessment tool missing"
                )
            else:
                 for port in web_ports:
                    proto = 'https' if port in [443, 8443] else 'http'
                    self.log(f"Nuclei Scanning {proto}://{self.target}:{port}...", "INFO")
                    
                    try:
                        nuc_stream = vuln_scanner.stream_vuln_scan(port, proto)
                        
                        vuln_count = 0
                        for event in nuc_stream:
                            if event["type"] == "stdout":
                                line = event["line"].strip()
                                if line:
                                    # Nuclei format: [dns-waf-detect] [medium] ...
                                    # We'll try to guess severity by checking string
                                    sev = "info"
                                    if "[critical]" in line.lower(): sev = "critical"
                                    elif "[high]" in line.lower(): sev = "high"
                                    elif "[medium]" in line.lower(): sev = "medium"
                                    elif "[low]" in line.lower(): sev = "low"
                                    
                                    self.log(line, "WARN" if sev in ["critical", "high"] else "INFO")
                                    
                                    # Add finding if >= medium
                                    if sev in ["critical", "high", "medium"]:
                                        vuln_count += 1
                                        self.add_finding(
                                            title=f"Vulnerability Found ({sev.upper()})",
                                            description=f"Nuclei Output:\n{line}",
                                            severity=sev,
                                            tool_source="nuclei"
                                        )
                                        # Add to detailed results structure
                                        if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                                        if 'nuclei' not in results['phases']['vuln']: results['phases']['vuln']['nuclei'] = {'findings': []}
                                        
                                        results['phases']['vuln']['nuclei']['findings'].append({
                                            "severity": sev,
                                            "title": line,
                                            "port": port
                                        })
                                        self.save_results(self.scan_id, results)
                            elif event["type"] == "exit":
                                self.log(f"Nuclei on port {port} finished with code {event['code']}", "INFO")

                        if vuln_count > 0:
                            self.log(f"Alert: {vuln_count} vulnerabilities identified on port {port}!", "ERROR")
                        else:
                            self.log(f"No critical vulnerabilities found on port {port}.", "SUCCESS")
                            
                    except Exception as e:
                        self.log(f"Error during Vuln Scan on port {port}: {str(e)}", "ERROR")

        # --- PHASE 6: Automated Dirbusting (ffuf) ---
        if web_ports:
            self.log("Phase 6: Starting Automated Dirbusting (ffuf)...", "INFO")
            from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner
            import os
            
            # Default wordlist path
            wordlist = os.path.join(os.getcwd(), "data", "wordlists", "common.txt")
            if not os.path.exists(wordlist):
                # Create a minimal wordlist if it doesn't exist
                os.makedirs(os.path.dirname(wordlist), exist_ok=True)
                with open(wordlist, "w") as f:
                    f.write("admin\nlogin\napi\nrobots.txt\n.env\n.git\ndashboard\n")
            
            for port in web_ports:
                proto = 'https' if port in [443, 8443] else 'http'
                target_url = f"{proto}://{self.target}:{port}"
                self.log(f"Fuzzing {target_url}...", "INFO")
                
                scanner6 = FfufScanner(target_url, wordlist)
                if not scanner6.check_tools():
                    self.log("Skipping ffuf: tool not installed.", "WARN")
                    break # Usually either it's installed or not for all ports
                
                try:
                    ffuf_stream = scanner6.stream_scan()
                    found_items = []
                    
                    for event in ffuf_stream:
                        if event["type"] == "stdout":
                            line = event["line"].strip()
                            if line:
                                # Simple check for success (ffuf output with -s is usually just the found path)
                                # But let's be safe, if it contains '200' or similar headers
                                # Actually with -s it just prints the findings
                                self.log(f"[DIR] Found: {line}", "WARN")
                                found_items.append(line)
                                
                                # Add finding for each discovery
                                self.add_finding(
                                    title=f"Directory Discovered: {line}",
                                    description=f"Endpoint found during fuzzing of {target_url}",
                                    severity="low",
                                    tool_source="ffuf"
                                )
                        elif event["type"] == "exit":
                             self.log(f"ffuf for {target_url} finished with code {event['code']}", "INFO")

                    if found_items:
                        if 'dirbusting' not in results['phases']: 
                            results['phases']['dirbusting'] = {'ffuf': {'endpoints': []}}
                        
                        for item in found_items:
                            # Attempt to clean / leading if present
                            clean_item = item.lstrip('/')
                            results['phases']['dirbusting']['ffuf']['endpoints'].append({
                                "path": clean_item,
                                "status": "200", # ffuf with -s only shows successful hits
                                "size": "N/A"
                            })
                        
                        self.save_results(self.scan_id, results)

                except Exception as e:
                    self.log(f"Error during ffuf scan on port {port}: {str(e)}", "ERROR")

        return success
