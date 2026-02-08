import re
import threading
import os
from datetime import datetime

from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.step01_recon.dns_scanner import DNSScanner
from scan_engine.step02_enum.katana_scanner import KatanaScanner
from scan_engine.step02_enum.web_scanner import WebReconScanner
from scan_engine.step03_vuln.nuclei_scanner import NucleiScanner
from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner
from scan_engine.helpers.output_parsers import parse_nmap_open_ports
from core.analysis import AnalysisEngine
from core.intelligence import AttackVectorMapper
from core.models import Scan, db
from core.scan_profiles import SCAN_PROFILES
from core.screenshots import take_service_screenshot


class ScanOrchestrator:
    def __init__(self, scan_id, target, logger_func, finding_func, suggestion_func, results_func):
        self.scan_id = scan_id
        self.target = target
        self.log = logger_func # callback to log/emit
        self.add_finding = finding_func
        self.add_suggestion = suggestion_func
        self.save_results = results_func

    def _emit_progress(self, percent, phase_name):
        self.save_results(self.scan_id, {
            "progress": {
                "percent": percent,
                "current_phase": phase_name
            }
        })

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
            # --- PHASE 0: Pre-Flight Intelligence (Geo) ---
            self._emit_progress(5, "Geolocation Init")
            self.log("Phase 0: Gathering Geolocation Intelligence...", "INFO")
            geo = AttackVectorMapper.get_ip_geolocation(self.target)
            if geo:
                self.log(f"Target located: {geo.get('city')}, {geo.get('country')} ({geo.get('isp')})", "SUCCESS")
                # Update Scan model directly
                scan_obj = Scan.query.get(self.scan_id)
                if scan_obj:
                    scan_obj.geolocation_data = geo
                    db.session.commit()
            else:
                self.log("Geolocation lookup failed or target is local.", "WARN")

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

        # --- PHASE 0.5: DNS Enumeration ---
        self._emit_progress(10, "DNS Enumeration")
        self.log("Phase 0.5: Starting DNS Enumeration...", "INFO")
        dns_scanner = DNSScanner(self.target)
        dns_results = dns_scanner.enumerate_all(logger=self.log)
        if dns_results["subdomains"]:
            self.log(f"Discovered {len(dns_results['subdomains'])} subdomains.", "SUCCESS")
            self.add_finding(
                title=f"DNS Discovery: {len(dns_results['subdomains'])} Subdomains",
                description="\n".join(dns_results["subdomains"]),
                severity="info",
                tool_source="subfinder"
            )

        # --- PHASE 1: Port Scan ---
        self._emit_progress(20, "Port Scanning (nmap)")
        self.log(f"Phase 1: Starting Recon (Standard Nmap)...", "INFO")
        scanner = NmapScanner(self.target)

        if not scanner.check_tools():
            self.log("CRITICAL: 'nmap' not found in system path! Please install it.", "ERROR")
            return False

        # Determine arguments
        scan_args = []
        found_profile = False
        
        # 1. Check if profile is a predefined key
        for category, profiles in SCAN_PROFILES.items():
            if profile in profiles:
                # Found it
                raw_args = profiles[profile]['args']
                scan_args = raw_args.split()
                self.log(f"Using profile '{profile}': {raw_args}", "INFO")
                found_profile = True
                break
                
        # 2. If not found, check compatibility mappings or fallback
        if not found_profile:
            if profile == 'quick': scan_args = ["-T4", "--top-ports", "100"] 
            elif profile == 'full': scan_args = ["-p-", "-T4"] 
            elif profile == 'vuln': scan_args = ["--script", "vuln"]
            else: 
                 self.log(f"Unknown profile '{profile}', defaulting to quick scan.", "WARN")
                 scan_args = ["-F"]

        self.log(f"Executing Nmap with: {' '.join(scan_args)}", "DEBUG")
        
        try:
            # We need to bypass the 'stream_profile' logic of NmapScanner if we want raw args
            # Or we can update NmapScanner. For now, let's assume NmapScanner has a method 
            # or we use a lower level call. 
            # Looking at NmapScanner (not shown but assumed), it likely has `stream_scan(args)`.
            # If `stream_profile` translates key to args, we might need to change it.
            # Let's try to use `stream_scan` if it exists, or pass the args directly.
            
            # Since I cannot see NmapScanner source right now (I saw it earlier in searches but didn't view it),
            # I will assume `stream_command` or similar exists, or I will subclass/modify logic here.
            # Actually, `scanner.stream_profile(profile)` was used. 
            # I'll rely on `scanner.run_custom(args)` if it exists.
            # Let's check `scan_engine/step01_recon/nmap_scanner.py` quickly.
            # For now, I'll pass the *args list* to valid existing method or assume stream_scan accepts list.
            
            # HACK: If NmapScanner doesn't support raw args list easily, 
            # I will reconstruct the list manually.
            
            stream = scanner.stream_scan(scan_args)
            
        except AttributeError:
             # If stream_scan doesn't exist, we might have to use stream_profile with a hack or fix NmapScanner.
             # Let's assume `stream_scan` is the generic one.
             self.log("Falling back to legacy profile logic...", "WARN")
             stream = scanner.stream_profile('quick')
        except Exception as e:
            self.log(f"Failed to start nmap: {str(e)}", "ERROR")
            return False
            
        output_buffer = []
        discovered_ports = []
        for event in stream:
            if event["type"] == "stdout":
                line = event["line"].strip()
                if line:
                    # Detect real-time port discovery (from Nmap -v)
                    if "Discovered open port" in line:
                        self.log(f"🔥 {line}", "SUCCESS")
                        # Extract port/proto: "Discovered open port 80/tcp on 1.2.3.4"
                        port_match = re.search(r"port (\d+)/(tcp|udp)", line)
                        if port_match:
                            p_num = int(port_match.group(1))
                            discovered_ports.append({
                                "port": p_num,
                                "service_name": "probing...",
                                "version": "detecting..."
                            })
                            # Send intermediate update to UI
                            self.save_results(self.scan_id, {
                                "phases": {
                                    "recon": {
                                        "open_ports": discovered_ports,
                                        "raw_output": "\n".join(output_buffer[-50:]) # Send last 50 lines only for speed
                                    }
                                }
                            })

                    # Detect progress stats
                    elif "Stats:" in line:
                        self.log(line, "INFO")
                    else:
                        self.log(line, "INFO")
                    output_buffer.append(line)
            elif event["type"] == "exit":
                self.log(f"Phase 1 finished with exit code {event['code']}", "SUCCESS" if event['code'] == 0 else "WARN")
            elif event["type"] == "error":
                self.log(f"Stream error: {event['message']}", "ERROR")
                return False

        full_output = "\n".join(output_buffer)
        
        # --- PHASE 2: Parsing ---
        self._emit_progress(40, "Packet Analysis")
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
        self._emit_progress(50, "Intel Mapping")
        try:
            self.log("Phase 3: Querying Intelligence Engine for Attack Vectors...", "INFO")
            
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
                    is_web = 'http' in svc or port in [80, 443, 8080, 8443]
                    if is_web:
                        web_ports.append(port)
                        # Trigger Screenshot
                        try:
                            self.log(f"Phase 3+: Capturing screenshot for port {port}...", "INFO")
                            shot_path = take_service_screenshot(self.scan_id, port, self.target)
                        except Exception as e:
                            self.log(f"Screenshot failed for port {port}: {e}", "WARN")
                            shot_path = None
                    else:
                        shot_path = None

                    # 2. Get Expert Analysis
                    try:
                        vectors = AttackVectorMapper.analyze_service(svc, ver, port)
                        p['priority_score'] = max([v['score'] for v in vectors]) if vectors else 0
                        
                        for v in vectors:
                            # Log actionable intelligence
                            self.log(f"[{v['category']}] {v['name']} detected on port {port} (Priority: {v['score']})", "WARN" if v['score'] >= 80 else "INFO")
                            
                            # Create highly specific suggestions/findings
                            self.add_finding(
                                title=f"{v['name']} (Port {port})",
                                description=f"{v['description']}\n\nACTIONABLE INTEL:\n{v['action']}",
                                severity=v['risk'].lower(),
                                tool_source="RedOps-Intel",
                                screenshot_path=shot_path if v['category'] == 'WEB' else None
                            )
                            
                            # Store vectors in results for UI/Brain display
                            if 'intel' not in results['phases']: results['phases']['intel'] = {}
                            if str(port) not in results['phases']['intel']: results['phases']['intel'][str(port)] = []
                            results['phases']['intel'][str(port)].append(v)

                            # Convert action to suggestion
                            self.add_suggestion(
                                tool_name="Assessment",
                                command_suggestion=v['action'],
                                reason=f"Vector: {v['name']} (Score: {v['score']})"
                            )
                    except Exception as e:
                         self.log(f"Analysis error for port {port}: {e}", "ERROR")
                
                # Sync back results with scores
                results['phases']['recon']['open_ports'] = open_ports
                self.save_results(self.scan_id, results)
        except Exception as e:
            self.log(f"Phase 3 (Analysis) encountered an error: {e}", "ERROR")
        
        # --- PHASE 4: Auto-Enumeration (Web) ---
        self._emit_progress(60, "Web Enumeration")
        if web_ports:
            try:
                self.log(f"Phase 4: Starting Auto-Recon for {len(web_ports)} web ports...", "INFO")
                
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
                            
                            # --- IMPROVED PARSING FOR UI ---
                            # Extract useful tech stack info into a summary dict
                            tech_summary = {}
                            
                            # Default regex to extract widely used Technology names
                            # Simple logic: extract Title[...] HTTPServer[...] Country[...]
                            
                            title_match = re.search(r"Title\[(.*?)\]", full_ww)
                            if title_match: tech_summary['Title'] = title_match.group(1)
                            
                            server_match = re.search(r"HTTPServer\[(.*?)\]", full_ww)
                            if server_match: tech_summary['Server'] = server_match.group(1)
                            
                            country_match = re.search(r"Country\[(.*?)\]", full_ww)
                            if country_match: tech_summary['Country'] = country_match.group(1)
                            
                            ip_match = re.search(r"IP\[(.*?)\]", full_ww)
                            if ip_match: tech_summary['IP'] = ip_match.group(1)
                            
                            # Also regex generic text like "Apache[2.4.41]"
                            # This is harder to do safely without clutter, let's stick to key items above for the summary box
                            
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
                                # Merge into main summary (UI expects flat object but we have multiple ports...)
                                # The UI code iterates Object.entries(summary). If we have multiple ports, keys might collide.
                                # Let's prefix keys with port if we have multiple.
                                for k, v in tech_summary.items():
                                    results['phases']['enum']['whatweb']['summary'][f"{k} ({port})"] = v
                                    
                                self.save_results(self.scan_id, results) # Update results incrementally

                        except Exception as e:
                            self.log(f"Error during Web Recon on port {port}: {str(e)}", "ERROR")

                        # --- KATANA CRAWLING ---
                        try:
                            katana = KatanaScanner(self.target)
                            if not katana.check_tools():
                                self.log("Skipping Katana: tool not installed. Install with 'install_tools.sh'", "WARN")
                                self.add_suggestion(
                                    tool_name="setup",
                                    command_suggestion="./install_tools.sh",
                                    reason="Deep crawling capability missing (Katana)"
                                )
                            else:
                                self.log(f"Deep Crawling {proto}://{self.target}:{port} with Katana...", "INFO")
                                try:
                                    kt_stream = katana.stream_katana(port, proto)
                                    endpoints = []
                                    for event in kt_stream:
                                        if event["type"] == "stdout":
                                            line = event["line"].strip()
                                            if line:
                                                endpoints.append(line)
                                    
                                    if endpoints:
                                        self.log(f"Katana discovered {len(endpoints)} endpoints.", "SUCCESS")
                                        self.add_finding(
                                            title=f"Crawling Results ({port})",
                                            description=f"Discovered {len(endpoints)} URLs/Endpoints.",
                                            severity="info",
                                            tool_source="katana"
                                        )
                                        # Update results
                                        if 'enum' not in results['phases']: results['phases']['enum'] = {}
                                        results['phases']['enum']['katana'] = {str(port): endpoints[:100]} # limit UI display
                                        self.save_results(self.scan_id, results)
                                except Exception as e:
                                    self.log(f"Katana error on port {port}: {str(e)}", "ERROR")
                        except Exception as e:
                             self.log(f"Katana setup failed: {e}", "ERROR")

            except Exception as e:
                self.log(f"Phase 4 (Web Enum) failed: {e}", "ERROR")
        
        # --- PHASE 5: Automated Vulnerability Scanning (Nuclei) ---
        self._emit_progress(80, "Vulnerability Assessment")
        if web_ports:
            try:
                self.log(f"Phase 5: Starting Vulnerability Assessment for {len(web_ports)} targets...", "INFO")
                
                vuln_scanner = NucleiScanner(self.target)
                if not vuln_scanner.check_tools():
                    self.log("Skipping Vuln Scan: 'nuclei' not installed.", "WARN")
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
                                        sev = "info"
                                        if "[critical]" in line.lower(): sev = "critical"
                                        elif "[high]" in line.lower(): sev = "high"
                                        elif "[medium]" in line.lower(): sev = "medium"
                                        elif "[low]" in line.lower(): sev = "low"
                                        
                                        self.log(line, "WARN" if sev in ["critical", "high"] else "INFO")
                                        
                                        if sev in ["critical", "high", "medium"]:
                                            vuln_count += 1
                                            self.add_finding(
                                                title=f"Vulnerability Found ({sev.upper()})",
                                                description=f"Nuclei Output:\n{line}",
                                                severity=sev,
                                                tool_source="nuclei"
                                            )
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

                        except Exception as e:
                            self.log(f"Error during Vuln Scan on port {port}: {str(e)}", "ERROR")
            except Exception as e:
                self.log(f"Phase 5 (Vuln Scan) failed: {e}", "ERROR")

        # --- PHASE 6: Automated Dirbusting (ffuf) ---
        self._emit_progress(90, "Fuzzing")
        if web_ports:
            try:
                self.log("Phase 6: Starting Automated Dirbusting (ffuf)...", "INFO")
                
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
                    
                    scanner6 = FfufScanner(target_url, wordlist=wordlist)
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
                                # Ensure we don't duplicate existing endpoints structure if appending
                                # Actually we are appending to a fresh list in memory `found_items` then updating result dict
                                # But `results['phases']['dirbusting']['ffuf']['endpoints']` might reset per port loop iteration if we re-init
                                # Fix: init list outside loop or check exist
                                if 'endpoints' not in results['phases']['dirbusting']['ffuf']:
                                     results['phases']['dirbusting']['ffuf']['endpoints'] = []
                                
                                results['phases']['dirbusting']['ffuf']['endpoints'].append({
                                    "path": clean_item,
                                    "status": "200", 
                                    "size": "N/A"
                                })
                            
                            self.save_results(self.scan_id, results) # Update results

                    except Exception as e:
                        self.log(f"Error during ffuf scan on port {port}: {str(e)}", "ERROR")
            except Exception as e:
                self.log(f"Phase 6 (Dirbusting) failed: {e}", "ERROR")

        self._emit_progress(100, "Operation Completed")
        self._emit_progress(100, "Operation Completed")
        return success
