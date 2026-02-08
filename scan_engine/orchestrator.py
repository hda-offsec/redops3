import re
import threading
import os
from datetime import datetime
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.step01_recon.dns_scanner import DNSScanner
from scan_engine.step02_enum.katana_scanner import KatanaScanner
from scan_engine.step02_enum.web_scanner import WebReconScanner
from scan_engine.step03_vuln.nuclei_scanner import NucleiScanner
from scan_engine.step03_vuln.wpscan_scanner import WPScanScanner
from scan_engine.step03_vuln.dalfox_scanner import DalfoxScanner
from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner
from scan_engine.step02_enum.waf_scanner import WafScanner
from scan_engine.step02_enum.arjun_scanner import ArjunScanner
from scan_engine.step02_enum.js_scanner import JSSecretScanner
from scan_engine.step00_osint.cloud_scanner import CloudScanner
from scan_engine.step00_osint.favicon_scanner import FaviconScanner
from scan_engine.step00_osint.github_scanner import GitHubScanner
from scan_engine.step00_osint.email_scanner import EmailScanner
from scan_engine.step03_vuln.takeover_scanner import TakeoverScanner
from scan_engine.step02_enum.api_scanner import APIScanner
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
            # Define the main results structure early
            results = {
                "scan_id": self.scan_id,
                "target": self.target,
                "status": "running",
                "timestamp": datetime.utcnow().isoformat(),
                "phases": {
                    "recon": {"open_ports": [], "raw_output": ""},
                    "dns": {"subdomains": []},
                    "intel": {},
                    "osint": {
                        "cloud": [],
                        "favicon": {},
                        "github": [],
                        "emails": []
                    },
                    "enum": {
                        "whatweb": {"summary": {}},
                        "katana": {},
                        "waf": {},
                        "arjun": {},
                        "js_secrets": {},
                        "api": {}
                    },
                    "vuln": {
                        "nuclei": {"findings": []},
                        "takeover": [],
                        "wpscan": {}
                    },
                    "dirbusting": {
                        "ffuf": {"endpoints": []}
                    }
                }
            }
            self.save_results(self.scan_id, results)

            # --- PHASE 0: Pre-Flight Intelligence (Geo) ---
            self._emit_progress(5, "Geolocation Init")
            self.log("Phase 0: Gathering Geolocation Intelligence...", "INFO")
            # Capture app context for the thread
            from flask import current_app
            app_ctx = current_app.app_context()

            def on_geo_complete(geo):
                with app_ctx:
                    if geo:
                        self.log(f"Target located: {geo.get('city')}, {geo.get('country')} ({geo.get('isp')})", "SUCCESS")
                        # Update Scan model directly
                        try:
                            scan_obj = Scan.query.get(self.scan_id)
                            if scan_obj:
                                scan_obj.geolocation_data = geo
                                db.session.commit()
                        except Exception as e:
                            self.log(f"Failed to save geolocation: {e}", "WARN")
                    else:
                        self.log("Geolocation lookup failed or target is local.", "WARN")

            # Start async lookup
            AttackVectorMapper.get_ip_geolocation(self.target, callback=on_geo_complete)

            # --- PHASE 0.1: Cloud Assets Audit ---
            try:
                cloud_scanner = CloudScanner(self.target)
                cloud_results = cloud_scanner.scan_all(logger=self.log)
                if cloud_results:
                    results['phases']['osint']['cloud'] = cloud_results
                    self.save_results(self.scan_id, results)
                    for c in cloud_results:
                        self.add_finding(
                            title=f"Cloud Asset Found: {c['bucket'] if 'bucket' in c else c['account']}",
                            description=f"Provider: {c['provider']}\nURL: {c['url']}\nStatus: {c['status']}",
                            severity="medium" if c['status'] == 'OPEN/PUBLIC' else "info",
                            tool_source="Cloud-Audit"
                        )
            except Exception as e:
                self.log(f"Cloud Audit failed: {e}", "WARN")

            # --- PHASE 0.2: GitHub Leaks & Email Discovery ---
            try:
                # GitHub Leaks
                github_scanner = GitHubScanner(self.target)
                github_leaks = github_scanner.search_leaks(logger=self.log)
                if github_leaks:
                    results['phases']['osint']['github'] = github_leaks
                    self.save_results(self.scan_id, results)
                    for leak in github_leaks:
                        self.add_finding(
                            title=f"GitHub Leak Found: {leak['repository']}",
                            description=f"File: {leak['path']}\nURL: {leak['url']}",
                            severity="medium",
                            tool_source="GitHub-Scanner"
                        )
                
                # Email Discovery
                email_scanner = EmailScanner(self.target)
                emails = email_scanner.scan(logger=self.log)
                if emails:
                    results['phases']['osint']['emails'] = emails
                    self.save_results(self.scan_id, results)
                    self.add_finding(
                        title=f"OSINT: {len(emails)} Emails Found",
                        description="\n".join(emails[:20]),
                        severity="info",
                        tool_source="EmailScanner"
                    )
            except Exception as e:
                self.log(f"OSINT Discovery modules failed: {e}", "WARN")

            # --- INITIALIZATION: Done ---
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

            # Save to results
            results['phases']['dns']['subdomains'] = dns_results['subdomains']
            self.save_results(self.scan_id, results)

            self.add_finding(
                title=f"DNS Discovery: {len(dns_results['subdomains'])} Subdomains",
                description="\n".join(dns_results["subdomains"]),
                severity="info",
                tool_source="subfinder"
            )

            # --- Subdomain Takeover Check ---
            try:
                takeover_scanner = TakeoverScanner(self.target)
                if takeover_scanner.check_tools():
                    tk_stream = takeover_scanner.stream_takeover_scan(logger=self.log)
                    for event in tk_stream:
                        if event['type'] == 'stdout':
                            line = event['line'].strip()
                            if line:
                                self.log(f"🚩 POTENTIAL TAKEOVER: {line}", "CRITICAL")
                                results['phases']['vuln']['takeover'].append(line)
                                self.add_finding(
                                    title="Subdomain Takeover Detected",
                                    description=line,
                                    severity="critical",
                                    tool_source="nuclei"
                                )
                    self.save_results(self.scan_id, results)
            except Exception as e:
                self.log(f"Takeover check failed: {e}", "WARN")

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
            stream = scanner.stream_scan(scan_args)
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
                                "version": "detecting...",
                                "priority_score": 0
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
        
        # Update structured results (preserve existing phases like DNS)
        results['phases']['recon']['open_ports'] = open_ports
        results['phases']['recon']['raw_output'] = full_output
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
                            # Link screenshot to the port object for the UI Matrix
                            p['screenshot_path'] = shot_path
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
                        
                        # Incremental save after each port analysis
                        self.save_results(self.scan_id, results)

                        # Convert actions to suggestions if any
                        for v in vectors:
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

                        # --- CMS SPECIFIC SCANS (WordPress) ---
                        if "WordPress" in full_ww:
                            self.log(f"WordPress detected on port {port}. Initiating WPScan...", "WARN")
                            try:
                                wpscan = WPScanScanner(self.target)
                                if not wpscan.check_tools():
                                    self.log("Skipping WPScan: tool not installed. Please install 'wpscan' to enable this feature.", "WARN")
                                else:
                                    wp_stream = wpscan.stream_scan(port, proto)
                                    wp_findings = []
                                    current_finding = []
                                    
                                    for event in wp_stream:
                                        if event["type"] == "stdout":
                                            line = event["line"].strip()
                                            if line:
                                                self.log(line, "INFO")
                                                
                                                # Basic parsing to group relevant finding lines
                                                if "[!]" in line or "[+]" in line:
                                                    wp_findings.append(line)
                                                    
                                        elif event["type"] == "exit":
                                            self.log(f"WPScan finished on port {port}.", "SUCCESS")

                                    if wp_findings:
                                        summary = "\n".join(wp_findings)
                                        # Update results
                                        if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                                        results['phases']['vuln']['wpscan'] = results['phases']['vuln'].get('wpscan', {})
                                        results['phases']['vuln']['wpscan'][str(port)] = summary
                                        self.save_results(self.scan_id, results)

                                        self.add_finding(
                                            title=f"WordPress Scan Findings ({port})",
                                            description=f"WPScan enumerated the following potential issues:\n\n{summary}",
                                            severity="high",
                                            tool_source="wpscan"
                                        )
                            except Exception as e:
                                self.log(f"WPScan failed: {e}", "ERROR")



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
                                        
                                        # --- SENSITIVE DATA ANALYSIS ---
                                        sensitive_exts = ['.env', '.git', '.bak', '.config', '.sql', '.db', '.xml', '.yml', '.yaml']
                                        sensitive_keywords = ['admin', 'login', 'dashboard', 'setup', 'install', 'test']
                                        
                                        exposed_secrets = []
                                        exposed_panels = []
                                        
                                        for ep in endpoints:
                                            # Check extensions
                                            if any(ep.endswith(ext) for ext in sensitive_exts):
                                                exposed_secrets.append(ep)
                                            # Check keywords in path
                                            if any(kw in ep.lower() for kw in sensitive_keywords):
                                                # Avoid obvious public login pages if possible, but worth flagging
                                                exposed_panels.append(ep)
                                        
                                        if exposed_secrets:
                                            self.add_finding(
                                                title=f"Sensitive Files Exposed ({port})",
                                                description=f"Potential sensitive files found:\n" + "\n".join(exposed_secrets[:20]),
                                                severity="critical",
                                                tool_source="katana"
                                            )
                                            
                                        if exposed_panels:
                                            self.add_finding(
                                                title=f"Administrative Panels ({port})",
                                                description=f"Potential admin interfaces found:\n" + "\n".join(exposed_panels[:20]),
                                                severity="medium",
                                                tool_source="katana"
                                            )

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

                        # --- WAF DETECTION ---
                        try:
                            waf_scanner = WafScanner(self.target)
                            if waf_scanner.check_tools():
                                self.log(f"Phase 4b: Detecting WAF on {proto}://{self.target}:{port}...", "INFO")
                                waf_stream = waf_scanner.stream_wafw00f(port, proto)
                                waf_result = "None"
                                for event in waf_stream:
                                    if event["type"] == "stdout":
                                        line = event["line"].strip()
                                        if "is behind" in line:
                                            waf_result = line.split("is behind")[-1].strip()
                                            self.log(f"🛡️ WAF Detected: {waf_result}", "SUCCESS")
                                            self.add_finding(
                                                title=f"WAF Detected ({port})",
                                                description=line,
                                                severity="info",
                                                tool_source="wafw00f"
                                            )
                                
                                if 'enum' not in results['phases']: results['phases']['enum'] = {}
                                results['phases']['enum']['waf'] = results['phases']['enum'].get('waf', {})
                                results['phases']['enum']['waf'][str(port)] = waf_result
                                self.save_results(self.scan_id, results)
                        except Exception as e:
                            self.log(f"WAF Detection failed: {e}", "ERROR")

                        # --- PARAMETER DISCOVERY (ARJUN) ---
                        try:
                            arjun = ArjunScanner(self.target)
                            if arjun.check_tools():
                                self.log(f"Phase 4c: Discovering hidden parameters on {proto}://{self.target}:{port}...", "INFO")
                                ar_stream = arjun.stream_arjun(port, proto)
                                params_found = []
                                for event in ar_stream:
                                    if event["type"] == "stdout":
                                        line = event["line"].strip()
                                        if "parameters found:" in line.lower() or "heuristic" in line.lower():
                                            self.log(f"Arjun: {line}", "SUCCESS")
                                            params_found.append(line)
                                
                                if params_found:
                                    self.add_finding(
                                        title=f"Hidden Parameters Discovered ({port})",
                                        description="\n".join(params_found),
                                        severity="medium",
                                        tool_source="arjun"
                                    )
                                    if 'enum' not in results['phases']: results['phases']['enum'] = {}
                                    results['phases']['enum']['arjun'] = results['phases']['enum'].get('arjun', {})
                                    results['phases']['enum']['arjun'][str(port)] = params_found
                                    self.save_results(self.scan_id, results)
                        except Exception as e:
                            self.log(f"Arjun failed: {e}", "ERROR")

                        # --- JS ADVANCED ANALYSIS ---
                        try:
                            if endpoints:
                                js_scanner = JSSecretScanner(self.target)
                                js_results = js_scanner.scan_list(endpoints, logger=self.log)
                                
                                # Handle Secrets
                                if js_results["secrets"]:
                                    for url, items in js_results["secrets"].items():
                                        desc = f"File: {url}\n\n"
                                        for item in items:
                                            desc += f"- [{item['type']}] {item['match']}\n  Context: ...{item['line_context']}...\n\n"
                                        
                                        self.add_finding(
                                            title=f"Secrets Discovered in JS ({port})",
                                            description=desc,
                                            severity="critical",
                                            tool_source="js_scanner"
                                        )
                                    
                                    if 'enum' not in results['phases']: results['phases']['enum'] = {}
                                    results['phases']['enum']['js_secrets'] = results['phases']['enum'].get('js_secrets', {})
                                    results['phases']['enum']['js_secrets'][str(port)] = js_results["secrets"]
                                    self.save_results(self.scan_id, results)
                                
                                # Handle New Endpoints from JS
                                if js_results["endpoints"]:
                                    self.log(f"JS Analysis: Found {len(js_results['endpoints'])} new endpoints/paths in source code.", "SUCCESS")
                                    # Add them to the general endpoints list for this port if relevant
                                    results['phases']['enum']['katana'][str(port)] = list(set(results['phases']['enum']['katana'].get(str(port), []) + js_results["endpoints"]))
                                    self.save_results(self.scan_id, results)
                                    self.add_finding(
                                        title=f"JS Intelligence: Hidden Endpoints Found ({port})",
                                        description="\n".join(js_results["endpoints"][:30]),
                                        severity="low",
                                        tool_source="js_scanner"
                                    )
                        except Exception as e:
                            self.log(f"JS Advanced Analysis failed: {e}", "ERROR")

                        # --- FAVICON HASHING ---
                        try:
                            fav_scanner = FaviconScanner(self.target)
                            fav_result = fav_scanner.scan(port, proto, logger=self.log)
                            if fav_result:
                                if 'osint' not in results['phases']: results['phases']['osint'] = {}
                                results['phases']['osint']['favicon'][str(port)] = fav_result
                                self.save_results(self.scan_id, results)
                                self.add_finding(
                                    title=f"Favicon Intel ({port})",
                                    description=f"Hash: {fav_result['hash']}\nShodan: {fav_result['shodan_query']}",
                                    severity="info",
                                    tool_source="FaviconScanner"
                                )
                        except Exception as e:
                            self.log(f"Favicon scanning failed: {e}", "WARN")

                        # --- API DISCOVERY ---
                        try:
                            api_scanner = APIScanner(self.target)
                            if api_scanner.check_tools():
                                api_stream = api_scanner.stream_api_discovery(port, proto, logger=self.log)
                                api_endpoints = []
                                for event in api_stream:
                                    if event['type'] == 'stdout':
                                        line = event['line'].strip()
                                        if line:
                                            # ffuf output can be cleaned or kept as is
                                            api_endpoints.append(line)
                                
                                if api_endpoints:
                                    self.log(f"API Discovery: Found {len(api_endpoints)} potential endpoints on port {port}", "SUCCESS")
                                    if 'enum' not in results['phases']: results['phases']['enum'] = {}
                                    if 'api' not in results['phases']['enum']: results['phases']['enum']['api'] = {}
                                    results['phases']['enum']['api'][str(port)] = api_endpoints
                                    self.save_results(self.scan_id, results)
                                    self.add_finding(
                                        title=f"API Endpoints Discovered ({port})",
                                        description="\n".join(api_endpoints[:20]),
                                        severity="low",
                                        tool_source="ffuf"
                                    )
                        except Exception as e:
                            self.log(f"API discovery failed: {e}", "ERROR")

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
                            # Nuclei: Standard + specific vulnerability classes
                            # We use tags to ensure we cover the requested categories (XSS handled by Dalfox, but Nuclei can backup)
                            # including 'sqli', 'injection' as requested.
                            # We strictly exclude 'dos' or 'fuzz' to ensure non-destructive behavior.
                            
                            nuc_stream = vuln_scanner.stream_vuln_scan(port, proto, tags="cve,lfi,rfi,ssti,sqli,injection,misconfig")
                            
                            if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                            if 'nuclei' not in results['phases']['vuln']: results['phases']['vuln']['nuclei'] = {'findings': []}
                            
                            found_any = False
                            unsaved_changes = False
                            vuln_count = 0
                            for event in nuc_stream:
                                if event['type'] == 'stdout':
                                    line = event['line'].strip()
                                    if line:
                                        sev = 'info'
                                        if '[critical]' in line.lower(): sev = 'critical'
                                        elif '[high]' in line.lower(): sev = 'high'
                                        elif '[medium]' in line.lower(): sev = 'medium'
                                        elif '[low]' in line.lower(): sev = 'low'
                                        
                                        self.log(line, 'WARN' if sev in ['critical', 'high'] else 'INFO')
                                        
                                        # Record all findings regardless of severity for complete history
                                        results['phases']['vuln']['nuclei']['findings'].append({
                                            'severity': sev,
                                            'title': line,
                                            'port': port
                                        })
                                        found_any = True
                                        
                                        if sev in ['critical', 'high', 'medium']:
                                            self.add_finding(
                                                title=f"Vulnerability Found ({sev.upper()})",
                                                description=f"Nuclei Output:\n{line}",
                                                severity=sev,
                                                tool_source="nuclei"
                                            )
                                        
                                        # Incremental save
                                        self.save_results(self.scan_id, results)

                                elif event['type'] == 'exit':
                                    self.log(f"Nuclei on port {port} finished with code {event['code']}", "INFO")
                            
                            if not found_any:
                                self.log(f"No vulnerabilities found on port {port}.", "SUCCESS")

                            # Final save if we have pending updates
                            if unsaved_changes:
                                self.save_results(self.scan_id, results)

                            
                            # --- DALFOX XSS SCANNING ---
                            try:
                                self.log(f"Phase 5b: XSS Heuristics (Dalfox) on {proto}://{self.target}:{port}...", "INFO")
                                xss_scanner = DalfoxScanner(self.target)
                                if xss_scanner.check_tools():
                                    # We use the generic 'url' mode primarily. 
                                    # Ideally we would pipe katana endpoints to dalfox, but for now we scan the base
                                    dalfox_stream = xss_scanner.stream_scan_xss(port, proto)
                                    
                                    xss_found = False
                                    for event in dalfox_stream:
                                        if event['type'] == 'stdout':
                                            line = event['line'].strip()
                                            if line and "POC" in line: # Dalfox usually outputs POC when found
                                                self.log(f"⚔️ XSS DETECTED: {line}", "CRITICAL")
                                                xss_found = True
                                                
                                                self.add_finding(
                                                    title=f"XSS Vulnerability Reflected ({port})",
                                                    description=f"Dalfox identified a Cross-Site Scripting vector:\n\n{line}",
                                                    severity="critical",
                                                    tool_source="dalfox"
                                                )
                                        elif event['type'] == 'error':
                                            pass # Dalfox is noisy
                                            
                                    if xss_found:
                                        self.log(f"XSS vulnerabilities confirmed on port {port}", "SUCCESS")
                                else:
                                    self.log("Dalfox not found, skipping XSS deep-scan.", "WARN")
                            except Exception as e:
                                self.log(f"Dalfox XSS scan failed: {e}", "ERROR")

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
                    
                    try:
                        scanner6 = FfufScanner(target_url, wordlist=wordlist)
                    except TypeError:
                        self.log("Detected legacy FfufScanner constructor, falling back.", "WARN")
                        scanner6 = FfufScanner(target_url)

                    if not scanner6.check_tools():
                        self.log("Skipping ffuf: tool not installed.", "WARN")
                        break
                    
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
