import shlex
import time
from scan_engine.step03_vuln.nuclei_scanner import NucleiScanner
from scan_engine.step03_vuln.wpscan_scanner import WPScanScanner
from scan_engine.step03_vuln.dalfox_scanner import DalfoxScanner
from scan_engine.step03_vuln.ssrf_scanner import SSRFScanner
from scan_engine.step03_vuln.open_redirect_scanner import OpenRedirectScanner
from scan_engine.step03_vuln.takeover_scanner import TakeoverScanner
from scan_engine.step03_vuln.git_scanner import GitExposureScanner
from scan_engine.step03_vuln.backup_scanner import BackupScanner
from scan_engine.step03_vuln.graphql_scanner import GraphQLScanner
from scan_engine.step03_vuln.js_vuln_scanner import JSVulnScanner
from scan_engine.phases.utils import extract_wp_data, emit_progress

def run_vuln_scans(orchestrator, port, proto, fingerprint_data=""):
    """
    Executes Phase 3/4/5: Vulnerability Scanning on a specific port
    - WPScan (if WordPress detected)
    - Git Exposure
    - Backup Audit
    - GraphQL Audit
    - SSRF Probing (if API endpoints found)
    - JS Vulnerabilities
    - Dalfox (XSS)
    - Open Redirect
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    profile = orch.options.get('profile', 'quick')

    # --- CMS SPECIFIC SCANS (WordPress) ---
    # Enhanced Detection: Check WhatWeb + HTTP Headers
    is_wordpress = "WordPress" in fingerprint_data or "wp-content" in fingerprint_data or "wp-includes" in fingerprint_data
    
    # Check headers if available from Phase 2 (Enum)
    if not is_wordpress and 'enum' in results['phases'] and 'headers' in results['phases']['enum']:
        headers = results['phases']['enum']['headers'].get(str(port), {})
        headers_str = str(headers).lower()
        if 'wp-json' in headers_str or 'wordpress' in headers.get('X-Redirect-By', '').lower():
            is_wordpress = True
            log(f"WordPress detected via HTTP Headers on port {port}.", "SUCCESS")

    if is_wordpress:
        log(f"WordPress signature detected on port {port}. Initiating WPScan...", "WARN")
        try:
            wpscan = WPScanScanner(target)
            if not wpscan.check_tools():
                log("Skipping WPScan: tool not installed.", "WARN")
            else:
                enumerate_all = False if profile.startswith('quick') else True
                wp_stream = wpscan.stream_scan(port, proto, enumerate_all=enumerate_all)
                
                # Use shared utility for parsing
                wp_data, wp_raw_log = extract_wp_data(wp_stream, port, log)
                
                if wp_data:
                    if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                    if 'wordpress' not in results['phases']['vuln']: results['phases']['vuln']['wordpress'] = {}
                    results['phases']['vuln']['wordpress'][str(port)] = wp_data
                    
                    if 'wpscan' not in results['phases']['vuln']: results['phases']['vuln']['wpscan'] = {}
                    results['phases']['vuln']['wpscan'][str(port)] = wp_raw_log
                    
                    # Backward compatibility
                    results['phases']['vuln']['wordpress'] = results['phases']['vuln'].get('wordpress', {})
                    results['phases']['vuln']['wordpress'][str(port)] = wp_data
                    
                    orch.save_results(orch.scan_id, results)

                    if wp_data['vulns']:
                        orch.add_finding(
                            title=f"WordPress Vulnerabilities Detected ({port})",
                            description=f"WPScan detected potential vulnerabilities:\n\n" + "\n".join([v.get('title', 'Vuln') for v in wp_data['vulns']]),
                            severity="high",
                            tool_source="wpscan"
                        )
        except Exception as e:
            log(f"WPScan failed: {e}", "ERROR")

    # --- SENSITIVE DIR AUDIT (.git, etc.) ---
    try:
        gs = GitExposureScanner(target)
        gs_findings = gs.audit_git(port, proto, logger=log)
        if gs_findings:
            if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
            results['phases']['vuln']['git'] = gs_findings
            for f in gs_findings:
                orch.add_finding(
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="git_scanner"
                )
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Git exposure audit failed on port {port}: {e}", "DEBUG")

    # --- EXPERT: Backup & Archive Audit ---
    try:
        bs = BackupScanner(target)
        bs_findings = bs.scan_backups(port, proto, logger=log)
        if bs_findings:
            if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
            results['phases']['vuln']['backups'] = bs_findings
            for f in bs_findings:
                orch.add_finding(
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="backup_expert"
                )
                if orch.add_loot and f.get('raw_loot'):
                    orch.add_loot(
                        loot_type=f.get('loot_type', 'Backup/Archive'),
                        content=f['raw_loot'],
                        context=f"Discovered in backup audit on {target}:{port}"
                    )
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Backup audit failed on port {port}: {e}", "DEBUG")

    # --- EXPERT: GraphQL Audit ---
    try:
        gs = GraphQLScanner(target)
        gs_findings = gs.audit_graphql(port, proto, logger=log)
        if gs_findings:
            if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
            results['phases']['vuln']['graphql'] = gs_findings
            for f in gs_findings:
                orch.add_finding(
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="graphql_expert"
                )
                if orch.add_loot and f.get('raw_loot'):
                    orch.add_loot(
                        loot_type=f.get('loot_type', 'API Intelligence'),
                        content=f['raw_loot'],
                        context=f"Discovered via GraphQL audit on {target}:{port}"
                    )
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"GraphQL audit failed on port {port}: {e}", "DEBUG")

    # --- EXPERT: SSRF Probing (Cloud Metadata) ---
    try:
        # Use discovered API endpoints for SSRF probing
        discovered_endpoints = []
        api_data = results.get('phases', {}).get('enum', {}).get('api', {})
        
        # Iterate over all ports in api data
        for port_key, port_val in api_data.items():
            if isinstance(port_val, list):
                for item in port_val:
                    if isinstance(item, dict) and 'url' in item:
                        discovered_endpoints.append(item['url'])
                    elif isinstance(item, str):
                        discovered_endpoints.append(item)
                        
        if discovered_endpoints:
            ssrf = SSRFScanner(target)
            ssrf_findings = ssrf.scan_endpoints(discovered_endpoints, logger=log)
            if ssrf_findings:
                if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                results['phases']['vuln']['ssrf'] = ssrf_findings
                for f in ssrf_findings:
                    orch.add_finding(
                        title=f['title'],
                        description=f['description'],
                        severity=f['severity'],
                        tool_source="ssrf_expert"
                    )
                    if orch.add_loot and f.get('raw_loot'):
                        orch.add_loot(
                            loot_type=f.get('loot_type', 'Cloud Asset'),
                            content=f['raw_loot'],
                            context=f"Discovered via SSRF on {target}"
                        )
                orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"SSRF Expert probe failed: {e}", "DEBUG")

    # --- JS VULNERABILITY AUDIT ---
    try:
        url = f"{proto}://{target}:{port}"
        js_scanner = JSVulnScanner(target)
        js_findings = js_scanner.audit_js_endpoints(url, logger=log)
        if js_findings:
            if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
            if 'js_vulns' not in results['phases']['vuln']: results['phases']['vuln']['js_vulns'] = {}
            results['phases']['vuln']['js_vulns'][str(port)] = js_findings
            
            for f in js_findings:
                orch.add_finding(
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="js_vuln_audit"
                )
            orch.save_results(orch.scan_id, results)
    except Exception as e:
         log(f"JS Vuln audit failed: {e}", "DEBUG")

    # --- DALFOX (XSS) ---
    try:
        dalfox = DalfoxScanner(target)
        if dalfox.check_tools():
            log(f"Checking for XSS on {proto}://{target}:{port}...", "INFO")
            cmd_df = dalfox.get_command(port, proto)
            results['commands'].append({'tool': 'dalfox', 'cmd': shlex.join(cmd_df)})
            
            df_stream = dalfox.stream_scan_xss(port, proto)
            xss_found = []
            
            for event in df_stream:
                if event["type"] == "stdout":
                    line = event["line"].strip()
                    if "[V]" in line or "PoC" in line:
                         log(f"XSS Discovered: {line}", "SUCCESS")
                         xss_found.append(line)
                         orch.add_finding(
                            title=f"Cross-Site Scripting (XSS) Detected ({port})",
                            description=f"Dalfox output:\n{line}",
                            severity="high",
                            tool_source="dalfox"
                         )
            
            if xss_found:
                if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                if 'xss' not in results['phases']['vuln']: results['phases']['vuln']['xss'] = {}
                results['phases']['vuln']['xss'][str(port)] = xss_found
                orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Dalfox failed: {e}", "ERROR")

    # --- OPEN REDIRECT ---
    try:
        # Use endpoints from enum phase if available, otherwise just check base if needed?
        # Orchestrator passed 'endpoints' which presumably came from Katana/Ffuf.
        # Here we can grab them from results['phases']['dirbusting'] or ['enum']['api']
        
        endpoints = []
        # Gather all known endpoints
        if 'dirbusting' in results['phases']:
             for tool, data in results['phases']['dirbusting'].items():
                 if 'endpoints' in data:
                     for ep in data['endpoints']:
                         if isinstance(ep, dict) and 'url' in ep: endpoints.append(ep['url'])
                         elif isinstance(ep, str): endpoints.append(ep)
        
        if 'enum' in results['phases'] and 'api' in results['phases']['enum']:
            endpoints.extend(results['phases']['enum']['api'].get('discovered_endpoints', []))

        if endpoints:
            or_scanner = OpenRedirectScanner(target)
            or_findings = or_scanner.scan_endpoints(endpoints, logger=log)
            
            if or_findings:
                if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                results['phases']['vuln']['redirects'] = or_findings
                
                for f in or_findings:
                    orch.add_finding(
                        title=f"Open Redirect Vulnerability ({port})",
                        description=f"Vulnerable URL: {f.get('url')}\nDestination: {f.get('destination')}",
                        severity="medium",
                        tool_source="redirect_scanner"
                    )
                orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Open Redirect audit failed: {e}", "DEBUG")


def run_global_vuln_scans(orchestrator):
    """
    Executes global vulnerability scans (Target-wide, not per-port)
    - Nuclei
    - Subdomain Takeover
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    
    # --- PHASE 3: Subdomain Takeover ---
    emit_progress(orch, 50, "Subdomain Takeover Check")
    try:
        takeover = TakeoverScanner(target)
        if takeover.check_tools():
            # Get subdomains from DNS phase
            subdomains = results.get('phases', {}).get('dns', {}).get('subdomains', [])
            if subdomains:
                log(f"Checking {len(subdomains)} subdomains for takeover...", "INFO")
                tk_stream = takeover.stream_takeover_scan(logger=log, targets=subdomains)
                for event in tk_stream:
                    if event['type'] == 'stdout':
                         log(f"🚩 POTENTIAL TAKEOVER: {event['line']}", "CRITICAL")
                         orch.add_finding(
                             title="Subdomain Takeover Detected",
                             description=f"Subzy output: {event['line']}",
                             severity="critical",
                             tool_source="takeover_scanner"
                         )
                orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Takeover check failed: {e}", "WARN")

    # --- PHASE 5: Nuclei ---
    emit_progress(orch, 80, "Vulnerability Assessment (Nuclei)")
    try:
        nuclei = NucleiScanner(target)
        if nuclei.check_tools():
            log("Running Nuclei Vulnerability Scan (Critical/High/Medium)...", "INFO")
            
            # Identify web ports to scan
            web_ports = []
            if 'recon' in results['phases'] and 'open_ports' in results['phases']['recon']:
                for p_info in results['phases']['recon']['open_ports']:
                    # Robust service check: handles 'service', 'service_name', or assumes web ports
                    svc = p_info.get('service_name', p_info.get('service', '')).lower()
                    port_num = p_info.get('port')
                    
                    if svc in ['http', 'https', 'ssl/http', 'http-alt'] or port_num in [80, 443, 8080, 8443]:
                        web_ports.append(port_num)
            
            # If no web ports identified but we have open ports, maybe try 80/443 if in list?
            # Existing logic fallback was:
            if not web_ports: web_ports = [80, 443]

            for port in web_ports:
                proto = 'https' if port in [443, 8443] or 'ssl' in str(port) else 'http'
                # Simple heuristc logic, might need refinement
                
                try:
                    cmd_nuc = nuclei.get_command(port, proto, tags="cve,lfi,rfi,ssti,sqli,injection,misconfig")
                    results['commands'].append({'tool': 'nuclei', 'cmd': shlex.join(cmd_nuc)})
                    log(f"Executing Nuclei on {target}:{port}...", "DEBUG")
                    
                    nuc_stream = nuclei.stream_vuln_scan(port, proto, tags="cve,lfi,rfi,ssti,sqli,injection,misconfig")
                    
                    if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                    if 'nuclei' not in results['phases']['vuln']: results['phases']['vuln']['nuclei'] = {'findings': []}
                    
                    start_time = time.time()
                    found_any = False
                    
                    for event in nuc_stream:
                        # Timeout logic
                        if (time.time() - start_time) > 1200: # 20 mins
                            log(f"Nuclei on port {port} timed out. Skipping.", "WARN")
                            break
                            
                        if event['type'] == 'stdout':
                            line = event['line'].strip()
                            # Strip ANSI if needed, usually stream handles it or we do it here
                            # Assuming line is clean or we accept ANSI for now
                            
                            if "[FTL]" in line or "error" in line.lower(): continue

                            sev = 'info'
                            if '[critical]' in line.lower(): sev = 'critical'
                            elif '[high]' in line.lower(): sev = 'high'
                            elif '[medium]' in line.lower(): sev = 'medium'
                            elif '[low]' in line.lower(): sev = 'low'
                            
                            if sev in ['critical', 'high', 'medium', 'low']:
                                log(f"Nuclei: {line}", 'WARN' if sev in ['critical', 'high'] else 'INFO')
                                
                                results['phases']['vuln']['nuclei']['findings'].append({
                                    'severity': sev,
                                    'title': line,
                                    'port': port
                                })
                                found_any = True
                                
                                orch.add_finding(
                                    title=f"Vulnerability Found ({sev.upper()})",
                                    description=f"Nuclei Output:\n{line}",
                                    severity=sev,
                                    tool_source="nuclei"
                                )
                                orch.save_results(orch.scan_id, results)
                                
                    if not found_any:
                        log(f"No Nuclei findings on port {port}.", "SUCCESS")
                        
                except Exception as e:
                    log(f"Nuclei error on {port}: {e}", "ERROR")

    except Exception as e:
        log(f"Nuclei scan failed: {e}", "ERROR")
