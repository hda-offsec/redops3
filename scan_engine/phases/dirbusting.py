import shlex
from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner
from scan_engine.phases.utils import emit_progress

def run_dirbusting(orchestrator):
    """
    Executes Phase 5: Directory Busting / Recursive Scanning
    - Ffuf (Recursive)
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    
    emit_progress(orch, 90, "Directory Busting (Recursive)")
    log("Phase 5: Starting Recursive Directory Busting...", "INFO")
    
    # Identify web ports to scan
    web_ports = []
    if 'recon' in results['phases'] and 'open_ports' in results['phases']['recon']:
        for p_info in results['phases']['recon']['open_ports']:
            svc = p_info.get('service_name', p_info.get('service', '')).lower()
            port_num = p_info.get('port')
            
            if svc in ['http', 'https', 'ssl/http', 'http-alt'] or port_num in [80, 443, 8080, 8443]:
                # Avoid duplicates
                if port_num not in web_ports:
                    web_ports.append(port_num)
    
    # Fallback
    if not web_ports: web_ports = [80, 443]

    try:
        if 'dirbusting' not in results['phases']: results['phases']['dirbusting'] = {}
        if 'ffuf' not in results['phases']['dirbusting']: results['phases']['dirbusting']['ffuf'] = {'endpoints': []}
        
        for port in web_ports:
            proto = 'https' if port in [443, 8443] or 'ssl' in str(port) else 'http'
            if port == 80: proto = 'http'
            
            log(f"Starting Ffuf on {proto}://{target}:{port}...", "INFO")
            
            scanner = FfufScanner(target)
            if not scanner.check_tools():
                log("Ffuf not found. Skipping.", "WARN")
                continue
                
            cmd = scanner.get_command(port, proto)
            results['commands'].append({'tool': 'ffuf', 'cmd': shlex.join(cmd)})
            
            try:
                stream = scanner.stream_fuzz(port, proto)
                
                for event in stream:
                    if event["type"] == "stdout":
                        line = event["line"].strip()
                        if not line: continue
                        
                        # Ffuf output format: [Status: 200, ... ] URL
                        # or just raw URL if configured?
                        # Default is roughly: "index.php [Status: 200, Size: 123...]"
                        # We just want to extract useful info.
                        
                        if "[Status: 200]" in line or "[Status: 301]" in line or "[Status: 403]" in line:
                             log(f"DirBust Found: {line}", "SUCCESS")
                             results['phases']['dirbusting']['ffuf']['endpoints'].append(line)
                             
                             orch.add_finding(
                                 title=f"Directory Discovered ({port})",
                                 description=f"Ffuf: {line}",
                                 severity="info",
                                 tool_source="ffuf"
                             )
                             orch.save_results(orch.scan_id, results)
                             
            except Exception as e:
                log(f"Ffuf error on port {port}: {e}", "ERROR")
                
    except Exception as e:
        log(f"Dirbusting phase failed: {e}", "ERROR")

    return True
