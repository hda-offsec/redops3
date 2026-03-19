import sys
import os

# Ensure the project root is in sys.path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from core.celery_app import celery
from core.extensions import db, socketio
from core.models import Scan, Finding, Signal, ScanLog, Suggestion
from modules.scanners.nmap_scan import NmapScannerAdvanced, NMAP_PROFILES
from parsers.nmap_parser import parse_nmap_xml
from engine.nmap_intelligence import NmapIntelligenceEngine
from scan_engine.helpers.finding_schema import normalize_finding_shape
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

@celery.task(bind=True, name='redops.nmap_scan')
def nmap_scan_task(self, scan_id, target, profile_name):
    # Setup App Context
    from app import create_app
    app = create_app()
    
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return "Scan not found"
            
        scan.status = 'running'
        db.session.commit()
        
        def _log(msg, level="INFO"):
            try:
                log = ScanLog(scan_id=scan_id, message=msg, level=level)
                db.session.add(log)
                db.session.commit()
                if socketio:
                    socketio.emit('new_log', {
                        'scan_id': scan_id,
                        'message': msg,
                        'level': level,
                        'timestamp': datetime.now().strftime('%H:%M:%S')
                    }, room=f"scan_{scan_id}")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to log/emit: {e}")
            
        _log(f"Starting advanced Nmap scan on {target} with profile {profile_name}", "SCAN_START")
        
        scanner = NmapScannerAdvanced(target, orchestrator=type('Orch', (), {'log': _log}))
        xml_output = ""
        
        try:
            stream = scanner.run_profile(profile_name)
            for event in stream:
                if event["type"] == "stdout":
                    line = event["line"]
                    xml_output += line + "\n"
                    # Emit live events
                    if "Discovered open port" in line:
                         _log(line, "PORT_OPEN")
                    elif "Scanning" in line:
                         _log(line, "INFO")
                elif event["type"] == "error":
                    _log(f"Nmap Error: {event['message']}", "ERROR")
                elif event["type"] == "exit":
                    _log(f"Nmap process exited with code {event.get('code')}", "INFO")
            
            # Parse results
            results = parse_nmap_xml(xml_output)
            
            for host in results:
                _log(f"Host discovered: {host['ip']}", "HOST_DISCOVERED")
                for port in host['ports']:
                    _log(f"Service detected on port {port['port']}: {port['service']} ({port['version']})", "SERVICE_DETECTED")
                    
                    # Create Finding
                    finding_data = {
                        "title": f"Service Detection: {port['service']} on {host['ip']} (Port {port['port']})",
                        "description": f"Target: {host['ip']}\nHostname: {host['hostname'] or 'N/A'}\nService: {port['service']}\nVersion: {port['version']}\nPort: {port['port']}\nState: {port['state']}",
                        "severity": "info",
                        "tool_source": "ScanNmap",
                        "tool": "nmap",
                        "target": target,
                        "endpoint": f"{host['ip']}:{port['port']}",
                        "category": "service_detection",
                        "metadata": {
                            "host_ip": host['ip'],
                            "hostname": host['hostname'],
                            "port": port['port'],
                            "port_state": port['state'],
                            "service": port['service'],
                            "version": port['version'],
                            "os": host['os'],
                            "command": f"nmap {NMAP_PROFILES[profile_name]['args']} {target}"
                        }
                    }
                    # Calculate Confidence Score
                    def calc_conf(m, c):
                        base = 50
                        if m == 'probed': base = 85
                        elif m == 'table': base = 40
                        try:
                            val = int(c)
                        except:
                            val = 3
                        return min(base + (val * 1.5), 100)
                    
                    conf_score = calc_conf(port.get('method', 'table'), port.get('conf', '3'))
                    finding_data["metadata"]["confidence_score"] = conf_score
                    finding_data["metadata"]["detection_method"] = port.get('method', 'unknown')

                    # Build raw metadata — do NOT go through normalize_finding_shape
                    # to avoid losing structured fields (metadata_json kwarg not picked up by SQLAlchemy init)
                    raw_meta = {
                        "host_ip": host['ip'],
                        "hostname": host['hostname'],
                        "port": port['port'],
                        "port_state": port['state'],
                        "service": port['service'],
                        "version": port['version'],
                        "os": host['os'],
                        "command": f"nmap {NMAP_PROFILES[profile_name]['args']} {target}",
                        "confidence_score": conf_score,
                        "detection_method": port.get('method', 'unknown'),
                    }
                    nmap_cmd = f"nmap {NMAP_PROFILES[profile_name]['args']} {target}"

                    new_finding = Finding(
                        scan_id=scan_id,
                        title=finding_data['title'],
                        description=finding_data['description'],
                        severity='info',
                        confidence='medium',
                        tool_source='ScanNmap',
                        tool='nmap',
                        module='nmap',
                        category='service_detection',
                        target=target,
                        endpoint=f"{host['ip']}:{port['port']}",
                        repro_command=nmap_cmd,
                    )
                    new_finding.metadata_json = raw_meta
                    db.session.add(new_finding)
                    
                    # Create Next Step Suggestions
                    p_num = int(port['port'])
                    suggestions = []
                    if p_num in [80, 443, 8080, 8443]:
                        suggestions.append(Suggestion(scan_id=scan_id, tool_name="Katana", command_suggestion=f"./katana -u {host['ip']} -jc", reason="Web port detected: Surface crawling recommended"))
                        suggestions.append(Suggestion(scan_id=scan_id, tool_name="Nuclei", command_suggestion=f"nuclei -u {host['ip']}", reason="Web service exposure: Automated vulnerability scan recommended"))
                    elif p_num in [445, 139]:
                        suggestions.append(Suggestion(scan_id=scan_id, tool_name="SMB-Enum", command_suggestion=f"nmap --script smb-enum-shares,smb-enum-users -p {p_num} {host['ip']}", reason="SMB port detected: Share and User enumeration recommended"))
                    elif p_num in [3306, 5432, 1433]:
                        suggestions.append(Suggestion(scan_id=scan_id, tool_name="DB-Audit", command_suggestion=f"nmap --script mysql-info,mysql-empty-password -p {p_num} {host['ip']}", reason="Database port detected: Access policy audit recommended"))
                    elif p_num == 22:
                        suggestions.append(Suggestion(scan_id=scan_id, tool_name="SSH-Audit", command_suggestion=f"ssh-audit {host['ip']}", reason="SSH port detected: Algorithm and key exchange audit recommended"))
                    
                    for sug in suggestions:
                        db.session.add(sug)
                    
                    db.session.commit()
                    
                    # Emit to UI
                    if socketio:
                        socketio.emit('new_finding', {
                            'scan_id': scan_id,
                            'id': new_finding.id,
                            'id_stable': new_finding.id_stable,
                            'title': new_finding.title,
                            'description': new_finding.description,
                            'severity': new_finding.severity,
                            'tool': new_finding.tool,
                            'category': new_finding.category,
                            'metadata': filtered_data['metadata_json']
                        }, room=f"scan_{scan_id}")
                        
                        # Also emit suggestions specifically for real-time dashboard
                        for sug in suggestions:
                            socketio.emit('new_suggestion', {
                                'scan_id': scan_id,
                                'tool_name': sug.tool_name,
                                'command_suggestion': sug.command_suggestion,
                                'reason': sug.reason
                            }, room=f"scan_{scan_id}")
                    
                    # Intelligence Engine: Automated targeted scripts
                    targeted_scripts = NmapIntelligenceEngine.get_scripts_for_service(port['service'])
                    if targeted_scripts:
                        _log(f"Intelligence Engine: Launching targeted NSE for {port['service']}: {','.join(targeted_scripts)}", "NSE_LAUNCHED")
                        
                        # Run targeted NSE
                        nse_cmd = ["nmap", "-Pn", "--script", ",".join(targeted_scripts), "-p", str(port['port']), target, "-oX", "-"]
                        from scan_engine.helpers.process_manager import ProcessManager
                        success, nse_out, nse_err, _ = ProcessManager.run_command(nse_cmd)
                        
                        if success:
                            nse_results = parse_nmap_xml(nse_out)
                            for nse_host in nse_results:
                                for nse_port in nse_host['ports']:
                                    for script in nse_port['scripts']:
                                        _log(f"NSE Result for {script['id']}: {script['output'][:100]}...", "NSE_RESULT")
                                        # Add finding for NSE result
                                        out_low = script['output'].lower()
                                        nse_severity = 'info'
                                        if any(k in out_low for k in ["vulnerable", "exploit", "critical", "compromise"]):
                                            nse_severity = 'critical'
                                        elif any(k in out_low for k in ["vuln", "exposed", "warning", "weak"]):
                                            nse_severity = 'high'

                                        nse_raw_meta = {
                                            "host_ip": host['ip'],
                                            "hostname": host['hostname'],
                                            "script_id": script['id'],
                                            "port": port['port'],
                                            "command": " ".join(nse_cmd),
                                            "script_output": script['output'],
                                        }

                                        nse_finding = Finding(
                                            scan_id=scan_id,
                                            title=f"NSE: {script['id']} on {host['ip']}",
                                            description=f"Target: {host['ip']}\nHostname: {host['hostname'] or 'N/A'}\nScript: {script['id']}\nPort: {port['port']}\n\nOutput:\n{script['output']}",
                                            severity=nse_severity,
                                            confidence='medium',
                                            tool_source='ScanNmap',
                                            tool='nmap-nse',
                                            module='nmap-nse',
                                            category='nse_result',
                                            target=target,
                                            endpoint=f"{host['ip']}:{port['port']}",
                                            repro_command=" ".join(nse_cmd),
                                        )
                                        nse_finding.metadata_json = nse_raw_meta
                                        db.session.add(nse_finding)
                                        db.session.commit()
                                        
                                        # Emit to UI
                                        if socketio:
                                            socketio.emit('new_finding', {
                                                'scan_id': scan_id,
                                                'id': nse_finding.id,
                                                'id_stable': nse_finding.id_stable,
                                                'title': nse_finding.title,
                                                'description': nse_finding.description,
                                                'severity': nse_finding.severity,
                                                'tool': nse_finding.tool,
                                                'category': nse_finding.category,
                                                'metadata': nse_raw_meta
                                            }, room=f"scan_{scan_id}")

                                            
                    # SSL Certificate Intelligence (Point 4: SAN Extraction)
                    if any(s in port['service'].lower() for s in ['ssl', 'https', 'imaps', 'pop3s', 'smtps']):
                        try:
                            import ssl
                            import socket
                            _log(f"Intelligence Engine: Extracting SSL Cert for {host['ip']}:{port['port']}", "DEBUG")
                            # We need a context that doesn't check hostname but allows gettingcert
                            # To get cert info without full validation, we might need to handle binary form
                            # or just use a basic connection
                            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            
                            with socket.create_connection((host['ip'], int(port['port'])), timeout=3) as sock:
                                with ctx.wrap_socket(sock, server_hostname=host['ip']) as ssock:
                                    # getpeercert() returns None if not validated unless we use binary_form=True
                                    # But parsing binary cert involves cryptography lib.
                                    # Let's try to get what we can.
                                    # In many cases, we can get cert even without validation if we configure ctx right.
                                    # Actually, ssl lib behavior varies. Let's try to grab subjectAltName if available.
                                    cert = ssock.getpeercert()
                                    if not cert:
                                        # Peer certification requires validation for dict return. 
                                        # Let's try a simpler approach if needed or just provide the Finding if successful connection.
                                        pass
                                    else:
                                        sans = [entry[1] for entry in cert.get('subjectAltName', []) if entry[0] == 'DNS']
                                        if sans:
                                            _log(f"SSL Intelligence: Found {len(sans)} SAN domains on {host['ip']}", "OSINT_DISCOVERY")
                                            san_finding_data = {
                                                "title": f"SSL Intelligence: SAN Identity on {host['ip']}",
                                                "description": f"Target: {host['ip']}\nAssociated Domains Found in Certificate:\n- " + "\n- ".join(sans),
                                                "severity": "info",
                                                "tool_source": "ScanNmap",
                                                "tool": "ssl_intel",
                                                "category": "osint",
                                                "metadata": {
                                                    "sans": sans,
                                                    "host_ip": host['ip'],
                                                    "port": port['port']
                                                }
                                            }
                                            norm_san = normalize_finding_shape(san_finding_data)
                                            san_f = Finding(scan_id=scan_id, **{k: norm_san[k] for k in model_fields if k in norm_san})
                                            san_f.metadata_json = norm_san.get('metadata')
                                            db.session.add(san_f)
                                            db.session.commit()
                                            
                                            if socketio:
                                                socketio.emit('new_finding', {
                                                    'scan_id': scan_id,
                                                    'id': san_f.id,
                                                    'title': san_f.title,
                                                    'severity': san_f.severity,
                                                    'tool': san_f.tool,
                                                    'category': san_f.category,
                                                    'metadata': san_f.metadata_json
                                                }, room=f"scan_{scan_id}")

                        except Exception as e:
                            logger.debug(f"SSL Intel extraction failed for {host['ip']}: {e}")
                                            
            scan.status = 'completed'
            db.session.commit()
            _log("ScanNmap complete.", "SCAN_COMPLETE")
            
        except Exception as e:
            db.session.rollback()
            _log(f"ScanNmap failed: {str(e)}", "ERROR")
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'failed'
                db.session.commit()
            
        return "ScanNmap Finished"
