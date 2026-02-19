import shlex
from core.intelligence import AttackVectorMapper
from core.screenshots import take_service_screenshot
from scan_engine.phases.utils import emit_progress

def run_intel(orchestrator):
    """
    Executes Phase 3/6: Intelligence & Attack Vector Mapping
    - Query Intelligence Engine
    - Map Attack Vectors
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    
    # --- PHASE 3: Deep Analysis & Attack Vector Mapping ---
    emit_progress(orch, 50, "Intel Mapping")
    try:
        log("Phase 3: Querying Intelligence Engine for Attack Vectors...", "INFO")
        
        # Report open ports summary
        open_ports = results.get('phases', {}).get('recon', {}).get('open_ports', [])
        
        if open_ports:
            orch.add_finding(
                title=f"Open Ports Detected ({len(open_ports)})",
                description=f"Services found:\n" + "\n".join([f"{p['port']}/{p.get('protocol', 'tcp')} - {p['service']}" for p in open_ports]),
                severity="info",
                tool_source="nmap"
            )

            # Map Attack Vectors
            vectors = []
            for p in open_ports:
                 # Ensure we handle potential missing keys gracefully
                 service = p.get('service', 'unknown')
                 version = p.get('version', '')
                 port = p.get('port', 0)
                 
                 v_list = AttackVectorMapper.analyze_service(service, version, port)
                 if v_list:
                     vectors.extend(v_list)
            
            if vectors:
                 log(f"Mapped {len(vectors)} potential attack vectors.", "SUCCESS")
                 def _store_vectors():
                     if 'intel' not in results['phases']:
                         results['phases']['intel'] = {}
                     results['phases']['intel']['attack_vectors'] = vectors
                 orch.thread_safe_results_update(_store_vectors)
                 orch.save_results(orch.scan_id, results)
                 
                 for v in vectors:
                     orch.add_suggestion(
                         tool_name="Manual Verification",
                         command_suggestion=v.get('commands', v.get('action', 'Check manually')),
                         reason=f"Vector: {v.get('name')} identified on {p.get('port', 'target')}"
                     )

            # --- Visual Recon (Screenshots) ---
            log("Phase 3+: Capturing Visual Evidence (Screenshots)...", "INFO")
            for p in open_ports:
                port = p['port']
                service = p['service']
                # Check if it's a web port
                if 'http' in service or port in [80, 443, 8080, 8443]:
                     try:
                        # Update status
                        orch.thread_safe_results_update(lambda: p.__setitem__('screenshot_path', 'pending'))
                        orch.save_results(orch.scan_id, results) # Save pending state
                        
                        shot_path = take_service_screenshot(orch.scan_id, port, target)
                        if shot_path:
                            log(f"Screenshot captured for port {port}.", "SUCCESS")
                            orch.thread_safe_results_update(lambda: p.__setitem__('screenshot_path', shot_path))
                        else:
                            orch.thread_safe_results_update(lambda: p.__setitem__('screenshot_path', None))
                            
                     except Exception as e:
                         log(f"Screenshot failed for port {port}: {e}", "WARN")
                         orch.thread_safe_results_update(lambda: p.__setitem__('screenshot_path', None))
            
            # Save final screenshot states
            orch.save_results(orch.scan_id, results)
            
        else:
             log("No open ports to map vectors or screenshot.", "INFO")
             
    except Exception as e:
        log(f"Attack Vector Mapping failed: {e}", "WARN")
