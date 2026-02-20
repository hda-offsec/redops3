import shlex
from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner
from scan_engine.phases.utils import emit_progress


def run_dirbusting(orchestrator):
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    profile = orch.options.get('profile', 'quick')
    is_quick = profile.startswith('quick')

    emit_progress(orch, 90, "Directory Busting (Recursive)")
    log("Phase 5: Starting Recursive Directory Busting...", "INFO")

    web_ports = []
    if 'recon' in results['phases'] and 'open_ports' in results['phases']['recon']:
        for p_info in results['phases']['recon']['open_ports']:
            svc = p_info.get('service', p_info.get('service_name', '')).lower()
            port_num = p_info.get('port')
            if svc in ['http', 'https', 'ssl/http', 'http-alt'] or port_num in [80, 443, 8080, 8443]:
                if port_num not in web_ports:
                    web_ports.append(port_num)

    if not web_ports:
        web_ports = [80, 443]

    try:
        def _init_dirbusting():
            results.setdefault('phases', {}).setdefault('dirbusting', {})
            results['phases']['dirbusting'].setdefault('ffuf', {})
            results['phases']['dirbusting']['ffuf'].setdefault('endpoints', [])

        orch.thread_safe_results_update(_init_dirbusting)

        for port in web_ports:
            proto = 'https' if port in [443, 8443] or 'ssl' in str(port) else 'http'
            if port == 80:
                proto = 'http'

            log(f"Starting Ffuf on {proto}://{target}:{port}...", "INFO")

            scanner = FfufScanner(target)
            if not scanner.check_tools():
                log("Ffuf not found. Skipping.", "WARN")
                orch.mark_module("ffuf", port, "skipped")
                continue

            cmd = scanner.get_command(port, proto, quick=is_quick)
            orch.thread_safe_results_update(lambda: results['commands'].append({'tool': 'ffuf', 'cmd': shlex.join(cmd)}))

            try:
                stream = scanner.stream_fuzz(port, proto, quick=is_quick)
                found_count = 0

                for event in stream:
                    if event["type"] == "stdout":
                        line = event["line"].strip()
                        if not line or not line.startswith('{'):
                            continue

                        try:
                            import json
                            data = json.loads(line)
                            url = data.get('url')
                            if not url: continue
                            
                            status = data.get('status', 200)
                            log(f"DirBust Found: {url} [Status: {status}]", "SUCCESS")

                            item = {"url": url, "path": data.get('input', {}).get('FUZZ', ''), "status": status}

                            def _append_endpoint():
                                results['phases'].setdefault('dirbusting', {})
                                results['phases']['dirbusting'].setdefault('ffuf', {})
                                results['phases']['dirbusting']['ffuf'].setdefault('endpoints', [])
                                existing = {e.get("url") for e in results['phases']['dirbusting']['ffuf']['endpoints'] if isinstance(e, dict)}
                                if item["url"] not in existing:
                                    results['phases']['dirbusting']['ffuf']['endpoints'].append(item)
                                    return 1
                                return 0

                            found_count += orch.thread_safe_results_update(_append_endpoint)

                            orch.add_finding(
                                title=f"Directory Discovered ({port})",
                                description=f"Ffuf: {url} [Status: {status}]",
                                severity="info",
                                tool_source="ffuf"
                            )
                            orch.save_results(orch.scan_id, results)
                        except Exception:
                            continue

                orch.mark_module("ffuf", port, "executed", artifacts=found_count)
                orch.add_finding(title="Module Executed: ffuf", description=f"Ffuf directory busting finished on port {port}", severity="info", tool_source="redops-core")

            except Exception as e:
                log(f"Ffuf error on port {port}: {e}", "ERROR")
                orch.mark_module("ffuf", port, "failed")

    except Exception as e:
        log(f"Dirbusting phase failed: {e}", "ERROR")

    return True
