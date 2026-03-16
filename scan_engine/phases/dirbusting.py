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

            fs_val = None
            fw_val = None
            try:
                import scan_engine.helpers.http_client as http_client
                import uuid
                test_url = f"{proto}://{target}:{port}/this_is_a_404_custom_test_{uuid.uuid4().hex[:8]}"
                r_404 = http_client.get(test_url, options=getattr(orch, "options", None), timeout=5)
                # Fallback on fs if target returns explicit status for a dead page (often 200, 403 or 404 but with uniform logic)
                if r_404.status_code in [200, 401, 403, 404]:
                    fs_val = len(r_404.content)
                    fw_val = len(r_404.text.split())
                    log(f"Ffuf: Custom 404 baseline established (Size: {fs_val}, Words: {fw_val}). Target returns {r_404.status_code} for missing pages.", "INFO")
            except Exception as e:
                log(f"Ffuf: Failed to probe 404 baseline ({e}). Falling back to -ac.", "DEBUG")

            cmd = scanner.get_command(port, proto, quick=is_quick, fs=fs_val, fw=fw_val)
            orch.thread_safe_results_update(lambda: results['commands'].append({'tool': 'ffuf', 'cmd': shlex.join(cmd)}))

            try:
                from scan_engine.helpers.process_manager import ProcessManager
                stream = scanner.stream_fuzz(port, proto, quick=is_quick, fs=fs_val, fw=fw_val)
                found_count = 0

                for event in stream:
                    if event["type"] == "stdout":
                        line = ProcessManager.strip_ansi(event["line"]).strip()
                        if not line or line.startswith("::") or line.startswith("["):
                            continue

                        # Parse Ffuf real-time standard output instead of JSON
                        # Format: admin                   [Status: 200, Size: 111, Words: 22, Lines: 33, Duration: 40ms]
                        if "[Status:" in line and "Size:" in line:
                            try:
                                parts = line.split("[Status:")
                                fuzz_val = parts[0].strip()
                                stats = parts[1]
                                
                                status = int(stats.split(",")[0].strip())
                                size_part = stats.split("Size:")[1].split(",")[0].strip()
                                size = int(size_part)
                                
                                url = f"{proto}://{target}:{port}/{fuzz_val}"
                                
                                log(f"DirBust Found: {url} [Status: {status}]", "SUCCESS")

                                item = {"url": url, "path": fuzz_val, "status": status, "size": size}

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
                                    title=f"Directory Discovered: /{fuzz_val} ({port})",
                                    description=f"Ffuf discovered endpoint: {url} [Status: {status}]",
                                    severity="info",
                                    tool_source="ffuf",
                                    endpoint=url
                                )
                                orch.save_results(orch.scan_id, results)
                            except Exception as e:
                                log(f"Failed to parse Ffuf line: {e}", "DEBUG")

                orch.mark_module("ffuf", port, "executed", artifacts=found_count)

            except Exception as e:
                log(f"Ffuf error on port {port}: {e}", "ERROR")
                orch.mark_module("ffuf", port, "failed")

    except Exception as e:
        log(f"Dirbusting phase failed: {e}", "ERROR")

    return True
