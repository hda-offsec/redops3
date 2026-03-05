import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import shlex
from core.scan_profiles import SCAN_PROFILES
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.step01_recon.dns_scanner import DNSScanner
from scan_engine.step00_osint.cloud_scanner import CloudScanner
from scan_engine.step00_osint.favicon_scanner import FaviconScanner
from scan_engine.step00_osint.github_scanner import GitHubScanner
from scan_engine.step00_osint.email_scanner import EmailScanner
from scan_engine.step00_osint.dork_scanner import DorkScanner
from scan_engine.step00_osint.origin_revealer import OriginRevealer
from scan_engine.step00_osint.historic_scanner import HistoricScanner
from scan_engine.phases.utils import emit_progress


def run_recon(orchestrator):
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log

    emit_progress(orch, 20, "Port Scanning (nmap)")
    log("Phase 1: Starting Recon (Standard Nmap)...", "INFO")
    scanner = NmapScanner(target)

    if not scanner.check_tools():
        log("CRITICAL: 'nmap' not found in system path! Please install it.", "ERROR")
        return False

    scan_args = []
    found_profile = False
    profile = orch.options.get('profile', 'quick')

    for category, profiles in SCAN_PROFILES.items():
        if profile in profiles:
            raw_args = profiles[profile]['args']
            scan_args = raw_args.split()
            log(f"Using profile '{profile}': {raw_args}", "INFO")
            found_profile = True
            break

    if not found_profile:
        if profile == 'quick':
            scan_args = ["-T4", "--top-ports", "100"]
        elif profile == 'full':
            scan_args = ["-p-", "-T4"]
        elif profile == 'vuln':
            scan_args = ["--script", "vuln"]
        else:
            log(f"Unknown profile '{profile}', defaulting to quick scan.", "WARN")
            scan_args = ["-F"]

    log(f"Executing Nmap with: {shlex.join(scan_args)}", "DEBUG")
    orch.thread_safe_results_update(lambda: results.setdefault('commands', []).append({'tool': 'nmap', 'cmd': shlex.join(['nmap'] + scan_args + [target])}))

    try:
        stream = scanner.stream_scan(scan_args)
    except Exception as e:
        log(f"Failed to start nmap: {str(e)}", "ERROR")
        return False

    output_buffer = []
    for event in stream:
        if event["type"] == "stdout":
            line = event["line"].strip()
            if not line:
                continue
            if "Discovered open port" in line:
                log(line, "SUCCESS")
            elif "Nmap scan report for" in line:
                log(line, "INFO")
            output_buffer.append(line)
        elif event["type"] == "error":
            log(f"Nmap Error: {event['message']}", "ERROR")
        elif event["type"] == "exit":
            if event["code"] != 0:
                log("external_tool_non_zero_exit_code", "DEBUG")

    def _store_recon_output():
        results.setdefault('phases', {}).setdefault('recon', {})
        results['phases']['recon']['raw_output'] = "\n".join(output_buffer)

    orch.thread_safe_results_update(_store_recon_output)

    from scan_engine.helpers.output_parsers import parse_nmap_open_ports, parse_nmap_full_output
    raw_out = "\n".join(output_buffer)
    discovered_ports = parse_nmap_open_ports(raw_out)
    full_intelligence = parse_nmap_full_output(raw_out)

    if not discovered_ports:
        log("No open ports found via Nmap. Checking if host is up...", "WARN")
        discovered_ports = probe_web_ports(orch)
    else:
        # Merge intelligence into discovered_ports
        for p_info in discovered_ports:
            port_num = p_info.get("port")
            if port_num in full_intelligence.get("ports_metadata", {}):
                p_info.update(full_intelligence["ports_metadata"][port_num])
                # Add default OS if same for all
                if full_intelligence["enriched"]["os_details"]["accuracy"] > 80:
                    p_info["os_guess"] = full_intelligence["enriched"]["os_details"]["os"]
        
        def _store_enriched():
            recon = results['phases']['recon']
            recon['open_ports'] = discovered_ports
            recon['enriched'] = full_intelligence["enriched"]
            
        orch.thread_safe_results_update(_store_enriched)
        log(f"Final Open Ports: {len(discovered_ports)} (Enriched with {len(full_intelligence['enriched']['vuln_hints'])} vuln hints)", "SUCCESS")

    orch.save_results(orch.scan_id, results)
    return discovered_ports


def probe_web_ports(orchestrator):
    orch = orchestrator
    log = orch.log
    target = orch.target

    log("Attempting Web-Port Fallback (80/443)...", "WARN")
    fallback_ports = [80, 443]
    open_ports = []

    for fp in fallback_ports:
        proto = "https" if fp == 443 else "http"
        url = f"{proto}://{target}:{fp}"
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"}
            resp = http_client.get(url, options=getattr(orch, "options", None), timeout=5, allow_redirects=True, headers=headers)
            log(f"  [+] Fallback: Target is ALIVE on {url} (Status: {resp.status_code})", "SUCCESS")
            open_ports.append({
                "port": fp,
                "service": "http" if fp == 80 else "ssl/http",
                "service_name": "http" if fp == 80 else "ssl/http",
                "version": f"Detected via Fallback (Status: {resp.status_code})",
                "priority_score": 70
            })
        except Exception as e:
            log(f"Fallback probe failed for {url}: {e}", "DEBUG")

    if open_ports:
        log(f"Fallback discovery: {len(open_ports)} open ports.", "SUCCESS")

        def _update_fallback_ports():
            orch.results.setdefault('phases', {}).setdefault('recon', {})
            orch.results['phases']['recon']['open_ports'] = open_ports

        orch.thread_safe_results_update(_update_fallback_ports)
        orch.save_results(orch.scan_id, orch.results)

    return open_ports


def run_dns_osint(orchestrator):
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log

    emit_progress(orch, 30, "DNS Enumeration")
    log(f"Phase 2: DNS Enumeration on {target}...", "INFO")

    def _reset_dns_osint():
        results.setdefault('phases', {}).setdefault('dns', {})
        results['phases']['dns']['subdomains'] = []
        results['phases']['dns']['records'] = []
        results['phases'].setdefault('osint', {})
        results['phases']['osint']['cloud'] = []
        results['phases']['osint']['emails'] = []
        results['phases']['osint']['github'] = []

    orch.thread_safe_results_update(_reset_dns_osint)

    try:
        dns_scanner = DNSScanner(target)
        dns_data = dns_scanner.enumerate_all(logger=log)
        subdomains = dns_data.get('subdomains', [])

        def _store_dns():
            results.setdefault('phases', {}).setdefault('dns', {})
            results['phases']['dns']['subdomains'] = subdomains
            results['phases']['dns']['records'] = dns_data.get('records', [])
            results['phases']['dns']['security'] = dns_data.get('security', {})

        orch.thread_safe_results_update(_store_dns)

        if subdomains:
            log(f"Found {len(subdomains)} subdomains.", "SUCCESS")
            # V10: Surface subdomain discovery as INFO finding
            sub_list = ", ".join(subdomains[:10])
            orch.add_finding(
                title=f"Subdomains Discovered ({len(subdomains)})",
                description=f"DNS enumeration found {len(subdomains)} subdomains:\n{sub_list}" + (f"\n...and {len(subdomains)-10} more" if len(subdomains) > 10 else ""),
                severity="info",
                tool_source="dns_enum"
            )
            if orch.options.get('recursive') and orch.recursion_func:
                depth = orch.options.get('current_recursion_depth', 0)
                max_depth = orch.options.get('max_recursion_depth', 1)
                try:
                    orch.recursion_func(subdomains, orch.scan_id, depth, max_depth)
                except Exception as e:
                    log(f"Failed to trigger recursion: {e}", "ERROR")
        else:
            log("No subdomains found for this target root.", "INFO")

        # V10: Surface DNS records as INFO finding
        records = dns_data.get('records', [])
        if records:
            rec_summary = ", ".join([f"{r.get('type','?')}: {r.get('value','')}" for r in records[:10] if isinstance(r, dict)])
            orch.add_finding(
                title=f"DNS Records ({len(records)})",
                description=f"DNS enumeration found {len(records)} records:\n{rec_summary}",
                severity="info",
                tool_source="dns_enum"
            )

        orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"DNS Enumeration failed: {e}", "ERROR")

    try:
        cloud = CloudScanner(target, dns_subdomains=subdomains)
        assets = cloud.scan_all(logger=log)
        if assets:
            log(f"Found {len(assets)} cloud assets.", "SUCCESS")
            orch.thread_safe_results_update(lambda: results['phases'].setdefault('osint', {}).__setitem__('cloud', assets))
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Cloud scan failed: {e}", "DEBUG")

    try:
        email_scanner = EmailScanner(target)
        emails = email_scanner.scan()
        if emails:
            log(f"Found {len(emails)} emails.", "SUCCESS")
            orch.thread_safe_results_update(lambda: results['phases']['osint'].__setitem__('emails', emails))
            # V10: Surface email OSINT as INFO finding
            email_list = ", ".join(emails[:5]) if isinstance(emails[0], str) else ", ".join([e.get('email','') for e in emails[:5]])
            orch.add_finding(
                title=f"OSINT: Email Addresses ({len(emails)})",
                description=f"Email enumeration discovered {len(emails)} addresses:\n{email_list}",
                severity="info",
                tool_source="email_osint"
            )
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Email scan failed: {e}", "DEBUG")

    try:
        gh_scanner = GitHubScanner(target)
        leaks = gh_scanner.search_leaks(logger=log)
        if leaks:
            log(f"Found {len(leaks)} GitHub leaks.", "SUCCESS")
            orch.thread_safe_results_update(lambda: results['phases']['osint'].__setitem__('github', leaks))
            # V10: Surface GitHub leaks as finding
            orch.add_finding(
                title=f"GitHub Intelligence ({len(leaks)} results)",
                description=f"GitHub OSINT found {len(leaks)} potential code/secret exposures for {target}.",
                severity="low",
                tool_source="github_osint"
            )
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"GitHub scan failed: {e}", "DEBUG")

    try:
        fav_scanner = FaviconScanner(target)
        fav_data = fav_scanner.scan()
        if fav_data:
            log("Favicon analysis complete.", "SUCCESS")
            orch.thread_safe_results_update(lambda: results['phases']['osint'].__setitem__('favicon', fav_data))
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Favicon scan failed: {e}", "DEBUG")

    try:
        dork_scanner = DorkScanner(target)
        dorks = dork_scanner.scan()
        if dorks:
            log("Google Dorks generated.", "SUCCESS")
            orch.thread_safe_results_update(lambda: results['phases']['osint'].__setitem__('dorks', dorks))
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Dork scan failed: {e}", "DEBUG")

    try:
        revealer = OriginRevealer(target)
        origins = revealer.scan()
        if origins:
            log(f"Origin IPs detected: {len(origins)}", "SUCCESS")
            orch.thread_safe_results_update(lambda: results['phases']['osint'].__setitem__('origin_ips', origins))
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Origin IP scan failed: {e}", "DEBUG")

    emit_progress(orch, 35, "Wayback Historic Discovery")
    try:
        historic = HistoricScanner(target, logger=log)
        raw_urls = historic.fetch_historic_urls()
        if raw_urls:
            candidates = historic.process_discovered_urls(raw_urls)
            def _store_historic():
                results['phases']['osint']['historic_urls'] = candidates
                # Also seed them into potential enum targets (grouped correctly for UI)
                results['phases'].setdefault('enum', {}).setdefault('targets', {})
                results['phases']['enum']['targets'].setdefault('Historic', [])
                for u in candidates[:100]: # Cap seeding to 100 to avoid bloat
                    if u not in results['phases']['enum']['targets']['Historic']:
                        results['phases']['enum']['targets']['Historic'].append(u)
            orch.thread_safe_results_update(_store_historic)
            orch.save_results(orch.scan_id, results)
    except Exception as e:
        log(f"Historic URL scan failed: {e}", "DEBUG")
