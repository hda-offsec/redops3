import shlex
import time
import os
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
from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
from scan_engine.step03_vuln.cors_scanner import CORSScanner
from scan_engine.step03_vuln.lfi_assault import LfiAssaultScanner
from scan_engine.step03_vuln.spring_boot_scanner import SpringBootScanner
from scan_engine.step03_vuln.crlf_scanner import CRLFScanner
from scan_engine.step03_vuln.firebase_scanner import FirebaseScanner
from scan_engine.step03_vuln.xxe_scanner import XXEScanner
from scan_engine.step03_vuln.deserialization_scanner import DeserializationScanner
from scan_engine.step03_vuln.acl_scanner import AccessControlScanner
from scan_engine.step03_vuln.email_security_scanner import EmailSecurityScanner
from scan_engine.step03_vuln.kube_docker_scanner import KubeDockerScanner
from scan_engine.step03_vuln.websocket_scanner import WebSocketScanner
from scan_engine.step03_vuln.prototype_pollution_scanner import PrototypePollutionScanner
from scan_engine.step03_vuln.data_miner import SensitiveDataMiner
from scan_engine.step03_vuln.secret_scanner import SecretScanner
from scan_engine.step03_vuln.tech_exposure_scanner import TechExposureScanner
from scan_engine.step03_vuln.api_expert_scanner import APIExpertScanner
from scan_engine.step03_vuln.db_scanner import DBScanner
from scan_engine.step03_vuln.logic_assault import LogicAssaultScanner
from scan_engine.step03_vuln.waf_bypass_scanner import WafBypassScanner
from scan_engine.step03_vuln.cloud_perm_scanner import CloudPermScanner
from scan_engine.step03_vuln.surface_mapper import SurfaceMapperScanner
from scan_engine.phases.utils import extract_wp_data, emit_progress
from scan_engine.helpers.mutation_engine import MutationEngine
from scan_engine.helpers.budget_manager import BudgetManager
from scan_engine.helpers.finding_normalizer import FindingNormalizer

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

    def _ts(fn):
        return orch.thread_safe_results_update(fn)

    # Initialize Mutation Layer & Strategy
    budget = BudgetManager(max_seeds=200, max_total_variants=1000)
    mutation_engine = MutationEngine(budget, logger=log)
    normalizer = FindingNormalizer()
    
    # --- DATA RECOVERY: Fetch fingerprint from results if empty ---
    if not fingerprint_data:
        whatweb_summary = results.get('phases', {}).get('enum', {}).get('whatweb', {}).get('summary', {}).get(str(port), "")
        if whatweb_summary:
            fingerprint_data = whatweb_summary
            log(f"Recovered fingerprint data from WhatWeb results ({len(fingerprint_data)} bytes).", "DEBUG")
    
    # Retrieve pre-computed intelligence from Strategic Analysis (Phase 2.5)
    mutation_strategy = results.get('phases', {}).get('enum', {}).get('mutation_strategy', {}).get(str(port), {})
    execution_hints = results.get('phases', {}).get('enum', {}).get('derived', {}).get('execution_hints', {})
    execution_hints = execution_hints if isinstance(execution_hints, dict) else {}
    
    # --- V6 ADVANCED: SURFACE EXPANSION INTEGRATION ---
    surface_expansion = results.get('phases', {}).get('enum', {}).get('derived', {}).get('surface_expansion', {})
    port_expansion = surface_expansion.get('per_port', {}).get(str(port), {})
    derived_endpoints = port_expansion.get('derived_endpoints', [])
    
    # Normalize derived endpoints to full URLs
    expansion_urls = []
    base_url = f"{proto}://{target}:{port}"
    for ep in derived_endpoints:
        if ep.startswith('/'):
            expansion_urls.append(f"{base_url}{ep}")
        elif ep.startswith('http'):
            expansion_urls.append(ep)
        else:
            expansion_urls.append(f"{base_url}/{ep}")
    
    if expansion_urls:
        log(f"Surface Expander: Injecting {len(expansion_urls)} heuristic endpoints into vulnerability phase.", "SUCCESS")


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
        emit_progress(orch, 75, f"Application Audit (WordPress) on {port}")
        log(f"WordPress signature detected on port {port}. Initiating WPScan...", "WARN")
        try:
            wpscan = WPScanScanner(target)
            if not wpscan.check_tools():
                log("Skipping WPScan: tool not installed.", "WARN")
                orch.mark_module("wpscan", port, "skipped")
            else:
                enumerate_all = False if profile.startswith('quick') else True
                wp_stream = wpscan.stream_scan(port, proto, enumerate_all=enumerate_all)
                
                # Use shared utility for parsing
                wp_data, wp_raw_log = extract_wp_data(wp_stream, port, log)
                
                if wp_data:
                    def _store_wp():
                        if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                        if 'wordpress' not in results['phases']['vuln']: results['phases']['vuln']['wordpress'] = {}
                        results['phases']['vuln']['wordpress'][str(port)] = wp_data

                        if 'wpscan' not in results['phases']['vuln']: results['phases']['vuln']['wpscan'] = {}
                        results['phases']['vuln']['wpscan'][str(port)] = wp_raw_log

                        # Backward compatibility
                        results['phases']['vuln']['wordpress'] = results['phases']['vuln'].get('wordpress', {})
                        results['phases']['vuln']['wordpress'][str(port)] = wp_data
                    _ts(_store_wp)
                    
                    orch.save_results(orch.scan_id, results)

                    if wp_data['vulns']:
                        # Build rich description with component context
                        vuln_lines = []
                        for v in wp_data['vulns']:
                            component = v.get('component', 'Unknown')
                            raw = v.get('raw_title', v.get('title', 'Vuln'))
                            fixed = v.get('fixed_in', '')
                            entry = f"• [{component}] {raw}"
                            if fixed and fixed != "Check WPScan":
                                entry += f" (fixed in {fixed})"
                            vuln_lines.append(entry)

                        # Also list detected plugins with versions
                        plugin_summary = ""
                        if wp_data['plugins']:
                            plugin_lines = []
                            for p in wp_data['plugins']:
                                pline = f"  - {p['slug']} v{p['version']}"
                                if p.get('latest_version'):
                                    pline += f" (latest: {p['latest_version']})"
                                if p.get('vulns'):
                                    pline += f" ⚠ {len(p['vulns'])} issue(s)"
                                plugin_lines.append(pline)
                            plugin_summary = "\n\nPlugins Detected:\n" + "\n".join(plugin_lines)

                        desc = (
                            f"WPScan detected {len(wp_data['vulns'])} issue(s):\n\n"
                            + "\n".join(vuln_lines)
                            + plugin_summary
                            + f"\n\nWordPress v{wp_data['version']} | Theme: {wp_data['theme']}"
                        )

                        orch.add_finding(
                            title=f"WordPress Vulnerabilities Detected ({port})",
                            description=desc,
                            severity="high",
                            tool_source="wpscan"
                        )
                
                orch.mark_module("wpscan", port, "executed", artifacts=1)
                orch.add_finding(title=f"Module Executed: wpscan", description=f"WPScan finished on port {port}", severity="info", tool_source="redops-core")
                
        except Exception as e:
            log(f"WPScan failed: {e}", "ERROR")
            orch.mark_module("wpscan", port, "failed", reason=str(e))

    # --- SENSITIVE DIR AUDIT (.git, etc.) ---
    try:
        gs = GitExposureScanner(target)
        gs_findings = gs.audit_git(port, proto, logger=log)
        if gs_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('git', gs_findings)))
            for f in gs_findings:
                orch.add_finding(
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="git_scanner"
                )
            orch.save_results(orch.scan_id, results)
        
        orch.mark_module("git_scanner", port, "executed", artifacts=len(gs_findings) if gs_findings else 0)
        orch.add_finding(title=f"Module Executed: git_scanner", description=f"Git exposure audit finished on port {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"Git exposure audit failed on port {port}: {e}", "DEBUG")
        orch.mark_module("git_scanner", port, "failed")

    # --- EXPERT: Backup & Archive Audit ---
    try:
        bs = BackupScanner(target)
        bs_findings = bs.scan_backups(port, proto, logger=log)
        if bs_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('backups', bs_findings)))
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
        
        orch.mark_module("backup_scanner", port, "executed", artifacts=len(bs_findings) if bs_findings else 0)
        orch.add_finding(title=f"Module Executed: backup_scanner", description=f"Backup audit finished on port {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"Backup audit failed on port {port}: {e}", "DEBUG")
        orch.mark_module("backup_scanner", port, "failed")

    # --- EXPERT: GraphQL Audit ---
    try:
        gs = GraphQLScanner(target)
        gs_findings = gs.audit_graphql(port, proto, logger=log)
        if gs_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('graphql', gs_findings)))
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
        
        orch.mark_module("graphql_scanner", port, "executed", artifacts=len(gs_findings) if gs_findings else 0)
        orch.add_finding(title=f"Module Executed: graphql_scanner", description=f"GraphQL audit finished on port {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"GraphQL audit failed on port {port}: {e}", "DEBUG")
        orch.mark_module("graphql_scanner", port, "failed")

    # --- EXPERT: SSRF Probing (Cloud Metadata) ---
    try:
        discovered_endpoints = []
        
        api = results.get('phases', {}).get('enum', {}).get('api', {})
        seed = []

        seed.extend([x for x in api.get("discovered_endpoints", []) if isinstance(x, str)])

        for k, v in api.items():
            if k == "discovered_endpoints":
                continue
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and item.get("url"):
                        seed.append(item["url"])
                    elif isinstance(item, str):
                        seed.append(item)

        discovered_endpoints_raw = list(dict.fromkeys(seed))
        discovered_endpoints = []
        variant_meta = {}  # url -> variant metadata for telemetry
        
        # MUTATION: Apply SSRF specific mutations
        for u in discovered_endpoints_raw[:50]: # Cap for SSRF
            vars = mutation_engine.generate_variants(u, attack_type="ssrf", strategy=mutation_strategy)
            for v in vars:
                discovered_endpoints.append(v['url'])
                variant_meta[v['url']] = {
                    "attack_type": v.get("attack_type"),
                    "mutation_type": v.get("mutation_type"),
                    "payload_hash": v.get("payload_hash"),
                    "source_seed": v.get("source_seed"),
                }
        
        log(f"Mutation Engine: Generated {len(discovered_endpoints)} SSRF variants.", "DEBUG")
        
        if discovered_endpoints:
            ssrf = SSRFScanner(target)
            ssrf_findings = ssrf.scan_endpoints(discovered_endpoints, logger=log)
            if ssrf_findings:
                _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('ssrf', ssrf_findings)))
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
        
        orch.mark_module("ssrf_expert", port, "executed", artifacts=len(discovered_endpoints))
        # SSRF is technically global for found endpoints, but we attribute to current port loop for visibility or mark it once?
        # Since it runs per port loop if new endpoints are found, marking it 'executed' per port is fine.
        orch.add_finding(title=f"Module Executed: ssrf_expert", description=f"SSRF probe finished using endpoints from {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"SSRF Expert probe failed: {e}", "DEBUG")
        orch.mark_module("ssrf_expert", port, "failed", reason=str(e))

    # --- JS VULNERABILITY AUDIT ---
    try:
        url = f"{proto}://{target}:{port}"
        js_scanner = JSVulnScanner(target)
        js_findings = js_scanner.audit_js_endpoints(url, logger=log)
        if js_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].setdefault('js_vulns', {}), results['phases']['vuln']['js_vulns'].__setitem__(str(port), js_findings)))
            
            for f in js_findings:
                orch.add_finding(
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="js_vuln_audit"
                )
            orch.save_results(orch.scan_id, results)
        
        orch.mark_module("js_vuln_audit", port, "executed", artifacts=len(js_findings) if js_findings else 0)
        orch.add_finding(title=f"Module Executed: js_vuln_audit", description=f"JS vulnerability audit finished on {port}", severity="info", tool_source="redops-core")

    except Exception as e:
         log(f"JS Vuln audit failed: {e}", "DEBUG")
         orch.mark_module("js_vuln_audit", port, "failed", reason=str(e))

    # --- DALFOX (XSS) ---
    try:
        dalfox = DalfoxScanner(target)
        if dalfox.check_tools():
            log(f"Checking for XSS on {proto}://{target}:{port}...", "INFO")

            # SEED MUTATION & DISPATCH
            raw_seeds = results['phases']['enum'].get('injection_points', {}).get(str(port), [])
            hinted_seeds = execution_hints.get('dalfox', {}).get('seed_priority', []) if isinstance(execution_hints, dict) else []
            if hinted_seeds:
                hinted_for_port = [
                    u for u in hinted_seeds
                    if isinstance(u, str) and (
                        f":{port}" in u or
                        u.startswith(f"{proto}://{target}")
                    )
                ]
                if hinted_for_port:
                    raw_seeds = hinted_for_port
            
            # V6 Fix: Merge with surface expansion URLs
            if expansion_urls:
                raw_seeds = list(set(raw_seeds + expansion_urls))

            mutated_seeds = []
            for rs in raw_seeds[:100]: # Top 100 seeds for mutation
                variants = mutation_engine.generate_variants(rs, attack_type="xss", strategy=mutation_strategy)
                for v in variants:
                    # Skip noise: null-payload non-original variants
                    if v.get("payload") is None and v.get("mutation_type") != "original":
                        continue
                    mutated_seeds.append(v['url'])
            
            log(f"Mutation Engine: Generated {len(mutated_seeds)} XSS variants for Dalfox.", "DEBUG")

            # Batch scan: feed ALL mutated URLs to Dalfox via file mode
            capped_seeds = mutated_seeds[:200]
            xss_found = []
            dalfox_max_seconds = int(os.getenv("REDOPS_DALFOX_MAX_SECONDS", "900"))
            dalfox_max_findings = int(os.getenv("REDOPS_DALFOX_MAX_FINDINGS", "30"))
            dalfox_start = time.time()
            stop_reason = None

            if capped_seeds:
                _ts(lambda: results['commands'].append({
                    'tool': 'dalfox',
                    'cmd': f'dalfox file <{len(capped_seeds)} mutated URLs>'
                }))

                df_stream = dalfox.stream_scan_pipe(capped_seeds)
                for event in df_stream:
                    if (time.time() - dalfox_start) > dalfox_max_seconds:
                        stop_reason = "time_budget_exceeded"
                        try:
                            if hasattr(df_stream, "terminate"):
                                df_stream.terminate()
                            elif hasattr(df_stream, "process") and df_stream.process:
                                try:
                                    df_stream.process.terminate()
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        break
                    if event["type"] == "stdout":
                        line = event["line"].strip()
                        if "[V]" in line or "PoC" in line:
                             log(f"XSS Discovered: {line}", "SUCCESS")
                             
                             # Parse Dalfox line into structured object for UI template
                             import re
                             xss_obj = {"url": "", "method": "GET", "payload": line, "evidence": line, "port": port}
                             method_match = re.search(r'\[(GET|POST|PUT|DELETE)\]', line)
                             if method_match:
                                 xss_obj["method"] = method_match.group(1)
                             url_match = re.search(r'(https?://[^\s\[\]]+)', line)
                             if url_match:
                                 xss_obj["url"] = url_match.group(1)
                             poc_match = re.search(r'PoC:\s*(.+)', line)
                             if poc_match:
                                 xss_obj["payload"] = poc_match.group(1).strip()
                             
                             xss_found.append(xss_obj)

                             if len(xss_found) >= dalfox_max_findings:
                                stop_reason = "findings_budget_exceeded"
                                try:
                                    df_stream.close()
                                except Exception:
                                    pass
                                break
                             
                             # NORMALIZED FINDING
                             normalized_f = normalizer.normalize({"url": "", "param": "", "poison": "", "evidence": line}, "dalfox")
                             orch.add_finding(
                                title=normalized_f["title"],
                                description=normalized_f["description"],
                                severity=normalized_f["severity"],
                                tool_source="dalfox"
                             )
            
            if xss_found:
                def _store_xss():
                    if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
                    # Flatten: append to single list (template iterates vuln.xss directly)
                    if 'xss' not in results['phases']['vuln']: results['phases']['vuln']['xss'] = []
                    results['phases']['vuln']['xss'].extend(xss_found)
                _ts(_store_xss)
                orch.save_results(orch.scan_id, results)
            
            orch.mark_module("dalfox", port, "executed", artifacts=len(xss_found), reason=stop_reason)
            orch.add_finding(title=f"Module Executed: dalfox", description=f"Dalfox XSS scan finished on {port}", severity="info", tool_source="redops-core")
            
    except Exception as e:
        log(f"Dalfox failed: {e}", "ERROR")
        orch.mark_module("dalfox", port, "failed", reason=str(e))

    # --- OPEN REDIRECT ---
    try:
        endpoints = []
        # Use endpoints from enum phase if available, otherwise just check base if needed?
        # Orchestrator passed 'endpoints' which presumably came from Katana/Ffuf.
        # Here we can grab them from results['phases']['dirbusting'] or ['enum']['api']
        
        if 'enum' in results['phases'] and 'targets' in results['phases']['enum'] and str(port) in results['phases']['enum']['targets']:
             endpoints = results['phases']['enum']['targets'][str(port)]
        
        if not endpoints:
             # Gather all known endpoints (Fallback)
             if 'dirbusting' in results['phases']:
                  for tool, data in results['phases']['dirbusting'].items():
                      if 'endpoints' in data:
                          for ep in data['endpoints']:
                              if isinstance(ep, dict) and 'url' in ep: endpoints.append(ep['url'])
                              elif isinstance(ep, str): endpoints.append(ep)
        
             if 'enum' in results['phases'] and 'api' in results['phases']['enum']:
                 endpoints.extend(results['phases']['enum']['api'].get('discovered_endpoints', []))

        # V6 Fix: Force include surface expansion for redirect audit
        if expansion_urls:
            endpoints = list(set(endpoints + expansion_urls))

        if endpoints:
            or_scanner = OpenRedirectScanner(target)
            or_findings = or_scanner.scan_endpoints(endpoints, logger=log)
            
            if or_findings:
                _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('redirects', or_findings)))
                
                for f in or_findings:
                    orch.add_finding(
                        title=f"Open Redirect Vulnerability ({port})",
                        description=f"Vulnerable URL: {f.get('url')}\nDestination: {f.get('destination')}",
                        severity="medium",
                        tool_source="redirect_scanner"
                    )
                orch.save_results(orch.scan_id, results)
        
        orch.mark_module("redirect_scanner", port, "executed", artifacts=len(endpoints)) # approximate artifacts
        orch.add_finding(title=f"Module Executed: redirect_scanner", description=f"Open redirect check finished on {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"Open Redirect audit failed: {e}", "DEBUG")
        orch.mark_module("redirect_scanner", port, "failed", reason=str(e))

    # --- EXPERT: ADVANCED VULNERABILITY AUDIT (PHASE 4) ---
    log(f"Phase 4: Executing Advanced Vuln Audit (Expert Scanners) on port {port}...", "INFO")
    
    # 1. SSTI
    try:
        ssti = SSTIScanner(target)
        ssti_findings = ssti.scan_ssti(port, proto, logger=log)
        if ssti_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('ssti', ssti_findings)))
            for f in ssti_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"SSTI Scanner Error: {e}", "DEBUG")

    # 2. CORS
    try:
        cors = CORSScanner(target)
        cors_findings = cors.scan_cors(port, proto, logger=log)
        if cors_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('cors_audit', cors_findings)))
            for f in cors_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"CORS Scanner Error: {e}", "DEBUG")

    # 3. LFI Assault
    try:
        lfi = LfiAssaultScanner()
        lfi_urls = results['phases']['enum'].get('targets', {}).get(str(port), [])
        if not lfi_urls: lfi_urls = [f"{proto}://{target}:{port}/"]
        lfi_findings = lfi.scan(target, orch.scan_id, urls=lfi_urls, logger=log, quick=(profile.startswith('quick')))
        if lfi_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('lfi', lfi_findings)))
            for f in lfi_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"LFI Assault Error: {e}", "DEBUG")

    # 4. Spring Boot Actuators
    try:
        spring = SpringBootScanner(target)
        spring_findings = spring.scan_actuators(port, proto, logger=log)
        if spring_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('spring_boot', spring_findings)))
            for f in spring_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Spring Boot Scanner Error: {e}", "DEBUG")

    # 5. CRLF Injection
    try:
        crlf = CRLFScanner(target)
        crlf_findings = crlf.scan_crlf(port, proto, logger=log)
        if crlf_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('crlf', crlf_findings)))
            for f in crlf_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"CRLF Scanner Error: {e}", "DEBUG")

    # 6. XXE
    try:
        xxe = XXEScanner(target)
        xxe_findings = xxe.scan_xxe(port, proto, logger=log)
        if xxe_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('xxe', xxe_findings)))
            for f in xxe_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"XXE Scanner Error: {e}", "DEBUG")

    # 7. Prototype Pollution
    try:
        proto_scanner = PrototypePollutionScanner(target)
        proto_findings = proto_scanner.scan_prototype(port, proto, logger=log)
        if proto_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('prototype', proto_findings)))
            for f in proto_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Prototype Pollution Error: {e}", "DEBUG")

    # --- 360 DEGREE SURFACE HARDENING (PHASE 4.5) ---
    log(f"Phase 4.5: Executing 360-Degree Attack Surface Audit on port {port}...", "INFO")

    # 1. Shadow API & Documentation (APIExpertScanner)
    try:
        api_expert = APIExpertScanner(f"{proto}://{target}:{port}")
        # Use existing API endpoints or discover new ones
        api_endpoints = results.get('phases', {}).get('enum', {}).get('api', {}).get('endpoints', [])
        if not api_endpoints:
             api_endpoints = api_expert.advanced_discovery(logger=log)
        
        api_findings = api_expert.audit_endpoints(api_endpoints, logger=log)
        if api_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('api_expert', api_findings)))
            for f in api_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"API Expert Error: {e}", "DEBUG")

    # 2. Environment & Config Exposure (TechExposureScanner)
    try:
        tes = TechExposureScanner(target)
        tes_findings = tes.audit(port, proto, logger=log)
        if tes_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('tech_exposure', tes_findings)))
            for f in tes_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Tech Exposure Error: {e}", "DEBUG")

    # 3. Unprotected Database & Broker Audit (DBScanner)
    try:
        dbs = DBScanner(target)
        # Port info needed for DBScanner
        port_info_list = results.get('phases', {}).get('recon', {}).get('open_ports', [])
        current_port_info = [p for p in port_info_list if str(p.get('port')) == str(port)]
        if current_port_info:
            db_findings = dbs.run_all(current_port_info, logger=log)
            if db_findings:
                _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('db_audit', db_findings)))
                for f in db_findings:
                    orch.add_finding(**normalizer.normalize(f))
                    if orch.add_loot and f.get('raw_loot'):
                        orch.add_loot(loot_type=f.get('loot_type', 'DB Creds'), content=f['raw_loot'], context=f"DB exposure on {target}:{port}")
                orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"DB Scanner Error: {e}", "DEBUG")

    # 4. Business Logic & IDOR Heuristics (LogicAssaultScanner)
    try:
        la = LogicAssaultScanner()
        la_findings = la.scan(target, orch.scan_id, logger=log)
        if la_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('logic_assault', la_findings)))
            for f in la_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Logic Assault Error: {e}", "DEBUG")

    # 5. WAF Bypass & Origin Leak (WafBypassScanner)
    try:
        waf_bypass = WafBypassScanner(target)
        wb_findings = waf_bypass.scan(port, proto, logger=log)
        if wb_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('waf_bypass', wb_findings)))
            for f in wb_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"WAF Bypass Error: {e}", "DEBUG")

    # 6. Cloud Identity Leak (CloudPermScanner)
    try:
        cloud_perm = CloudPermScanner()
        # Find already discovered cloud assets
        cloud_assets = results.get('phases', {}).get('osint', {}).get('cloud', [])
        cp_findings = cloud_perm.scan_all(cloud_assets, logger=log)
        if cp_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('cloud_permissions', cp_findings)))
            for f in cp_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Cloud Permission Error: {e}", "DEBUG")

    # 8. Access Control (ACL)
    try:
        acl = AccessControlScanner(target)
        acl_findings = acl.scan_acl(port, proto, logger=log)
        if acl_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('acl_bypass', acl_findings)))
            for f in acl_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"ACL Scanner Error: {e}", "DEBUG")

    # --- OSINT & DATA MINING (PHASE 6) ---
    try:
        # Sensitive Data Mining on Response Bodies
        if fingerprint_data:
            miner = SensitiveDataMiner()
            miner_findings = miner.scan(fingerprint_data, f"{proto}://{target}:{port}")
            if miner_findings:
                _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('data_leaks', miner_findings)))
                for f in miner_findings:
                    orch.add_finding(
                        title=f"Data Leak: {f['type'].upper()} Detected",
                        description=f"Found {f['count']} matches in response. Sample: {', '.join(f['matches'])}",
                        severity="high",
                        tool_source="data_miner"
                    )
                orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Data Miner Error: {e}", "DEBUG")

    try:
        # Global Secret Scanning
        secret_scanner = SecretScanner()
        secrets = secret_scanner.scan_text(fingerprint_data, source_info=f"Port {port}", target_domain=target)
        if secrets:
            _ts(lambda: (results['phases'].setdefault('enum', {}), results['phases']['enum'].setdefault('js_secrets', {}), results['phases']['enum']['js_secrets'].__setitem__(str(port), secrets)))
            for s in secrets:
                orch.add_finding(**normalizer.normalize(s))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Secret Scanner Error: {e}", "DEBUG")

    # 10. Container & Kube Exposure
    try:
        kube = KubeDockerScanner(target)
        kube_findings = kube.scan_exposure(port, proto, logger=log)
        if kube_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('container_exposure', kube_findings)))
            for f in kube_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Kube Scanner Error: {e}", "DEBUG")

    # 11. WebSockets Audit
    try:
        ws = WebSocketScanner(target)
        ws_findings = ws.scan_websocket(port, proto, logger=log)
        if ws_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('websocket', ws_findings)))
            for f in ws_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"WebSocket Scanner Error: {e}", "DEBUG")

    # 12. Backend Surface Exposure mapping (Architecture Driven)
    try:
        mapper = SurfaceMapperScanner(target)
        surface_findings = mapper.audit(port, proto, logger=log, scan_results=results)
        if surface_findings:
            # Separate UI data from findings for specialized viewing
            ui_data = surface_findings[0].get("surface_data")
            _ts(lambda: (results['phases'].setdefault('vuln', {}).setdefault('surface_mapping', {}).__setitem__(str(port), ui_data)))
            
            # The mapper returns a summary finding which we add to the log
            orch.add_finding(**normalizer.normalize(surface_findings[0]))
            orch.save_results(orch.scan_id, results)
    except Exception as e: log(f"Surface Mapper Error: {e}", "DEBUG")


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
    normalizer = FindingNormalizer()

    def _ts(fn):
        return orch.thread_safe_results_update(fn)
    
    def _ts(fn):
        return orch.thread_safe_results_update(fn)
    
    # --- PHASE 3: Subdomain Takeover ---
    emit_progress(orch, 50, "Subdomain Takeover Check")
    try:
        subdomains = results.get('phases', {}).get('dns', {}).get('subdomains', [])
        takeover = TakeoverScanner(target)
        if takeover.check_tools():
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
                    elif event['type'] == 'exit':
                        if event['code'] != 0:
                            log("external_tool_non_zero_exit_code", "DEBUG")
                orch.save_results(orch.scan_id, results)
            orch.mark_module("takeover_scanner", 0, "executed", artifacts=len(subdomains))
            orch.add_finding(title=f"Module Executed: takeover_scanner", description=f"Subdomain takeover check finished", severity="info", tool_source="redops-core")
        else:
            log("Subdomain takeover tool not found. Skipping.", "WARN")
            orch.mark_module("takeover_scanner", 0, "skipped")

    except Exception as e:
        log(f"Takeover scan failed: {e}", "WARN")
        orch.mark_module("takeover_scanner", 0, "failed", reason=str(e))

    # --- PHASE 3.5: Email Security & Infrastructure ---
    try:
        email = EmailSecurityScanner(target)
        email_findings = email.scan_security(logger=log)
        if email_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('email_security', email_findings)))
            for f in email_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
        orch.mark_module("email_security", 0, "executed")
    except Exception as e:
        log(f"Email security scan failed: {e}", "WARN")
        orch.mark_module("email_security", 0, "failed", reason=str(e))

    # --- PHASE 3.6: Firebase Audit ---
    try:
        firebase = FirebaseScanner(target)
        fb_findings = firebase.scan_firebase(logger=log)
        if fb_findings:
            _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].__setitem__('firebase', fb_findings)))
            for f in fb_findings:
                orch.add_finding(**normalizer.normalize(f))
            orch.save_results(orch.scan_id, results)
        orch.mark_module("firebase_scanner", 0, "executed")
    except Exception as e:
        log(f"Firebase scan failed: {e}", "WARN")
        orch.mark_module("firebase_scanner", 0, "failed", reason=str(e))

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
                    svc = p_info.get('service', p_info.get('service_name', '')).lower()
                    port_num = p_info.get('port')
                    
                    if svc in ['http', 'https', 'ssl/http', 'http-alt'] or port_num in [80, 443, 8080, 8443]:
                        web_ports.append(port_num)
            
            # If no web ports identified but we have open ports, maybe try 80/443 if in list?
            # Existing logic fallback was:
            if not web_ports: web_ports = [80, 443]

            execution_hints = results.get('phases', {}).get('enum', {}).get('derived', {}).get('execution_hints', {})
            extra_tags = execution_hints.get('nuclei', {}).get('extra_tags', []) if isinstance(execution_hints, dict) else []
            base_tags = ["cve", "lfi", "rfi", "ssti", "sqli", "injection", "misconfig"]
            merged_tags = base_tags + [tag for tag in extra_tags if isinstance(tag, str) and tag not in base_tags]
            tags_csv = ",".join(merged_tags[:len(base_tags) + 3])

            for port in web_ports:
                proto = 'https' if port in [443, 8443] or 'ssl' in str(port) else 'http'
                # Simple heuristc logic, might need refinement
                
                try:
                    cmd_nuc = nuclei.get_command(port, proto, tags=tags_csv)
                    _ts(lambda: results['commands'].append({'tool': 'nuclei', 'cmd': shlex.join(cmd_nuc)}))
                    log(f"Executing Nuclei on {target}:{port}...", "DEBUG")
                    
                    nuc_stream = nuclei.stream_vuln_scan(port, proto, tags=tags_csv)
                    
                    _ts(lambda: (results['phases'].setdefault('vuln', {}), results['phases']['vuln'].setdefault('nuclei', {'findings': []})))
                    
                    start_time = time.time()
                    found_any = False
                    
                    for event in nuc_stream:
                        # Timeout logic
                        if (time.time() - start_time) > 1200: # 20 mins
                            log(f"Nuclei on port {port} timed out. Skipping.", "WARN")
                            break
                            
                        if event['type'] == 'stdout':
                            line = event['line'].strip()
                            if not line: continue
                            if line.startswith('{'):
                                try:
                                    data = json.loads(line)
                                    sev = data.get('info', {}).get('severity', 'info').lower()
                                    title = data.get('info', {}).get('name', 'Nuclei Finding')
                                    template_id = data.get('template-id')
                                    matched_at = data.get('matched-at', '')
                                    
                                    # Evidence
                                    req = data.get('request', '')
                                    res = data.get('response', '')
                                    curl_cmd = data.get('curl-command', '')
                                    matcher = data.get('matcher-name', '')
                                    
                                    desc = f"**Nuclei Template**: {template_id}\n"
                                    if matcher: desc += f"**Matcher**: {matcher}\n"
                                    desc += f"**URL**: {matched_at}\n\n"
                                    if data.get('info', {}).get('description'):
                                        desc += f"**Description**: {data['info']['description']}\n"
                                    
                                    log(f"Nuclei Finding: {title} ({sev.upper()}) at {matched_at}", 'WARN' if sev in ['critical', 'high'] else 'INFO')
                                    
                                    _ts(lambda: results['phases']['vuln']['nuclei']['findings'].append({
                                        'title': title,
                                        'severity': sev,
                                        'url': matched_at,
                                        'tool': 'nuclei',
                                        'template_id': template_id,
                                        'matcher': matcher
                                    }))
                                    found_any = True
                                    
                                    orch.add_finding(
                                        title=title,
                                        description=desc,
                                        severity=sev,
                                        confidence="high" if res else "medium",
                                        tool_source="nuclei",
                                        request=req,
                                        response=res,
                                        repro_command=curl_cmd
                                    )
                                    orch.save_results(orch.scan_id, results)
                                except Exception as ej:
                                    log(f"Nuclei JSON Parse Error: {ej}", "DEBUG")
                            elif "[INF]" in line or "[WRN]" in line:
                                log(f"Nuclei Status: {line}", "DEBUG")
                        elif event['type'] == 'exit':
                            if event['code'] != 0:
                                log("external_tool_non_zero_exit_code", "DEBUG")
                                
                    if not found_any:
                        log(f"No Nuclei findings on port {port}.", "SUCCESS")
                    
                    orch.mark_module("nuclei", port, "executed", artifacts=1 if found_any else 0)
                    orch.add_finding(title=f"Module Executed: nuclei", description=f"Nuclei scan finished on port {port}", severity="info", tool_source="redops-core")
                        
                except Exception as e:
                    log(f"Nuclei error on {port}: {e}", "ERROR")
                    orch.mark_module("nuclei", port, "failed", reason=str(e))

    except Exception as e:
        log(f"Nuclei scan failed: {e}", "ERROR")
