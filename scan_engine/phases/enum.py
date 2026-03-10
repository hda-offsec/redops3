import shlex
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
from scan_engine.step02_enum.web_scanner import WebReconScanner
from scan_engine.step02_enum.waf_scanner import WafScanner
from scan_engine.step02_enum.api_scanner import APIScanner
from scan_engine.step03_vuln.api_expert_scanner import APIExpertScanner
from scan_engine.step02_enum.js_scanner import JSSecretScanner
from scan_engine.step02_enum.arjun_scanner import ArjunScanner
from scan_engine.step03_vuln.tech_exposure_scanner import TechExposureScanner
from scan_engine.step02_enum.katana_scanner import KatanaScanner
from scan_engine.helpers.process_manager import ProcessManager
from scan_engine.helpers.enum_seed_factory import EnumSeedFactory
from scan_engine.helpers.context_attack_engine import ContextAttackEngine
from scan_engine.helpers.js_mining_expert import JSDeepMiningExpert

# prioritization moved to EnumSeedFactory

def analyze_security_headers(target, port, proto, logger_func, options=None):
    """
    Analyzes HTTP headers for security configurations.
    Returns structured results with status and recommendations.
    """
    security_defs = {
        'Strict-Transport-Security': {
            'name': 'HSTS',
            'rec': 'max-age=31536000; includeSubDomains; preload',
            'desc': 'Enforces HTTPS connections.'
        },
        'Content-Security-Policy': {
            'name': 'CSP',
            'rec': "default-src 'self'; script-src 'self'; object-src 'none';",
            'desc': 'Prevents XSS and injection attacks.'
        },
        'X-Frame-Options': {
            'name': 'Clickjacking Protection',
            'rec': 'DENY or SAMEORIGIN',
            'desc': 'Prevents the site from being framed.'
        },
        'X-Content-Type-Options': {
            'name': 'MIME Sniffing Protection',
            'rec': 'nosniff',
            'desc': 'Prevents browsers from MIME-sniffing.'
        },
        'Referrer-Policy': {
            'name': 'Referrer Policy',
            'rec': 'strict-origin-when-cross-origin',
            'desc': 'Controls how much referrer information is shared.'
        },
        'Permissions-Policy': {
            'name': 'Permissions Policy',
            'rec': 'geolocation=(), microphone=(), camera=()',
            'desc': 'Restricts use of browser features.'
        }
    }

    try:
        url = f"{proto}://{target}:{port}"
        try:
            resp = http_client.head(url, options=options, timeout=5, allow_redirects=True)
        except Exception:
            resp = http_client.get(url, options=options, timeout=5, allow_redirects=True)
             
        actual_headers = {k.lower(): v for k, v in resp.headers.items()}
        analysis = {}

        for header_key, defs in security_defs.items():
            low_key = header_key.lower()
            if low_key in actual_headers:
                analysis[header_key] = {
                    'status': 'ok',
                    'value': actual_headers[low_key],
                    'recommendation': defs['rec']
                }
            else:
                analysis[header_key] = {
                    'status': 'missing',
                    'value': None,
                    'recommendation': defs['rec']
                }
        
        # Add non-security headers for general info
        for h, v in resp.headers.items():
            if h not in analysis:
                analysis[h] = {'status': 'info', 'value': v, 'recommendation': None}

        return analysis

    except Exception as e:
        logger_func(f"Header Analysis Error: {e}", "DEBUG")
        return {}

def sanitize_endpoints(raw_list):
    """Clean and filter raw endpoints: only http(s) strings, no dict leaks."""
    if not raw_list:
        return []
    clean = []
    for ep in raw_list:
        if not ep: continue
        # Handle dict leaks from API/Recon modules
        if isinstance(ep, dict):
            url = ep.get("url") or ep.get("endpoint")
        elif isinstance(ep, str):
            url = ep
        else:
            continue
            
        if url and isinstance(url, str):
            url = url.strip()
            if url.startswith("http"):
                clean.append(url)
    return list(set(clean))

def normalize_endpoint(url: str) -> str:
    """Normalize endpoints before prioritization (Phase 1 Fix)."""
    if not url: return ""
    from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
    try:
        parsed = urlparse(url)
        path = parsed.path.replace("//", "/")
        if not path: path = "/"
        query = parse_qs(parsed.query)
        sorted_query = urlencode(sorted(query.items()), doseq=True)
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", sorted_query, ""))
    except Exception:
        return url.strip()

def run_enum(orchestrator, port, proto):
    """
    Executes Phase 2: Enumeration on a specific port (V6 Hardened)
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    profile = orch.options.get('profile', 'quick')
    is_quick = profile.startswith('quick')

    def _ts(fn):
        return orch.thread_safe_results_update(fn)

    full_ww = ""
    
    # --- GUARANTEED INITIALIZATION ---
    def _init_enum_struct():
        results.setdefault('phases', {})
        results['phases'].setdefault('enum', {})
        results['phases']['enum'].setdefault('whatweb', {'summary': {}, 'technologies': {}})
        results['phases']['enum'].setdefault('katana', {})
        results['phases']['enum'].setdefault('api', {'discovered_endpoints': []})
        results['phases']['enum'].setdefault('arjun', {})
        results['phases']['enum'].setdefault('targets', {})
        results['phases']['enum'].setdefault('injection_points', {})
        results['phases']['enum'].setdefault('seed_meta', {})
        results['phases']['enum'].setdefault('js_deep_mining', {})
        results['phases']['enum'].setdefault('http_methods', {})
        results['phases']['enum'].setdefault('normalized', {})
        results['phases']['enum'].setdefault('derived', {})
        results.setdefault('commands', [])

    _ts(_init_enum_struct)
    orch.save_results(orch.scan_id, results)
    
    # 1. Web Recon (WhatWeb)
    try:
        web_recon = WebReconScanner(target)
        if web_recon.check_tools():
            log(f"Fingerprinting {proto}://{target}:{port}...", "INFO")
            _ts(lambda: results['commands'].append({'tool': 'whatweb', 'cmd': shlex.join(web_recon.get_command(port, proto))}))
            ww_stream = web_recon.stream_whatweb(port, proto)
            for event in ww_stream:
                 if event["type"] == "stdout":
                     full_ww += event["line"].strip() + "\n"
            
            techs = []
            for line in full_ww.split('\n'):
                if not line.startswith("http"): continue
                try:
                    parts = line.split(']', 1)
                    if len(parts) > 1:
                        for t in parts[1].split(', '):
                            t = t.strip()
                            if t and t not in techs: techs.append(t)
                except Exception as parse_error:
                    log(f"WhatWeb parse failed: {parse_error}", "DEBUG")

            def _store_whatweb():
                ww = results['phases']['enum'].setdefault('whatweb', {})
                ww.setdefault('summary', {})[str(port)] = full_ww
                ww.setdefault('technologies', {})[str(port)] = techs
            _ts(_store_whatweb)
            orch.save_results(orch.scan_id, results)
            orch.mark_module("whatweb", port, "executed", artifacts=len(techs))
            # V10: Surface discovered technologies as INFO finding
            if techs:
                tech_list = ", ".join(techs[:15])
                orch.add_finding(
                    title=f"Technology Fingerprint ({port})",
                    description=f"Detected {len(techs)} technologies on port {port}:\n{tech_list}",
                    severity="info",
                    tool_source="whatweb"
                )
    except Exception as e:
        log(f"WhatWeb failed: {e}", "ERROR")
        orch.mark_module("whatweb", port, "failed", reason=str(e))

    # 2. Security Headers
    try:
        header_analysis = analyze_security_headers(target, port, proto, log, options=orch.options)
        _ts(lambda: results['phases']['enum'].setdefault('headers', {}).__setitem__(str(port), header_analysis))

        allow_methods = []
        allow_entry = header_analysis.get('Allow') or header_analysis.get('allow')
        if isinstance(allow_entry, dict):
            allow_val = allow_entry.get('value')
            if isinstance(allow_val, str):
                allow_methods = [m.strip().upper() for m in allow_val.split(',') if m.strip()]
        base_endpoint = f"{proto}://{target}:{port}/"
        if allow_methods:
            _ts(lambda: results['phases']['enum'].setdefault('http_methods', {}).__setitem__(base_endpoint, allow_methods))
        
        # V10: Surface missing headers as LOW findings (hardening, not vulnerability)
        missing = [k for k, v in header_analysis.items() if v.get('status') == 'missing']
        if missing:
            header_list = "\n".join(f"  • {h}" for h in missing)
            orch.add_finding(
                title=f"Missing Security Headers ({port})",
                description=(
                    f"The following security headers are not configured:\n\n"
                    f"{header_list}\n\n"
                    f"These are hardening recommendations, not exploitable vulnerabilities."
                ),
                severity="low",
                tool_source="header_audit"
            )
        
        orch.mark_module("headers", port, "executed")
    except Exception as e:
        log(f"Security headers scan failed: {e}", "DEBUG")
        orch.mark_module("headers", port, "failed", reason=str(e))

    # 3. Katana Crawler
    try:
         katana = KatanaScanner(target)
         if katana.check_tools():
             log(f"Crawling {proto}://{target}:{port} (Katana)...", "INFO")
             _ts(lambda: results['commands'].append({'tool': 'katana', 'cmd': shlex.join(katana.get_command(port, proto, quick=is_quick))}))
             kt_stream = katana.stream_scan(port, proto, quick=is_quick)
             raw_endpoints = [ev["line"].strip() for ev in kt_stream if ev["type"] == "stdout" and ev["line"].strip()]
             
             # --- SCOPE ENFORCEMENT: Drop off-scope URLs ---
             from urllib.parse import urlparse as _urlparse
             t_parts = target.lower().split('.')
             root_dom = '.'.join(t_parts[-2:]) if len(t_parts) >= 2 else target.lower()
             endpoints = []
             dropped = 0
             for ep in raw_endpoints:
                 try:
                     h = (_urlparse(ep).hostname or "").lower()
                     if h.endswith(root_dom):
                         endpoints.append(ep)
                     else:
                         dropped += 1
                 except Exception:
                     endpoints.append(ep)
             if dropped:
                 log(f"Katana Scope Filter: Dropped {dropped} off-scope URLs.", "WARN")
             
             _ts(lambda: results['phases']['enum']['katana'].__setitem__(str(port), endpoints[:1000]))
             orch.mark_module("katana", port, "executed", artifacts=len(endpoints))
             # V10: Surface crawl summary as INFO finding
             if endpoints:
                 orch.add_finding(
                     title=f"Web Crawl Summary ({port})",
                     description=f"Katana discovered {len(endpoints)} endpoints on port {port}.",
                     severity="info",
                     tool_source="katana"
                 )

             try:
                 js_scanner = JSSecretScanner(target, options=orch.options)
                 js_summary = js_scanner.scan_list(endpoints, logger=log)
                 if js_summary.get("secrets"):
                     _ts(lambda: results['phases']['enum'].setdefault('js_secrets', {}).__setitem__(str(port), [x for arr in js_summary['secrets'].values() for x in arr]))
                 if js_summary.get("endpoints"):
                     _ts(lambda: results['phases']['enum'].setdefault('api', {}).setdefault('discovered_endpoints', []).extend(js_summary.get('endpoints', [])))

                 deep = JSDeepMiningExpert(target, options=orch.options).mine_endpoints([u for u in endpoints if isinstance(u, str) and u.endswith('.js')], timeout=45, logger=log)
                 _ts(lambda: results['phases']['enum'].setdefault('js_deep_mining', {}).__setitem__(str(port), deep))

                 if deep.get('discovered_endpoints'):
                     sample = ", ".join(deep.get('discovered_endpoints', [])[:5])
                     orch.add_finding(
                         title=f"JavaScript Intelligence Discovery ({port})",
                         description=f"JS mining extracted {len(deep.get('discovered_endpoints', []))} endpoints. Sample: {sample}",
                         severity="info",
                         tool_source="js_deep_scanner",
                         module="js_mining",
                         category="js_intelligence",
                         endpoint=f"{proto}://{target}:{port}",
                         evidence=sample,
                         raw_output=str(deep)[:2000],
                         metadata={"status": deep.get('status'), "js_files_scanned": deep.get('js_files_scanned')}
                     )
             except Exception as js_e:
                 log(f"JavaScript mining failed: {js_e}", "DEBUG")
    except Exception as e:
        log(f"Katana scan failed: {e}", "DEBUG")
        orch.mark_module("katana", port, "failed", reason=str(e))

    # 4. WAF Detection
    try:
        waf_scanner = WafScanner(target)
        if waf_scanner.check_tools():
            _ts(lambda: results['commands'].append({'tool': 'wafw00f', 'cmd': shlex.join(waf_scanner.get_command(port, proto))}))
            waf_stream = waf_scanner.stream_wafw00f(port, proto)
            for event in waf_stream:
                if "is behind" in event.get("line", ""):
                    res = event["line"].split("is behind")[-1].strip()
                    _ts(lambda: results['phases']['enum'].setdefault('waf', {}).__setitem__(str(port), res))
                    log(f"🛡️ WAF: {res}", "SUCCESS")
                    # V10: Surface WAF detection as INFO finding
                    orch.add_finding(
                        title=f"WAF Detected ({port})",
                        description=f"Web Application Firewall identified: {res}",
                        severity="info",
                        tool_source="wafw00f"
                    )
            orch.mark_module("waf", port, "executed")
    except Exception as e:
        log(f"WAF scan failed: {e}", "DEBUG")
        orch.mark_module("waf", port, "failed", reason=str(e))

    # 5. Arjun Param Discovery (Refactored & Hardened)
    try:
        arjun = ArjunScanner(target, options=orch.options)
        if arjun.check_tools():
            log(f"Discovering & Validating parameters (Arjun)...", "INFO")
            # We use a temp file for Arjun JSON output (managed inside scan_and_validate)
            arjun_results = arjun.scan_and_validate(port, proto, logger=log)
            
            params = [p["name"] for p in arjun_results.get("parameters", [])]
            
            if params:
                def _update_arjun():
                     results['phases']['enum']['arjun'][str(port)] = params
                     # Store full metadata for advanced analysis
                     results['phases']['enum']['arjun'][f"{port}_metadata"] = arjun_results
                _ts(_update_arjun)
                
                log(f"Arjun Summary: Found {arjun_results['total_found']} (Active: {arjun_results['active_validated']}, CMS Config: {arjun_results['passive_filtered']})", "SUCCESS")
            
            orch.mark_module("arjun", port, "executed", artifacts=len(params))
    except Exception as e:
        log(f"Arjun scan failed: {e}", "DEBUG")
        orch.mark_module("arjun", port, "failed", reason=str(e))
    except Exception as e:
        log(f"Arjun scan failed: {e}", "DEBUG")
        orch.mark_module("arjun", port, "failed", reason=str(e))

    # 6. API Discovery (Kiterunner)
    try:
         api_scanner = APIScanner(target)
         if api_scanner.check_tools():
            log(f"API Discovery (Kiterunner)...", "INFO")
            _ts(lambda: results['commands'].append({'tool': 'kiterunner', 'cmd': shlex.join(api_scanner.get_command(port, protocol=proto, quick=is_quick))}))
            api_stream = api_scanner.stream_api_discovery(port, protocol=proto, logger=log, quick=is_quick)
            api_endpoints = []
            for ev in api_stream:
                if ev["type"] == "stdout":
                    line = ev["line"].strip()
                    if line.startswith('{'):
                        try:
                            import json
                            data = json.loads(line)
                            url = data.get('url')
                            if url:
                                api_endpoints.append(url)
                                # log(f"API Found: {url}", "SUCCESS")
                        except Exception: continue
            
            if api_endpoints:
                 def _store_api():
                     results['phases']['enum']['api'].setdefault('discovered_endpoints', []).extend(api_endpoints)
                     # store all, but keep compatible with older UI parts that might use port keys
                     results['phases']['enum']['api'][str(port)] = api_endpoints
                     results['phases']['enum']['api'].setdefault('endpoints', []).extend([{"url": url, "status": 200, "source": "fuzzing"} for url in api_endpoints])
                 _ts(_store_api)
            # V10: Surface API discovery as INFO finding
            if api_endpoints:
                sample = ", ".join(api_endpoints[:5])
                orch.add_finding(
                    title=f"API Endpoints Discovered ({port})",
                    description=f"Kiterunner discovered {len(api_endpoints)} API endpoints on port {port}.\nSample: {sample}",
                    severity="info",
                    tool_source="kiterunner"
                )
            orch.mark_module("api_scanner", port, "executed", artifacts=len(api_endpoints))
    except Exception as e:
        log(f"API discovery failed: {e}", "DEBUG")
        orch.mark_module("api_scanner", port, "failed", reason=str(e))

    # --- SEED FACTORY (V6 Aggressive Synthesis) ---
    try:
        factory = EnumSeedFactory(target, port, proto, config=orch.config)
        
        # Harvest all discovery results
        if 'katana' in results['phases']['enum'] and str(port) in results['phases']['enum']['katana']:
            factory.add_raw_endpoints(results['phases']['enum']['katana'][str(port)], source="katana")
        if 'api' in results['phases']['enum']:
            factory.add_raw_endpoints(results['phases']['enum']['api'].get(str(port), []), source="kiterunner")
        if 'arjun' in results['phases']['enum'] and str(port) in results['phases']['enum']['arjun']:
            factory.add_arjun_params(results['phases']['enum']['arjun'][str(port)])

        # Produce Canonical Output
        canonical = factory.produce_canonical_output()
        
        def _store_canonical():
            results['phases']['enum']['normalized'][str(port)] = canonical['normalized']
            results['phases']['enum']['derived'][str(port)] = canonical['derived']
            results['phases']['enum']['targets'][str(port)] = canonical['derived']['targets']
            results['phases']['enum']['injection_points'][str(port)] = canonical['derived']['injection_points']
            results['phases']['enum']['seed_meta'][str(port)] = canonical['derived'].get('seed_meta', {})
        _ts(_store_canonical)
        
        orch.save_results(orch.scan_id, results)
        log(f"Seed Factory: derived {len(canonical['derived']['injection_points'])} seeds.", "SUCCESS")

        # --- TECHNOLOGY STACK INTELLIGENCE ---
        try:
            tech_scanner = TechExposureScanner(target)
            tech_data = tech_scanner.audit(port, protocol=proto, logger=log)
            if tech_data:
                def _store_tech():
                    results['phases']['enum']['tech'] = tech_data
                    results['phases']['vuln'].setdefault('tech', tech_data)
                _ts(_store_tech)
                orch.save_results(orch.scan_id, results)
                for f in tech_data:
                    if isinstance(f, dict):
                        orch.add_finding(**f)
                log(f"Tech Stack / Exposure Intelligence identified {len(tech_data)} artifacts.", "SUCCESS")
        except Exception as e:
            log(f"Tech Exposure Scanner Error: {e}", "DEBUG")

        # Context Attack Engine
        try:
            context_engine = ContextAttackEngine(results, logger=log)
            profile = context_engine.build_attack_profile(port)
            strategy = context_engine.derive_mutation_strategy(profile)
            _ts(lambda: results['phases']['enum'].setdefault('attack_profile', {}).__setitem__(str(port), profile))
            _ts(lambda: results['phases']['enum'].setdefault('mutation_strategy', {}).__setitem__(str(port), strategy))
            orch.save_results(orch.scan_id, results)
        except Exception as e:
            log(f"Context attack engine failed: {e}", "DEBUG")

    except Exception as e:
        log(f"Seed Factory Error: {e}", "ERROR")
        orch.mark_module("seed_factory", port, "failed", reason=str(e))

    return full_ww
