import shlex
import requests
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

# prioritization moved to EnumSeedFactory

def analyze_security_headers(target, port, proto, logger_func):
    """
    Analyzes HTTP headers for security configurations.
    Returns tuple(missing_headers, headers_dict)
    """
    try:
        url = f"{proto}://{target}:{port}"
        # logger_func(f"Fetching headers from {url}...", "DEBUG") # Too verbose?
        try:
            resp = requests.head(url, timeout=5, verify=False, allow_redirects=True)
        except Exception:
            resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
             
        headers = resp.headers
        
        # Analyze specific headers
        missing_sec_headers = []
        important_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'Referrer-Policy': 'Referrer Policy'
        }
        
        for header, name in important_headers.items():
            if header not in headers:
                missing_sec_headers.append(name)
        
        return missing_sec_headers, dict(headers)

    except Exception as e:
        logger_func(f"Header Analysis Error: {e}", "DEBUG")
        return [], {}

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
    except Exception as e:
        log(f"WhatWeb failed: {e}", "ERROR")
        orch.mark_module("whatweb", port, "failed", reason=str(e))

    # 2. Security Headers
    try:
        missing_sec_headers, headers = analyze_security_headers(target, port, proto, log)
        _ts(lambda: results['phases']['enum'].setdefault('headers', {}).__setitem__(str(port), headers))
        orch.mark_module("headers", port, "executed")
    except Exception as e:
        log(f"Security headers scan failed: {e}", "DEBUG")
        orch.mark_module("headers", port, "failed", reason=str(e))

    # 3. Katana Crawler
    try:
         katana = KatanaScanner(target)
         if katana.check_tools():
             log(f"Crawling {proto}://{target}:{port} (Katana)...", "INFO")
             _ts(lambda: results['commands'].append({'tool': 'katana', 'cmd': shlex.join(katana.get_command(port, proto))}))
             kt_stream = katana.stream_scan(port, proto)
             endpoints = [ev["line"].strip() for ev in kt_stream if ev["type"] == "stdout" and ev["line"].strip()]
             _ts(lambda: results['phases']['enum']['katana'].__setitem__(str(port), endpoints[:1000]))
             orch.mark_module("katana", port, "executed", artifacts=len(endpoints))
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
            orch.mark_module("waf", port, "executed")
    except Exception as e:
        log(f"WAF scan failed: {e}", "DEBUG")
        orch.mark_module("waf", port, "failed", reason=str(e))

    # 5. Arjun Param Discovery
    try:
        arjun = ArjunScanner(target)
        if arjun.check_tools():
            log(f"Discovering parameters (Arjun)...", "INFO")
            _ts(lambda: results['commands'].append({'tool': 'arjun', 'cmd': shlex.join(arjun.get_command(port, proto))}))
            ar_stream = arjun.stream_arjun(port, proto)
            params = []
            for ev in ar_stream:
                if ev["type"] == "stdout" and "parameter" in ev["line"].lower():
                    p = ev["line"].split(":")[-1].strip()
                    if p: params.append(p)
            if params:
                _ts(lambda: results['phases']['enum']['arjun'].__setitem__(str(port), params))
            orch.mark_module("arjun", port, "executed", artifacts=len(params))
    except Exception as e:
        log(f"Arjun scan failed: {e}", "DEBUG")
        orch.mark_module("arjun", port, "failed", reason=str(e))

    # 6. API Discovery (Kiterunner)
    try:
         api_scanner = APIScanner(target)
         if api_scanner.check_tools():
            log(f"API Discovery (Kiterunner)...", "INFO")
            _ts(lambda: results['commands'].append({'tool': 'kiterunner', 'cmd': shlex.join(api_scanner.get_command(port, protocol=proto))}))
            api_stream = api_scanner.stream_api_discovery(port, protocol=proto, logger=log)
            api_endpoints = []
            for ev in api_stream:
                if ev["type"] == "stdout" and ev["line"].strip():
                    parts = ev["line"].split()
                    if len(parts) >= 2 and parts[1].startswith(('2', '3')):
                        url = parts[0]
                        if not url.startswith("http"): url = f"{proto}://{target}:{port}/{url.lstrip('/')}"
                        api_endpoints.append(url)
            
            if api_endpoints:
                 def _store_api():
                     results['phases']['enum']['api'].setdefault('discovered_endpoints', []).extend(api_endpoints)
                     results['phases']['enum']['api'][str(port)] = api_endpoints[:100]
                     results['phases']['enum']['api'].setdefault('endpoints', []).extend([{"url": url, "status": 200} for url in api_endpoints])
                 _ts(_store_api)
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
                log(f"Tech Stack: {tech_data.get('modernization_level', 'Standard')} architecture identified.", "SUCCESS")
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
