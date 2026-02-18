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

def analyze_security_headers(target, port, proto, results, logger_func):
    """
    Analyzes HTTP headers for security configurations.
    Populates results['phases']['enum']['headers']
    """
    try:
        url = f"{proto}://{target}:{port}"
        # logger_func(f"Fetching headers from {url}...", "DEBUG") # Too verbose?
        try:
            resp = requests.head(url, timeout=5, verify=False, allow_redirects=True)
        except:
             resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
             
        headers = resp.headers
        
        # Store in results
        if 'enum' not in results['phases']: results['phases']['enum'] = {}
        if 'headers' not in results['phases']['enum']: results['phases']['enum']['headers'] = {}
        
        # Convert CaseInsensitiveDict to dict for JSON serialization
        results['phases']['enum']['headers'][str(port)] = dict(headers)
        
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
    except:
        return url.strip()

def run_enum(orchestrator, port, proto):
    """
    Executes Phase 2: Enumeration on a specific port (V6 Hardened)
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    
    full_ww = ""
    
    # --- GUARANTEED INITIALIZATION ---
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
    orch.save_results(orch.scan_id, results)
    
    # 1. Web Recon (WhatWeb)
    try:
        web_recon = WebReconScanner(target)
        if web_recon.check_tools():
            log(f"Fingerprinting {proto}://{target}:{port}...", "INFO")
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
                except: pass

            ww = results['phases']['enum'].setdefault('whatweb', {})
            ww.setdefault('summary', {})[str(port)] = full_ww
            ww.setdefault('technologies', {})[str(port)] = techs
            orch.save_results(orch.scan_id, results)
            orch.mark_module("whatweb", port, "executed", artifacts=len(techs))
    except Exception as e:
        log(f"WhatWeb failed: {e}", "ERROR")
        orch.mark_module("whatweb", port, "failed")

    # 2. Security Headers
    try:
        analyze_security_headers(target, port, proto, results, log)
        orch.mark_module("headers", port, "executed")
    except: pass

    # 3. Katana Crawler
    try:
         katana = KatanaScanner(target)
         if katana.check_tools():
             log(f"Crawling {proto}://{target}:{port} (Katana)...", "INFO")
             kt_stream = katana.stream_scan(port, proto)
             endpoints = [ev["line"].strip() for ev in kt_stream if ev["type"] == "stdout" and ev["line"].strip()]
             results['phases']['enum']['katana'][str(port)] = endpoints[:1000]
             orch.mark_module("katana", port, "executed", artifacts=len(endpoints))
    except: pass

    # 4. WAF Detection
    try:
        waf_scanner = WafScanner(target)
        if waf_scanner.check_tools():
            waf_stream = waf_scanner.stream_wafw00f(port, proto)
            for event in waf_stream:
                if "is behind" in event.get("line", ""):
                    res = event["line"].split("is behind")[-1].strip()
                    results['phases']['enum'].setdefault('waf', {})[str(port)] = res
                    log(f"🛡️ WAF: {res}", "SUCCESS")
            orch.mark_module("waf", port, "executed")
    except: pass

    # 5. Arjun Param Discovery
    try:
        arjun = ArjunScanner(target)
        if arjun.check_tools():
            log(f"Discovering parameters (Arjun)...", "INFO")
            ar_stream = arjun.stream_arjun(port, proto)
            params = []
            for ev in ar_stream:
                if ev["type"] == "stdout" and "parameter" in ev["line"].lower():
                    p = ev["line"].split(":")[-1].strip()
                    if p: params.append(p)
            if params:
                results['phases']['enum']['arjun'][str(port)] = params
            orch.mark_module("arjun", port, "executed", artifacts=len(params))
    except: pass

    # 6. API Discovery (Kiterunner)
    try:
         api_scanner = APIScanner(target)
         if api_scanner.check_tools():
            log(f"API Discovery (Kiterunner)...", "INFO")
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
                 results['phases']['enum']['api'].setdefault('discovered_endpoints', []).extend(api_endpoints)
                 results['phases']['enum']['api'][str(port)] = api_endpoints[:100]
                 # Also keep a flat list for the report template (legacy compat)
                 results['phases']['enum']['api'].setdefault('endpoints', []).extend([{"url": url, "status": 200} for url in api_endpoints])
            orch.mark_module("api_scanner", port, "executed", artifacts=len(api_endpoints))
    except: pass

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
        
        results['phases']['enum']['normalized'][str(port)] = canonical['normalized']
        results['phases']['enum']['derived'][str(port)] = canonical['derived']
        results['phases']['enum']['targets'][str(port)] = canonical['derived']['targets']
        results['phases']['enum']['injection_points'][str(port)] = canonical['derived']['injection_points']
        results['phases']['enum']['seed_meta'][str(port)] = canonical['derived'].get('seed_meta', {})
        
        orch.save_results(orch.scan_id, results)
        log(f"Seed Factory: derived {len(canonical['derived']['injection_points'])} seeds.", "SUCCESS")

        # --- TECHNOLOGY STACK INTELLIGENCE ---
        try:
            tech_scanner = TechExposureScanner(target)
            tech_data = tech_scanner.audit(port, protocol=proto, logger=log)
            if tech_data:
                results['phases']['enum']['tech'] = tech_data
                # Also mirror to vuln for template compatibility
                results['phases']['vuln'].setdefault('tech', tech_data)
                orch.save_results(orch.scan_id, results)
                log(f"Tech Stack: {tech_data.get('modernization_level', 'Standard')} architecture identified.", "SUCCESS")
        except Exception as e:
            log(f"Tech Exposure Scanner Error: {e}", "DEBUG")

        # Context Attack Engine
        try:
            context_engine = ContextAttackEngine(results, logger=log)
            profile = context_engine.build_attack_profile(port)
            strategy = context_engine.derive_mutation_strategy(profile)
            results['phases']['enum']['attack_profile'] = {str(port): profile}
            results['phases']['enum']['mutation_strategy'] = {str(port): strategy}
            orch.save_results(orch.scan_id, results)
        except: pass

    except Exception as e:
        log(f"Seed Factory Error: {e}", "ERROR")

    return full_ww
