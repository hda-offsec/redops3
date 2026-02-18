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

def run_enum(orchestrator, port, proto):
    """
    Executes Phase 2: Enumeration on a specific port
    - Web Recon (WhatWeb)
    - WAF Detection
    - Technology Exposure
    - Security Headers
    - API Discovery
    - JS Secrets
    - Parameter Discovery (Arjun)
    """
    orch = orchestrator
    results = orch.results
    target = orch.target
    log = orch.log
    
    full_ww = ""
    
    # 1. Web Recon (WhatWeb)
    # Using existing WebReconScanner wrapper
    try:
        web_recon = WebReconScanner(target)
        if web_recon.check_tools():
            log(f"Fingerprinting {proto}://{target}:{port} (WhatWeb)...", "INFO")
            ww_cmd = web_recon.get_command(port, proto)
            results['commands'].append({'tool': 'whatweb', 'cmd': shlex.join(ww_cmd)})
            
            # Using stream_scan from WebReconScanner? 
            # Original Orchestrator logic:
            # ww_stream = web_recon.stream_scan(port, proto)
            # ... parsing loop ...
            
            # Let's replicate the stream consumption logic here or simplify if WebReconScanner handles it.
            # WebReconScanner.stream_scan yields events.
            
            ww_stream = web_recon.stream_whatweb(port, proto)
            full_ww = ""
            current_tech = {}
            
            for event in ww_stream:
                if event["type"] == "stdout":
                    line = event["line"].strip()
                    full_ww += line + "\n"
                    # Log finding logic...
                    if "[" in line and "]" in line:
                        # Simple parsing for log, specific parsing can be added
                        log(line[:100] + "..." if len(line)>100 else line, "INFO")
            
            # Parse WhatWeb output for structured reporting
            techs = []
            for line in full_ww.split('\n'):
                line = line.strip()
                if not line or not line.startswith("http"): continue
                
                # Format: URL [Status] Plugin[Ver], Plugin...
                try:
                    # Remove URL and Status
                    parts = line.split(']', 1)
                    if len(parts) > 1:
                        tech_part = parts[1].strip()
                        # specific parser for WhatWeb's comma-separated list
                        # Caveat: Values inside [] might contain commas? specific parser needed?
                        # Simple split by ", " work for most cases
                        raw_techs = tech_part.split(', ')
                        for t in raw_techs:
                            t = t.strip()
                            if t and t not in techs:
                                techs.append(t)
                except:
                    pass

            # Update results
            if 'enum' not in results['phases']: results['phases']['enum'] = {}
            if 'whatweb' not in results['phases']['enum']: results['phases']['enum']['whatweb'] = {}
            if 'summary' not in results['phases']['enum']['whatweb']: results['phases']['enum']['whatweb']['summary'] = {}
            if 'technologies' not in results['phases']['enum']['whatweb']: results['phases']['enum']['whatweb']['technologies'] = {}
            
            results['phases']['enum']['whatweb']['summary'][str(port)] = full_ww
            results['phases']['enum']['whatweb']['technologies'][str(port)] = techs
            
            # --- TECHNOLOGY SCORING ---
            # Basic heuristic to populate 'enum.tech' for the report
            if 'tech' not in results['phases']['enum']: results['phases']['enum']['tech'] = {}
            
            # Calculate score based on keywords
            score = 50 # Base
            modern_keywords = ['React', 'Vue', 'Angular', 'Node', 'Express', 'Python', 'Django', 'Flask', 'Go', 'Ruby', 'Rails', 'Cloudflare', 'AWS', 'Docker', 'Kubernetes']
            legacy_keywords = ['PHP', 'Apache', 'IIS', 'ASP.NET', 'JQuery', 'Bootstrap']
            cms_keywords = ['WordPress', 'Joomla', 'Drupal']
            
            tags_found = set(techs)
            
            # Adjust score
            for t in tags_found:
                if any(k.lower() in t.lower() for k in modern_keywords): score += 10
                if any(k.lower() in t.lower() for k in legacy_keywords): score -= 5
                if any(k.lower() in t.lower() for k in cms_keywords): score -= 5
                
            score = max(0, min(100, score))
            
            # Determine Level
            if score >= 80: level = "Bleeding Edge"
            elif score >= 60: level = "Modern"
            elif score >= 40: level = "Standard / Mixed"
            else: level = "Legacy / Outdated"
            
            results['phases']['enum']['tech']['technology_score'] = score
            results['phases']['enum']['tech']['modernization_level'] = level
            
            orch.save_results(orch.scan_id, results)
            orch.mark_module("whatweb", port, "executed", artifacts=len(techs))
            orch.add_finding(title=f"Module Executed: whatweb", description=f"WhatWeb completed on port {port}", severity="info", tool_source="redops-core")
            
            # return full_ww # MOVED TO END
            
    except Exception as e:
        log(f"Web Recon failed: {e}", "ERROR")
        orch.mark_module("whatweb", port, "failed")

    # 2. Security Headers (Moved BEFORE specialized scans for better detection context)
    try:
        missing, headers_dict = analyze_security_headers(target, port, proto, results, log)
        if missing:
            log(f"Missing Security Headers on {port}: {', '.join(missing)}", "INFO")
        
        # Ensure headers are actually saved!
        orch.save_results(orch.scan_id, results)
        orch.mark_module("headers", port, "executed", artifacts=len(headers_dict))
        orch.add_finding(title=f"Module Executed: headers", description=f"Headers analyzed on port {port}", severity="info", tool_source="redops-core")
            
    except Exception as e:
        log(f"Security Header Analysis failed: {e}", "ERROR")
        orch.mark_module("headers", port, "failed")

    # 2.5 Katana (New)
    try:
         katana = KatanaScanner(target)
         if katana.check_tools():
             log(f"Crawling {proto}://{target}:{port} with Katana...", "INFO")
             cmd_kat = katana.get_command(port, proto)
             results['commands'].append({'tool': 'katana', 'cmd': shlex.join(cmd_kat)})
             
             kt_stream = katana.stream_scan(port, proto)
             endpoints = []
             
             for event in kt_stream:
                 if event["type"] == "stdout":
                     line = event["line"].strip()
                     if line:
                         endpoints.append(line)
                         log(f"Katana found: {line}", "DEBUG")
             
             # Store results safely
             if 'enum' not in results['phases']: results['phases']['enum'] = {}
             results['phases']['enum'].setdefault('katana', {})
             results['phases']['enum']['katana'][str(port)] = endpoints
             
             orch.save_results(orch.scan_id, results)
             orch.mark_module("katana", port, "executed", artifacts=len(endpoints))
             orch.add_finding(title=f"Module Executed: katana", description=f"Katana crawler finished on port {port}", severity="info", tool_source="redops-core")
             
    except Exception as e:
        log(f"Katana crawl failed: {e}", "ERROR")
        orch.mark_module("katana", port, "failed")

    # 3. WAF Detection
    try:
        waf_scanner = WafScanner(target)
        if waf_scanner.check_tools():
            log(f"Detecting WAF on {proto}://{target}:{port}...", "INFO")
            cmd = waf_scanner.get_command(port, proto)
            results['commands'].append({'tool': 'wafw00f', 'cmd': shlex.join(cmd)})
            
            waf_stream = waf_scanner.stream_wafw00f(port, proto)
            waf_result = "None"
            for event in waf_stream:
                if event["type"] == "stdout":
                    line = event["line"].strip()
                    if "is behind" in line:
                         waf_result = line.split("is behind")[-1].strip()
                         log(f"🛡️ WAF Detected: {waf_result}", "SUCCESS")
                         
            if 'enum' not in results['phases']: results['phases']['enum'] = {}
            if 'waf' not in results['phases']['enum']: results['phases']['enum']['waf'] = {}
            results['phases']['enum']['waf'][str(port)] = waf_result
            orch.save_results(orch.scan_id, results)
            orch.mark_module("waf", port, "executed", artifacts=1)
            orch.add_finding(title=f"Module Executed: waf", description=f"WAF detection finished on port {port}", severity="info", tool_source="redops-core")
    except Exception as e:
        log(f"WAF Check failed: {e}", "ERROR")
        orch.mark_module("waf", port, "failed")

    # 4. Tech Exposure
    try:
         tech_scanner = TechExposureScanner(target)
         ts_findings = tech_scanner.audit(port, proto, logger=log)
         if ts_findings:
             if 'vuln' not in results['phases']: results['phases']['vuln'] = {}
             # Tech exposure often considered a vulnerability/misconfiguration
             results['phases']['vuln']['tech'] = ts_findings
             for f in ts_findings:
                 orch.add_finding(
                     title=f['title'],
                     description=f['description'],
                     severity=f['severity'],
                     tool_source="tech_audit"
                 )
         orch.save_results(orch.scan_id, results)
         orch.mark_module("tech_scanner", port, "executed", artifacts=len(ts_findings) if ts_findings else 0)
         orch.add_finding(title=f"Module Executed: tech_scanner", description=f"Tech exposure audit finished on port {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"Tech exposure audit failed on port {port}: {e}", "DEBUG")
        orch.mark_module("tech_scanner", port, "failed")

    # 5. Arjun (Parameters)
    try:
        arjun = ArjunScanner(target)
        if arjun.check_tools():
            log(f"Discovering parameters on {proto}://{target}:{port}...", "INFO")
            cmd_ar = arjun.get_command(port, proto)
            results['commands'].append({'tool': 'arjun', 'cmd': shlex.join(cmd_ar)})
            
            ar_stream = arjun.stream_arjun(port, proto)
            params = []
            for event in ar_stream:
                if event["type"] == "stdout":
                     line = event["line"].strip()
                     if "parameter" in line.lower() and "found" in line.lower():
                         parts = line.split(":")
                         if len(parts)>1: params.append(parts[1].strip())
            
            if params:
                log(f"Arjun found parameters: {params}", "SUCCESS")
                if 'enum' not in results['phases']: results['phases']['enum'] = {}
                if 'arjun' not in results['phases']['enum']: results['phases']['enum']['arjun'] = {}
                results['phases']['enum']['arjun'][str(port)] = params
            
            orch.save_results(orch.scan_id, results)
            orch.mark_module("arjun", port, "executed", artifacts=len(params))
            orch.add_finding(title=f"Module Executed: arjun", description=f"Arjun completed on port {port}", severity="info", tool_source="redops-core")
    except Exception as e:
        log(f"Arjun failed: {e}", "DEBUG")
        orch.mark_module("arjun", port, "failed")

    # 6. JS Secrets
    try:
        js_scanner = JSSecretScanner(target)
        # Scan Headers
        url = f"{proto}://{target}:{port}"
        try:
             resp = requests.head(url, timeout=5, verify=False, allow_redirects=True)
             header_text = str(dict(resp.headers))
             s_findings = js_scanner.scan_text(header_text, f"HTTP Headers ({port})")
             
             # Scan Body (if feasible, usually part of crawling, but quick check here)
             # Orchestrator used 'resp.text' from header analysis which was a GET if HEAD failed.
             # We can re-fetch or assume header analysis passed resp/logic.
             # Let's do a quick fetch if not expensive.
             resp_body = requests.get(url, timeout=5, verify=False, allow_redirects=True).text
             s_findings.extend(js_scanner.scan_text(resp_body, f"Response Body ({port})"))

             if s_findings:
                if 'enum' not in results['phases']: results['phases']['enum'] = {}
                if 'js_secrets' not in results['phases']['enum']: results['phases']['enum']['js_secrets'] = []
                # Ensure it is a list if it was initialized as dict by mistake or legacy
                if isinstance(results['phases']['enum']['js_secrets'], dict):
                     results['phases']['enum']['js_secrets'] = []
                
                results['phases']['enum']['js_secrets'].extend(s_findings)

                for f in s_findings:
                    orch.add_finding(
                        title=f['title'],
                        description=f['description'],
                        severity=f['severity'],
                        tool_source="secret_scanner"
                    )
                    # HARVEST TO LOOT VAULT
                    if orch.add_loot and f.get('raw_secret'):
                        orch.add_loot(
                            loot_type=f.get('secret_type', 'Secret'),
                            content=f['raw_secret'],
                            context=f"Discovered in {f['tool_source']} at {url}"
                        )
             orch.save_results(orch.scan_id, results)
             orch.mark_module("js_scanner", port, "executed", artifacts=len(s_findings))
             orch.add_finding(title=f"Module Executed: js_scanner", description=f"JS secret scan finished on {port}", severity="info", tool_source="redops-core")
        except Exception:
            pass
    except Exception:
        orch.mark_module("js_scanner", port, "failed")
        pass

    # 7. API Discovery
    try:
         api_scanner = APIScanner(target)
         if api_scanner.check_tools():
            log(f"Scanning for API endpoints on {proto}://{target}:{port}...", "INFO")
            cmd_api = api_scanner.get_command(port, proto)
            results['commands'].append({'tool': 'kiterunner', 'cmd': shlex.join(cmd_api)})
            
            api_stream = api_scanner.stream_api_discovery(port, protocol=proto, logger=log)
            api_endpoints = []
            
            for event in api_stream:
                if event["type"] == "stdout":
                    line = event["line"].strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        status = parts[1] # heuristic
                        if status.isdigit() and status.startswith(('2', '3')):
                             api_endpoints.append(line)
            
            if api_endpoints:
                 log(f"Found {len(api_endpoints)} potential API endpoints.", "SUCCESS")
                 if 'enum' not in results['phases']: results['phases']['enum'] = {}
                 if 'api' not in results['phases']['enum']: results['phases']['enum']['api'] = {}
                 results['phases']['enum']['api']['discovered_endpoints'] = api_endpoints
                 
                 found_items_api = []
                 for ep in api_endpoints[:20]: # Limit for UI
                     found_items_api.append({'url': ep, 'status': '200'}) # Mock status parsing for UI
                     
                     orch.add_finding(
                        title=f"API Endpoint Discovered",
                        description=f"Endpoint: {ep}",
                        severity="info",
                        tool_source="kiterunner",
                        command=shlex.join(cmd_api)
                    )

                 # Update results structure for UI
                 if 'api' not in results['phases']['enum']: results['phases']['enum']['api'] = {}
                 results['phases']['enum']['api'][str(port)] = found_items_api
                 orch.save_results(orch.scan_id, results)

                 # --- EXPERT API ANALYSIS ---
                 try:
                    # Fix: Pass 'orch.target' correctly if needed by APIExpertScanner
                    # Actually APIExpertScanner takes target in init.
                    api_expert = APIExpertScanner(target)
                    # It expects a list of endpoints (strings or dicts?)
                    # audit_endpoints usually takes list of strings
                    expert_findings = api_expert.audit_endpoints(api_endpoints, logger=log)
                    if expert_findings:
                        for f in expert_findings:
                            orch.add_finding(
                                title=f['title'],
                                description=f['description'],
                                severity=f['severity'],
                                tool_source="api_expert"
                            )
                            # HARVEST TO LOOT VAULT
                            if orch.add_loot and f.get('raw_loot'):
                                orch.add_loot(
                                    loot_type=f.get('loot_type', 'API Loot'),
                                    content=f['raw_loot'],
                                    context=f"Discovered in expert API audit at {target}:{port}"
                                )
                        orch.save_results(orch.scan_id, results)
                 except Exception as e:
                     log(f"API Expert analysis failed for port {port}: {e}", "DEBUG")

            orch.mark_module("api_scanner", port, "executed", artifacts=len(api_endpoints))
            orch.add_finding(title=f"Module Executed: api_scanner", description=f"API discovery finished on port {port}", severity="info", tool_source="redops-core")

    except Exception as e:
        log(f"API discovery failed: {e}", "DEBUG")
        orch.mark_module("api_scanner", port, "failed")
    
    return full_ww
