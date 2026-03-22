import json
import logging
import re
import time
from urllib.parse import parse_qs, quote_plus, urlparse

from requests import RequestException

from scan_engine.helpers.http_client import get_session


LOGGER = logging.getLogger(__name__)
OBJECT_REFERENCE_PARAMS = {"id", "user_id", "account_id", "order_id", "owner_id", "tenant_id", "uuid"}
URL_REFERENCE_PAYLOADS = [
    "1",
    "2",
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
]


def _normalize_text_fingerprint(value):
    normalized = str(value or "").strip().lower()
    normalized = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", "<uuid>", normalized)
    normalized = re.sub(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", "<email>", normalized)
    normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", normalized)
    normalized = re.sub(r"\b\d+\b", "<num>", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def _normalize_json_value(value):
    if isinstance(value, dict):
        return {str(key): _normalize_json_value(value[key]) for key in sorted(value.keys(), key=str)}
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return "<num>"
    return _normalize_text_fingerprint(value)


def _response_fingerprint(response_body, status_code):
    raw = str(response_body or "").strip()
    try:
        normalized = json.dumps(_normalize_json_value(json.loads(raw)), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, json.JSONDecodeError):
        normalized = _normalize_text_fingerprint(raw)
    return status_code, normalized[:400]


def _extract_body_object_ids(body):
    matches = set()
    for key in ["id", "user_id", "account_id", "order_id", "owner_id", "tenant_id", "uuid"]:
        pattern = rf'"{re.escape(key)}"\s*:\s*"?(?P<value>[A-Za-z0-9_-]{{1,64}})"?'
        for match in re.finditer(pattern, str(body or ""), flags=re.IGNORECASE):
            value = match.group("value").strip()
            if value:
                matches.add(value.lower())
    return matches


def _emit_engine_error(logger, stage, endpoint, exc, **context):
    message = f"{stage} failed for {endpoint}: {exc.__class__.__name__}: {exc}"
    if logger:
        logger(message, "DEBUG")
    LOGGER.debug(message, extra={"stage": stage, "endpoint": endpoint, "context": context}, exc_info=True)


class ContextAttackEngine:
    """
    V6 Evolution: Analyzes enumeration intelligence to adapt the offensive strategy.
    Transforms raw tech detection into actionable attack profiles.
    """
    def __init__(self, results, logger=None, options=None):
        self.options = options
        self.results = results
        self.log = logger
        
    def build_attack_profile(self, port):
        """
        Analyzes WhatWeb, tech scores, and endpoint semantics for a specific port.
        """
        stack = []
        risk_vectors = []
        port_str = str(port)
        
        # 1. Extract Tech Stack from WhatWeb
        enum_data = self.results.get('phases', {}).get('enum', {})
        ww_data = enum_data.get('whatweb', {}).get(port_str, {})
        
        # Heuristics for stack detection
        full_text = str(ww_data).lower()
        if any(x in full_text for x in ['php', 'apache', 'phpsessid']):
            stack.append("php")
        if any(x in full_text for x in ['node', 'express', 'next.js', 'react']):
            stack.append("node")
        if any(x in full_text for x in ['wordpress', 'wp-content']):
            stack.append("wordpress")
        if any(x in full_text for x in ['python', 'django', 'flask', 'gunicorn']):
            stack.append("python_web")
        if any(x in full_text for x in ['asp.net', 'iis', '.net', 'aspx']):
            stack.append("dotnet")
        if any(x in full_text for x in ['react', 'vue', 'angular', 'svelte', 'webpack', 'vite']):
            stack.append("spa")

        # Fallback to generic if nothing detected
        if not stack:
            stack = ["generic"]

        # 2. Analyze Endpoint Semantics (Risk Vectors)
        # We look at normalized endpoints found on this port
        norm_data = enum_data.get('normalized', {}).get(port_str, {})
        endpoints = norm_data.get('endpoints', []) if isinstance(norm_data, dict) else []
        
        vector_keywords = {
            "redirect": ["redirect", "url=", "next=", "dest=", "return", "goto"],
            "file": ["file", "path", "page", "include", "template", "doc"],
            "auth": ["login", "admin", "auth", "session", "user"],
            "api": ["api", "v1", "v2", "json", "graphql", "rest"],
            "upload": ["upload", "import", "attachment"]
        }
        
        seen_paths = " ".join([ep.get('url', '').lower() for ep in endpoints if isinstance(ep, dict)])
        for vector, keywords in vector_keywords.items():
            if any(kw in seen_paths for kw in keywords):
                risk_vectors.append(vector)

        profile = {
            "stack": list(set(stack)),
            "risk_vectors": list(set(risk_vectors)),
            "confidence": 70 if stack != ["generic"] else 30
        }
        
        if self.log:
            self.log(f"ContextAttackEngine: profile={profile['stack']} vectors={profile['risk_vectors']}", "DEBUG")
            
        return profile


    def derive_mutation_strategy(self, profile):
        """
        Transforms a profile into a set of enabled mutation flags and extra parameters.
        """
        strategy = {
            "enable_lfi": False,
            "enable_ssrf": False,
            "enable_proto_pollution": False,
            "enable_wp_routes": False,
            "enable_json_mutations": False,
            "extra_params": []
        }
        
        stack = profile.get("stack", [])
        vectors = profile.get("risk_vectors", [])
        
        if "php" in stack:
            strategy["enable_lfi"] = True
            strategy["extra_params"].extend(["file", "path", "page", "include"])
            
        if "node" in stack:
            strategy["enable_json_mutations"] = True
            strategy["enable_proto_pollution"] = True
            strategy["extra_params"].extend(["__proto__", "constructor", "prototype"])
            
        if "wordpress" in stack:
            strategy["enable_wp_routes"] = True
            strategy["extra_params"].extend(["rest_route", "action"])
            
        if "redirect" in vectors or "api" in vectors:
            strategy["enable_ssrf"] = True
            strategy["extra_params"].extend(["url", "redirect", "next", "dest", "uri", "callback"])
            
        # Deduplicate extra params
        strategy["extra_params"] = list(set(strategy["extra_params"]))
        
        if self.log:
            self.log(f"Mutation Strategy Enabled: {strategy}", "INFO")
            
        return strategy


class APIIntelligenceEngine:
    """Derive API surface intelligence from existing telemetry and execute bounded active checks."""

    API_HINTS = ("/api/", "/v1", "/v2", "/rest", "/graphql")
    AUTH_HINTS = ("/auth", "/login", "/signin", "/session", "/oauth")
    ADMIN_HINTS = ("/admin", "/internal", "/manage")
    TOKEN_HINTS = ("token", "jwt", "apikey", "api_key")

    @staticmethod
    def _iter_endpoint_candidates(results):
        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}

        for _, endpoints in (enum.get("targets", {}) or {}).items():
            if isinstance(endpoints, list):
                for endpoint in endpoints:
                    if isinstance(endpoint, str):
                        yield endpoint, "enum.targets"

        discovered_api = enum.get("api", {}).get("discovered_endpoints", [])
        if isinstance(discovered_api, list):
            for endpoint in discovered_api:
                if isinstance(endpoint, str):
                    yield endpoint, "api_scanner"

        for _, data in (enum.get("js_deep_mining", {}) or {}).items():
            if not isinstance(data, dict):
                continue
            for endpoint in data.get("discovered_endpoints", []) or []:
                if isinstance(endpoint, str):
                    yield endpoint, "js_deep_mining"

    @classmethod
    def derive_surface(cls, results, target):
        findings = []
        api_inventory = []
        seen = set()
        injection_points = results.get("phases", {}).get("enum", {}).get("injection_points", {})

        for endpoint, source in cls._iter_endpoint_candidates(results):
            low = endpoint.lower()
            if not any(h in low for h in cls.API_HINTS + cls.AUTH_HINTS + cls.ADMIN_HINTS):
                continue

            parsed = urlparse(endpoint)
            params = sorted(parse_qs(parsed.query).keys())
            if isinstance(injection_points, dict):
                port = str(parsed.port) if parsed.port else ""
                params.extend([p for p in (injection_points.get(port) or []) if isinstance(p, str)])
            params = sorted(set(params))
            method = "GET"

            key = (endpoint, method, ",".join(params), source)
            if key in seen:
                continue
            seen.add(key)

            tags = []
            if any(h in low for h in cls.AUTH_HINTS):
                tags.append("auth")
            if any(h in low for h in cls.ADMIN_HINTS):
                tags.append("admin")
            if any(h in low for h in cls.TOKEN_HINTS):
                tags.append("token")

            findings.append({
                "title": "API Surface Endpoint Discovered",
                "severity": "info" if not tags else "medium",
                "confidence": "high" if source in {"api_scanner", "enum.targets"} else "medium",
                "tool_source": "api_intelligence_engine",
                "module": "api_intelligence",
                "category": "api_surface",
                "target": target,
                "endpoint": endpoint,
                "parameter": ",".join(params[:12]),
                "description": "Discovered API-like endpoint with extracted parameter and route semantics.",
                "evidence": json.dumps({"method": method, "parameters": params[:20], "source": source, "tags": tags}, default=str),
                "metadata": {"method": method, "parameters": params[:20], "source": source, "tags": tags},
            })

            api_inventory.append({"endpoint": endpoint, "method": method, "parameters": params[:20], "source": source, "tags": tags})

        return findings, api_inventory

    @staticmethod
    def fuzz_surface(api_inventory, options=None, logger=None):
        options = options or {}
        max_requests = int(options.get("api_fuzz_max_requests", 40) or 40)
        timeout = float(options.get("timeout", 6) or 6)

        if max_requests <= 0:
            return []

        checks = {
            "idor": URL_REFERENCE_PAYLOADS,
            "ssrf": ["http://127.0.0.1", "http://localhost"],
            "command_injection": ["test;id", "test&&whoami"],
            "sqli": ["1' OR '1'='1", "1 UNION SELECT NULL"],
            "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
        }
        default_params = ["id", "url", "path", "q"]
        findings = []
        used = 0
        session = get_session(options)

        try:
            for item in api_inventory:
                if not isinstance(item, dict):
                    continue
                endpoint = item.get("endpoint")
                if not endpoint:
                    continue
                params = [p for p in (item.get("parameters") or []) if isinstance(p, str)] or default_params
                baseline_resp = None
                baseline_body = ""
                baseline_sig = None
                baseline_fetch_attempted = False
                for param in params[:3]:
                    for test_type, payloads in checks.items():
                        for payload in payloads[:2]:
                            if used >= max_requests:
                                return findings
                            used += 1
                            encoded = quote_plus(payload)
                            separator = "&" if "?" in endpoint else "?"
                            url = f"{endpoint}{separator}{param}={encoded}"
                            try:
                                resp = session.get(url, timeout=timeout, allow_redirects=False)
                                body = (resp.text or "")[:1200]
                            except RequestException as exc:
                                _emit_engine_error(logger, "api_fuzz_request", url, exc, inventory_endpoint=endpoint, parameter=param, test_type=test_type)
                                continue

                            body_low = body.lower()
                            is_hit = False
                            evidence = ""
                            differential_reasons = []
                            baseline_ids = set()
                            candidate_ids = set()
                            
                            # V12: Hardened Signal Detection
                            if test_type == "idor" and resp.status_code == 200 and param.lower() in OBJECT_REFERENCE_PARAMS:
                                if not baseline_fetch_attempted and used < max_requests:
                                    baseline_fetch_attempted = True
                                    used += 1
                                    try:
                                        baseline_resp = session.get(endpoint, timeout=timeout, allow_redirects=False)
                                        baseline_body = (baseline_resp.text or "")[:1200]
                                        baseline_sig = _response_fingerprint(baseline_body, baseline_resp.status_code)
                                    except RequestException as exc:
                                        _emit_engine_error(logger, "api_fuzz_idor_baseline", endpoint, exc, inventory_endpoint=endpoint)

                                candidate_sig = _response_fingerprint(body, resp.status_code)
                                candidate_ids = _extract_body_object_ids(body)
                                baseline_ids = _extract_body_object_ids(baseline_body)
                                if baseline_resp is None:
                                    differential_reasons.append("missing_baseline")
                                else:
                                    if baseline_resp.status_code in {401, 403, 404}:
                                        differential_reasons.append(f"baseline_{baseline_resp.status_code}_candidate_200")
                                    if baseline_sig != candidate_sig:
                                        differential_reasons.append("response_fingerprint_changed")
                                    if candidate_ids and candidate_ids != baseline_ids:
                                        differential_reasons.append("object_identifier_changed")

                                meaningful_differential = any(
                                    reason.startswith("baseline_") or reason == "response_fingerprint_changed"
                                    for reason in differential_reasons
                                )

                                if any(x in body_low for x in ['"id":', '"username":', '"user":', '"email":', '"account":']) and meaningful_differential:
                                    is_hit = True
                                    evidence = (
                                        f"ID parameter produced a differentiated 200 OK response with structured object markers "
                                        f"({', '.join(sorted(differential_reasons))})."
                                    )

                            elif test_type == "ssrf":
                                # Must find actual meta-data content, not just the keywords in error messages
                                if any(x in body_low for x in ["instance-id", "latest/meta-data", "ami-id", "root:x:0:0"]):
                                    is_hit = True
                                    evidence = "Response contains high-confidence internal or cloud metadata signatures."
                                elif "127.0.0.1" in body_low and resp.status_code == 200 and len(body) > 50:
                                    # Heuristic for generic localhost reflection
                                    is_hit = True
                                    evidence = "Localhost indicator found in 200 OK response."

                            elif test_type == "command_injection" and re.search(r"(uid=\d+|gid=\d+|root:x:)", body_low):
                                is_hit = True
                                evidence = "Response includes command execution indicators."
                            elif test_type == "sqli" and any(x in body_low for x in ["sql syntax", "mysql", "postgres", "sqlite", "odbc"]):
                                is_hit = True
                                evidence = "Response contains SQL error patterns."
                            elif test_type == "path_traversal" and any(x in body_low for x in ["root:x:0:0", "[extensions]"]):
                                is_hit = True
                                evidence = "Traversal payload returned sensitive file signature."

                            if not is_hit:
                                continue

                            findings.append({
                                "title": f"API Fuzzing Signal: {test_type.replace('_', ' ').title()}",
                                "severity": "high" if test_type in {"command_injection", "sqli", "path_traversal"} else "medium",
                                "confidence": "medium",
                                "tool_source": "api_fuzz_engine",
                                "module": "api_fuzzing",
                                "category": test_type,
                                "endpoint": endpoint,
                                "parameter": param,
                                "payload": payload,
                                "response": body,
                                "evidence": evidence,
                                "repro_command": f"curl -isk '{url}'",
                                "metadata": {
                                    "status_code": resp.status_code,
                                    "test_type": test_type,
                                    "differential_reasons": sorted(differential_reasons),
                                    "baseline_status": getattr(baseline_resp, "status_code", None),
                                    "baseline_object_ids": sorted(baseline_ids),
                                    "candidate_object_ids": sorted(candidate_ids),
                                    "request_budget_used": used,
                                },
                            })
        finally:
            session.close()

        return findings


class ExploitValidationEngine:
    """
    V7 ADVANCED: Rigorous Verification Engine.
    Performs active, differential double-checks to confirm findings.
    """

    @staticmethod
    def _is_candidate(finding):
        title = str(finding.get("title", "")).lower()
        category = str(finding.get("category", "")).lower()
        combined = f"{title} {category}"
        markers = ["ssrf", "lfi", "rce", "open redirect", "cors", "http method", "upload", "nosql", "xxe"]
        return any(m in combined for m in markers)

    @classmethod
    def validate(cls, findings, options=None, logger=None):
        options = options or {}
        # Always enable for critical/high unless explicitly disabled
        if not options.get("enable_exploit_validation", True):
            return []

        max_requests = int(options.get("validation_max_requests", 30) or 30)
        timeout = float(options.get("timeout", 6) or 6)
        session = get_session(options)
        out = []
        used = 0

        try:
            for item in findings:
                if not isinstance(item, dict) or not cls._is_candidate(item):
                    continue

                # Skip if already highly confident and verified by redops native scanners
                if item.get("confidence") == "high" and "verified" in str(item.get("description", "")):
                    continue

                endpoint = item.get("endpoint") or item.get("target")
                if not endpoint or not str(endpoint).startswith(("http://", "https://")):
                    continue

                # 0. BASELINE FETCH
                try:
                    b_start = time.monotonic()
                    baseline_resp = session.get(endpoint, timeout=timeout, allow_redirects=False)
                    baseline_duration = time.monotonic() - b_start
                    baseline_text = baseline_resp.text or ""
                except RequestException as exc:
                    _emit_engine_error(logger, "exploit_validation_baseline", endpoint, exc, finding_title=item.get("title"))
                    continue

                title_low = str(item.get("title", "")).lower()
                cat_low = str(item.get("category", "")).lower()
                target = f"{title_low} {cat_low}"

                tests = []
                # Advanced Payloads
                if "ssrf" in target:
                    tests.append(("url", "http://169.254.169.254/latest/meta-data/"))
                    tests.append(("dest", "http://127.0.0.1/"))
                if "lfi" in target:
                    tests.append(("file", "../../../../etc/passwd"))
                    tests.append(("page", "/../../../../etc/passwd"))
                if "redirect" in target:
                    tests.append(("url", "https://google.com"))
                    tests.append(("next", "//google.com"))

                for param, payload in tests:
                    if used >= max_requests: break
                    used += 1
                    
                    sep = "&" if "?" in endpoint else "?"
                    url = f"{endpoint}{sep}{param}={quote_plus(payload)}"
                    
                    try:
                        v_start = time.monotonic()
                        resp = session.get(url, timeout=timeout, allow_redirects=False)
                        duration = time.monotonic() - v_start
                        body_low = (resp.text or "").lower()
                    except RequestException as exc:
                        _emit_engine_error(logger, "exploit_validation_probe", url, exc, finding_title=item.get("title"), parameter=param)
                        continue

                    valid = False
                    evidence = ""
                    
                    # 1. SSRF Check
                    if "ssrf" in target and any(x in body_low for x in ["meta-data", "instance-id"]) and "meta-data" not in baseline_text.lower():
                        valid = True
                        evidence = "Confirmed Cloud Metadata exfiltration via SSRF (Differential check OK)."
                    
                    # 2. LFI Check
                    elif "lfi" in target and "root:x:0:0" in body_low and "root:x:0:0" not in baseline_text.lower():
                        valid = True
                        evidence = "Confirmed LFI via /etc/passwd signature (Differential check OK)."
                    
                    # 3. Open Redirect Check
                    elif "redirect" in target and resp.status_code in [301, 302, 307] and "google.com" in resp.headers.get("Location", ""):
                        valid = True
                        evidence = f"Confirmed Open Redirect to {resp.headers.get('Location')}."

                    if valid:
                        out.append({
                            "title": f"VERIFIED: {item.get('title')}",
                            "severity": item.get("severity", "high"),
                            "confidence": "high",
                            "tool_source": "redops_verifier",
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload,
                            "evidence": evidence,
                            "repro_command": f"curl -isk '{url}'",
                            "metadata": {
                                "verified": True, 
                                "baseline_duration": baseline_duration,
                                "attack_duration": duration,
                                "timing_delta": duration - baseline_duration,
                                "source_id": item.get("id_stable")
                            }
                        })
                        break # One payload hit is enough

        finally:
            session.close()

        return out
