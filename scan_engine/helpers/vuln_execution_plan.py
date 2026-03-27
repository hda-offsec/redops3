from urllib.parse import urlparse


def _as_list(value):
    if not isinstance(value, list):
        return []
    extracted = []
    for item in value:
        if isinstance(item, str) and item.strip():
            extracted.append(item.strip())
        elif isinstance(item, dict):
            # Try common keys for URL/Path (as used in DiscoveryAccumulator)
            url = item.get('url') or item.get('endpoint') or item.get('target') or item.get('path')
            if url and isinstance(url, str) and url.strip():
                extracted.append(url.strip())
    return extracted


def _matches_port(url, port):
    if not isinstance(url, str):
        return False
    port_str = str(port)
    try:
        parsed = urlparse(url)
        if parsed.port is not None:
            return str(parsed.port) == port_str
        if parsed.scheme == "https":
            return port_str == "443"
        if parsed.scheme == "http":
            return port_str == "80"
    except Exception:
        return False
    return f":{port_str}" in url


def _contains_marker(urls, markers):
    for url in urls:
        low = url.lower()
        for marker in markers:
            if marker in low:
                return True
    return False


def derive_vuln_execution_plan(results, port, profile="quick", execution_hints=None):
    """Build an additive per-port execution plan to reduce scan noise in quick runs."""
    phases = (results or {}).get("phases", {})
    enum_phase = phases.get("enum", {}) if isinstance(phases, dict) else {}

    port_key = str(port)
    quick_mode = str(profile or "").startswith("quick")
    hints = execution_hints if isinstance(execution_hints, dict) else {}
    per_port_hints = hints.get("per_port", {}) if isinstance(hints.get("per_port"), dict) else {}
    module_hints = per_port_hints.get(port_key, {}) if isinstance(per_port_hints.get(port_key), dict) else {}

    katana = enum_phase.get("katana", {}) if isinstance(enum_phase, dict) else {}
    injection_points = enum_phase.get("injection_points", {}) if isinstance(enum_phase, dict) else {}
    api = enum_phase.get("api", {}) if isinstance(enum_phase, dict) else {}

    katana_urls = _as_list(katana.get(port_key) if isinstance(katana, dict) else [])
    injection_urls = _as_list(injection_points.get(port_key) if isinstance(injection_points, dict) else [])

    discovered_api = []
    if isinstance(api, dict):
        discovered_api = _as_list(api.get("discovered_endpoints"))
        raw_eps = api.get("endpoints")
        if isinstance(raw_eps, list):
            for item in raw_eps:
                if isinstance(item, str):
                    discovered_api.append(item)
                elif isinstance(item, dict) and isinstance(item.get("url"), str):
                    discovered_api.append(item["url"])

    dalfox_hint_urls = []
    dalfox_hints = hints.get("dalfox", {}) if isinstance(hints, dict) else {}
    if isinstance(dalfox_hints, dict):
        for candidate in _as_list(dalfox_hints.get("seed_priority")):
            if _matches_port(candidate, port):
                dalfox_hint_urls.append(candidate)

    candidate_urls = sorted(set(katana_urls + injection_urls + discovered_api + dalfox_hint_urls))
    has_any_surface = len(candidate_urls) > 0
    has_graphql_signal = _contains_marker(candidate_urls, ["graphql", "graphiql"])
    has_api_signal = _contains_marker(candidate_urls, ["/api", "/v1", "/v2", "/v3", "swagger", "openapi", "graphql"])
    has_param_signal = bool(injection_urls) or any("?" in url for url in candidate_urls)
    has_js_signal = any(url.lower().split("?", 1)[0].endswith(".js") for url in candidate_urls)
    has_execution_driver = bool(module_hints)

    def entry(enabled, reason):
        return {"enabled": bool(enabled), "reason": reason}

    plan = {
        "graphql_scanner": entry(
            has_graphql_signal or not quick_mode,
            "graphql_signal_detected" if has_graphql_signal else ("full_profile_broad_coverage" if not quick_mode else "no_graphql_surface_signal"),
        ),
        "ssrf_expert": entry(
            has_api_signal or has_param_signal,
            "api_or_param_surface_detected" if (has_api_signal or has_param_signal) else "no_api_or_param_signal",
        ),
        "js_vuln_audit": entry(
            has_js_signal or (has_any_surface and not quick_mode),
            "javascript_surface_detected" if has_js_signal else ("full_profile_surface_sampling" if (has_any_surface and not quick_mode) else "no_javascript_surface_signal"),
        ),
        "dalfox": entry(
            has_param_signal,
            "injection_or_query_param_signal" if has_param_signal else "no_parameterized_surface_signal",
        ),
        "parameter_miner": entry(
            has_any_surface and (has_param_signal or has_api_signal or has_execution_driver or not quick_mode),
            "cortex_targeted_parameter_surface" if has_execution_driver else ("surface_available_for_parameter_mining" if has_any_surface else "no_discovered_surface"),
        ),
        "api_fuzzer": entry(
            bool(module_hints.get("api_fuzzer")) or (has_api_signal and (has_param_signal or not quick_mode)),
            "cortex_targeted_api_followup" if module_hints.get("api_fuzzer") else ("api_surface_detected" if has_api_signal else "no_api_surface_signal"),
        ),
        "business_logic": entry(
            bool(module_hints.get("business_logic")) or has_api_signal or has_param_signal,
            "cortex_targeted_logic_followup" if module_hints.get("business_logic") else ("api_or_param_surface_detected" if (has_api_signal or has_param_signal) else "no_logic_surface_signal"),
        ),
        "logic_assault": entry(
            bool(module_hints.get("logic_assault")) or has_api_signal or has_param_signal,
            "cortex_targeted_object_access_followup" if module_hints.get("logic_assault") else ("api_or_param_surface_detected" if (has_api_signal or has_param_signal) else "no_object_access_signal"),
        ),
        "oauth_expert": entry(
            bool(module_hints.get("oauth")),
            "cortex_targeted_oauth_followup" if module_hints.get("oauth") else "no_oauth_surface_signal",
        ),
        "jwt_expert": entry(
            bool(module_hints.get("jwt")) or has_api_signal,
            "cortex_targeted_jwt_followup" if module_hints.get("jwt") else ("api_surface_detected" if has_api_signal else "no_jwt_surface_signal"),
        ),
        "access_control": entry(
            bool(module_hints.get("access_control")) or has_api_signal,
            "cortex_targeted_authorization_followup" if module_hints.get("access_control") else ("api_surface_detected" if has_api_signal else "no_authorization_surface_signal"),
        ),
        "ssti": entry(
            bool(module_hints.get("ssti")) or has_param_signal,
            "cortex_targeted_template_followup" if module_hints.get("ssti") else ("injection_or_query_param_signal" if has_param_signal else "no_template_surface_signal"),
        ),
        "signals": {
            "candidate_url_count": len(candidate_urls),
            "has_graphql_signal": has_graphql_signal,
            "has_api_signal": has_api_signal,
            "has_param_signal": has_param_signal,
            "has_js_signal": has_js_signal,
            "has_execution_driver": has_execution_driver,
            "quick_mode": quick_mode,
        },
    }
    return plan
