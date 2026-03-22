import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse


DEFAULT_MAX_SUGGESTIONS = 36
DEFAULT_MAX_SUGGESTIONS_PER_PORT = 8

CATEGORY_PRIORITY = {
    "vuln": 90,
    "enum": 72,
    "intel": 56,
    "recon": 40,
}
CATEGORY_SORT = {
    "vuln": 0,
    "enum": 1,
    "intel": 2,
    "recon": 3,
}
COST_SORT = {
    "low": 0,
    "medium": 1,
    "high": 2,
}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DANGEROUS_METHODS = {"CONNECT", "DELETE", "PATCH", "PROPFIND", "PUT", "TRACE"}
API_HINTS = ("/api", "/rest", "/v1", "/v2", "/v3", "swagger", "openapi", "graphql")
AUTH_HINTS = ("/auth", "/login", "/signin", "/logout", "/session", "/sso")
OAUTH_HINTS = ("oauth", "oidc", "openid", "callback", "authorize", "/token")
GRAPHQL_HINTS = ("graphql", "graphiql", "apollo")
ADMIN_HINTS = ("admin", "dashboard", "manage", "internal", "console", "debug", "actuator")
EXPORT_HINTS = ("download", "export", "report", "archive", "backup")
STATE_CHANGE_HINTS = (
    "activate",
    "approve",
    "cancel",
    "deactivate",
    "invite",
    "publish",
    "refund",
    "restore",
    "revoke",
    "share",
)
OBJECT_REFERENCE_PARAMS = {
    "account_id",
    "id",
    "object_id",
    "owner_id",
    "tenant_id",
    "user_id",
    "uuid",
}
MASS_ASSIGNMENT_PARAMS = {
    "account_id",
    "owner",
    "owner_id",
    "permission",
    "permissions",
    "plan",
    "role",
    "roles",
    "state",
    "status",
    "tenant_id",
}
TOKEN_HINTS = ("token", "jwt", "apikey", "api_key", "bearer")
INFRA_PORTS = {6379, 11211, 2375, 27017, 9200}


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_lower(value: Any) -> str:
    return str(value or "").lower()


def _stable_unique_strings(values: Sequence[Any]) -> List[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _port_sort_key(port: Optional[str]) -> Tuple[int, Any]:
    if port is None:
        return (1, "")
    try:
        return (0, int(str(port)))
    except (TypeError, ValueError):
        return (0, str(port))


def _coerce_positive_int(value: Any, default: Optional[int]) -> Optional[int]:
    if value is None:
        return default
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return default
    return coerced if coerced > 0 else default


def _resolve_port_from_url(url: str) -> Optional[str]:
    try:
        parsed = urlparse(str(url))
    except Exception:
        return None
    if not parsed.scheme and not parsed.netloc:
        return None
    try:
        if parsed.port is not None:
            return str(parsed.port)
    except ValueError:
        return None
    if parsed.scheme == "https":
        return "443"
    if parsed.scheme == "http":
        return "80"
    return None


def _matches_port(url: str, port: str) -> bool:
    return _resolve_port_from_url(url) == str(port)


def _is_http_like(service_name: str, port: str) -> bool:
    service = _safe_lower(service_name)
    return ("http" in service) or (str(port) in {"80", "443", "8080", "8443"})


def _profile_text(profile: Any) -> str:
    if isinstance(profile, dict):
        parts = []
        for value in profile.values():
            if isinstance(value, list):
                parts.extend(str(item) for item in value)
            else:
                parts.append(str(value))
        return " ".join(parts).lower()
    return _safe_lower(profile)


def _extract_waf_name(entry: Any) -> Optional[str]:
    if isinstance(entry, dict):
        if not entry.get("has_waf"):
            return None
        name = str(entry.get("waf_name") or "").strip()
        return name or "detected WAF"
    text = str(entry or "").strip()
    return text or None


def _has_wp_signal(results: Dict[str, Any], port: str) -> bool:
    enum = _as_dict(results.get("phases", {}).get("enum"))
    vuln = _as_dict(results.get("phases", {}).get("vuln"))
    enum_tech = _as_dict(enum.get("tech"))
    vuln_wp = _as_dict(vuln.get("wordpress"))
    whatweb = _as_dict(_as_dict(enum.get("whatweb")).get("technologies"))

    port_whatweb = whatweb.get(str(port), []) if isinstance(whatweb, dict) else []
    if any("wordpress" in _safe_lower(item) for item in port_whatweb):
        return True

    if isinstance(vuln_wp, dict) and str(port) in vuln_wp:
        return True

    return "wordpress" in _safe_lower(enum_tech)


def _service_tags_by_port(results: Dict[str, Any]) -> Dict[str, List[str]]:
    service_intel = _as_list(results.get("phases", {}).get("enum", {}).get("derived", {}).get("service_intelligence"))
    mapping: Dict[str, List[str]] = {}
    for item in service_intel:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        if port is None:
            continue
        tags = item.get("tags")
        if not isinstance(tags, list):
            continue
        mapping[str(port)] = _stable_unique_strings(tags)
    return mapping


def _build_suggestion(
    *,
    suggestion_id: str,
    title: str,
    reason: str,
    confidence: int,
    category: str,
    port: Optional[str] = None,
    family: Optional[str] = None,
    reason_tags: Optional[Sequence[str]] = None,
    evidence_sources: Optional[Sequence[str]] = None,
    trigger_signals: Optional[Sequence[str]] = None,
    supporting_reasons: Optional[Sequence[str]] = None,
    estimated_cost: str = "medium",
    internal_priority: Optional[int] = None,
) -> Dict[str, Any]:
    normalized_port = str(port) if port not in (None, "") else None
    normalized_reason_tags = _stable_unique_strings(reason_tags or [])
    normalized_sources = _stable_unique_strings(evidence_sources or [])
    normalized_signals = _stable_unique_strings(trigger_signals or [])
    normalized_support = _stable_unique_strings([reason, *(supporting_reasons or [])])
    priority = internal_priority
    if priority is None:
        priority = min(
            100,
            CATEGORY_PRIORITY.get(category, 45)
            + int(confidence // 4)
            + min(len(normalized_signals), 6),
        )

    return {
        "id": suggestion_id,
        "title": title,
        "reason": reason,
        "confidence": int(confidence),
        "port": normalized_port,
        "category": category,
        "family": family or suggestion_id,
        "reason_tags": normalized_reason_tags,
        "evidence_sources": normalized_sources,
        "trigger_signals": normalized_signals,
        "supporting_reasons": normalized_support,
        "estimated_cost": estimated_cost,
        "internal_priority": int(priority),
    }


def _suggestion_rank(item: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        -int(item.get("internal_priority", 0)),
        -int(item.get("confidence", 0)),
        COST_SORT.get(str(item.get("estimated_cost") or "medium").lower(), 1),
        CATEGORY_SORT.get(str(item.get("category") or ""), 99),
        _port_sort_key(item.get("port")),
        str(item.get("title") or ""),
        str(item.get("id") or ""),
    )


def _merge_suggestions(existing: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    dominant = candidate if _suggestion_rank(candidate) < _suggestion_rank(existing) else existing
    merged = dict(dominant)

    merged["confidence"] = max(int(existing.get("confidence", 0)), int(candidate.get("confidence", 0)))
    merged["internal_priority"] = max(int(existing.get("internal_priority", 0)), int(candidate.get("internal_priority", 0)))

    existing_cost = COST_SORT.get(str(existing.get("estimated_cost") or "medium").lower(), 1)
    candidate_cost = COST_SORT.get(str(candidate.get("estimated_cost") or "medium").lower(), 1)
    merged["estimated_cost"] = existing.get("estimated_cost") if existing_cost <= candidate_cost else candidate.get("estimated_cost")

    for key in ("reason_tags", "evidence_sources", "trigger_signals", "supporting_reasons"):
        merged[key] = _stable_unique_strings([*existing.get(key, []), *candidate.get(key, [])])

    merged["family"] = str(merged.get("family") or existing.get("family") or candidate.get("family") or merged.get("id") or "")
    return merged


def _suggestion_key(item: Dict[str, Any]) -> str:
    if item.get("id"):
        return str(item["id"])
    return "::".join(
        [
            str(item.get("port") or ""),
            str(item.get("category") or ""),
            str(item.get("family") or ""),
            str(item.get("title") or ""),
        ]
    )


def _sort_suggestions(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=_suggestion_rank)


def _dedupe_suggestions(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: Dict[str, Dict[str, Any]] = {}
    for item in items:
        key = _suggestion_key(item)
        if key in deduped:
            deduped[key] = _merge_suggestions(deduped[key], item)
        else:
            deduped[key] = dict(item)
    return _sort_suggestions(list(deduped.values()))


def _apply_budget(
    items: Sequence[Dict[str, Any]],
    *,
    max_suggestions: Optional[int],
    max_suggestions_per_port: Optional[int],
) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    per_port_counts: Dict[str, int] = {}

    for item in items:
        port = item.get("port")
        if (
            port is not None
            and max_suggestions_per_port is not None
            and per_port_counts.get(str(port), 0) >= max_suggestions_per_port
        ):
            continue
        if max_suggestions is not None and len(selected) >= max_suggestions:
            break

        copied = dict(item)
        copied["rank"] = len(selected) + 1
        selected.append(copied)
        if port is not None:
            per_port_counts[str(port)] = per_port_counts.get(str(port), 0) + 1

    return selected


@lru_cache(maxsize=256)
def _analyze_surface_inventory_cached(
    port: str,
    endpoints: Tuple[str, ...],
    method_entries: Tuple[Tuple[str, Tuple[str, ...]], ...],
) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    markers = set()
    sample_endpoints = []
    interesting_params = set()
    write_methods = set()
    dangerous_methods = set()

    def remember(marker: str, sample: Optional[str] = None) -> None:
        markers.add(marker)
        if sample and sample not in sample_endpoints and len(sample_endpoints) < 8:
            sample_endpoints.append(sample)

    for endpoint in endpoints:
        low = endpoint.lower()
        parsed = urlparse(endpoint)
        path = (parsed.path or "/").lower()
        segments = [segment.lower() for segment in path.split("/") if segment]
        params = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
        params_lower = {param.lower() for param in params}

        if any(hint in low for hint in API_HINTS):
            remember("api_surface", endpoint)
        if any(hint in low for hint in GRAPHQL_HINTS):
            remember("graphql_surface", endpoint)
        if any(hint in low for hint in AUTH_HINTS):
            remember("auth_surface", endpoint)
        if any(hint in low for hint in OAUTH_HINTS):
            remember("oauth_surface", endpoint)
        if any(hint in low for hint in ADMIN_HINTS):
            remember("admin_surface", endpoint)
        if any(hint in low for hint in ("internal", "debug", "swagger", "openapi", "actuator")):
            remember("internal_surface", endpoint)
        if any(hint in low for hint in EXPORT_HINTS):
            remember("export_surface", endpoint)
        if any(hint in low for hint in TOKEN_HINTS):
            remember("token_surface", endpoint)
        if any(hint in low for hint in STATE_CHANGE_HINTS):
            remember("state_change_surface", endpoint)

        if params_lower.intersection(OBJECT_REFERENCE_PARAMS):
            remember("object_reference_surface", endpoint)
            interesting_params.update(sorted(params_lower.intersection(OBJECT_REFERENCE_PARAMS)))

        if params_lower.intersection(MASS_ASSIGNMENT_PARAMS):
            remember("mass_assignment_surface", endpoint)
            interesting_params.update(sorted(params_lower.intersection(MASS_ASSIGNMENT_PARAMS)))

        if any(re.fullmatch(r"\d+", segment) or re.fullmatch(r"[0-9a-f-]{8,}", segment) for segment in segments):
            remember("object_reference_surface", endpoint)

    for base_url, methods in method_entries:
        for method in methods:
            if method in WRITE_METHODS:
                write_methods.add(method)
                remember("write_surface", base_url)
            if method in DANGEROUS_METHODS:
                dangerous_methods.add(method)
                remember("dangerous_method_surface", base_url)

    if "write_surface" in markers and "api_surface" in markers:
        markers.add("write_api_surface")

    return (
        tuple(sorted(markers)),
        tuple(sorted(sample_endpoints)),
        tuple(sorted(interesting_params)),
        tuple(sorted(write_methods)),
        tuple(sorted(dangerous_methods)),
    )


def _analyze_surface_inventory(
    port: str,
    endpoints: Sequence[str],
    method_entries: Sequence[Tuple[str, Sequence[str]]],
    evidence_sources: Sequence[str],
) -> Dict[str, Any]:
    normalized_endpoints = tuple(sorted({str(endpoint) for endpoint in endpoints if str(endpoint).strip()}))
    normalized_methods = tuple(
        sorted(
            (
                str(base_url),
                tuple(sorted({str(method).upper() for method in methods if str(method).strip()})),
            )
            for base_url, methods in method_entries
            if str(base_url).strip()
        )
    )

    markers, samples, params, write_methods, dangerous_methods = _analyze_surface_inventory_cached(
        str(port),
        normalized_endpoints,
        normalized_methods,
    )
    return {
        "markers": list(markers),
        "samples": list(samples),
        "params": list(params),
        "write_methods": list(write_methods),
        "dangerous_methods": list(dangerous_methods),
        "evidence_sources": _stable_unique_strings(evidence_sources),
    }


def _collect_port_surface(results: Dict[str, Any], port: str) -> Dict[str, Any]:
    enum = _as_dict(results.get("phases", {}).get("enum"))
    endpoints = []
    evidence_sources = []

    def add_endpoints(values: Any, source: str, *, filter_by_port: bool = False) -> None:
        added = False
        iterable = values if isinstance(values, list) else []
        for value in iterable:
            if isinstance(value, dict):
                url = value.get("url") or value.get("endpoint")
            else:
                url = value
            if not isinstance(url, str) or not url.strip():
                continue
            if filter_by_port and not _matches_port(url, port):
                continue
            endpoints.append(url)
            added = True
        if added:
            evidence_sources.append(source)

    add_endpoints(_as_list(_as_dict(enum.get("targets")).get(str(port))), "enum.targets")
    add_endpoints(_as_list(_as_dict(enum.get("injection_points")).get(str(port))), "enum.injection_points")
    add_endpoints(_as_list(_as_dict(enum.get("katana")).get(str(port))), "enum.katana")
    add_endpoints(_as_list(_as_dict(enum.get("api")).get(str(port))), "enum.api")
    add_endpoints(_as_list(_as_dict(enum.get("api")).get("discovered_endpoints")), "enum.api.discovered_endpoints", filter_by_port=True)

    normalized = _as_dict(_as_dict(enum.get("normalized")).get(str(port)))
    add_endpoints(_as_list(normalized.get("endpoints")), "enum.normalized")

    method_entries = []
    http_methods = _as_dict(enum.get("http_methods"))
    for base_url, methods in http_methods.items():
        if not isinstance(methods, list) or not _matches_port(base_url, port):
            continue
        method_entries.append((str(base_url), methods))
    if method_entries:
        evidence_sources.append("enum.http_methods")

    return _analyze_surface_inventory(port, endpoints, method_entries, evidence_sources)


def _core_port_recommendations(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions = []
    port = context["port"]
    profile_text = context["profile_text"]
    markers = set(context["surface"]["markers"])
    evidence_sources = context["surface"]["evidence_sources"]
    service_tags = set(context["service_tags"])
    inj_points = context["injection_points"]
    script_title = context["script_title"]

    if context["is_http"] and inj_points:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-enum-param-xss-{port}",
                title=f"Prioritize parameter fuzzing and XSS follow-up on port {port}",
                reason="HTTP surface with discovered injection points indicates likely input-driven attack paths.",
                confidence=82,
                port=port,
                category="enum",
                family="parameter_surface_followup",
                reason_tags=["injection_points", "http_surface"],
                evidence_sources=[*evidence_sources, "recon.open_ports"],
                trigger_signals=["candidate_injection_surface", "http_surface"],
                estimated_cost="medium",
                internal_priority=86,
            )
        )

    if context["waf_name"]:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-intel-waf-strategy-{port}",
                title=f"Use WAF-aware payload strategy on port {port}",
                reason=f"Detected WAF ({context['waf_name']}) may block naive payloads and require tuned probing.",
                confidence=78,
                port=port,
                category="intel",
                family="waf_strategy",
                reason_tags=["waf", "payload_tuning"],
                evidence_sources=["enum.waf"],
                trigger_signals=["waf_detected"],
                estimated_cost="low",
                internal_priority=78,
            )
        )

    if context["nse_findings"]:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-nse-triage-{port}",
                title=f"Triage identified CVEs on port {port}",
                reason=f"Nmap NSE script detected potential vulnerabilities: {', '.join(context['nse_findings'][:3])}",
                confidence=95,
                port=port,
                category="vuln",
                family="nse_cve_triage",
                reason_tags=["nmap_nse", "cve_candidate"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=["potential_cve"],
                estimated_cost="low",
                internal_priority=98,
            )
        )

    if script_title and any(token in script_title.lower() for token in ("admin", "login", "dashboard", "setup")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-enum-auth-focus-{port}",
                title=f"Focus Auth/Logic Audit on port {port}",
                reason=f"Page title '{script_title}' suggests an administrative or authentication entry point.",
                confidence=88,
                port=port,
                category="enum",
                family="auth_focus",
                reason_tags=["admin_title", "auth_surface"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=["http_title_admin", "http_title_auth"],
                estimated_cost="low",
                internal_priority=89,
            )
        )

    if "api_surface" in markers or "api_surface" in service_tags:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-enum-api-followup-{port}",
                title=f"Expand API endpoint validation on port {port}",
                reason="API or GraphQL surface telemetry indicates targeted endpoint validation should be expanded before deeper exploitation.",
                confidence=76 if "api_surface" in markers else 73,
                port=port,
                category="enum",
                family="api_followup",
                reason_tags=["api_surface", "endpoint_inventory"],
                evidence_sources=[*evidence_sources, "enum.derived.service_intelligence"],
                trigger_signals=sorted({"api_surface", *service_tags.intersection({"api_surface"})}),
                estimated_cost="low",
                internal_priority=79,
            )
        )

    if any(token in profile_text for token in ("spa", "react", "angular", "vue", "svelte", "webpack")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-enum-js-mining-{port}",
                title=f"Deep Client-Side Mining on port {port}",
                reason="Modern SPA/Bundle detected. Injected Deep JS Mining Expert to recover hidden routes and internal endpoints.",
                confidence=90,
                port=port,
                category="enum",
                family="js_mining",
                reason_tags=["spa", "client_bundle"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["spa", "client_bundle"],
                estimated_cost="medium",
                internal_priority=91,
            )
        )

    if "graphql_surface" in markers or "graphql" in profile_text or "apollo" in profile_text:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-graphql-{port}",
                title=f"Intense GraphQL Probing on port {port}",
                reason="GraphQL interface detected. Requires introspection audit and object injection testing.",
                confidence=85,
                port=port,
                category="vuln",
                family="graphql_probe",
                reason_tags=["graphql", "schema_surface"],
                evidence_sources=[*evidence_sources, "enum.attack_profile"],
                trigger_signals=sorted({"graphql_surface"} | ({"graphql_profile"} if "graphql" in profile_text or "apollo" in profile_text else set())),
                estimated_cost="medium",
                internal_priority=87,
            )
        )

    if _has_wp_signal(context["results"], port):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-wordpress-{port}",
                title=f"Prioritize WordPress checks on port {port}",
                reason="WordPress technology signals detected and existing WP module support is available.",
                confidence=80,
                port=port,
                category="vuln",
                family="wordpress_followup",
                reason_tags=["wordpress", "cms"],
                evidence_sources=["enum.whatweb", "vuln.wordpress", "enum.tech"],
                trigger_signals=["wordpress"],
                estimated_cost="medium",
                internal_priority=80,
            )
        )

    if "postgrey_possible" in service_tags:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-intel-smtp-postgrey-{port}",
                title=f"Validate SMTP banner behavior on port {port}",
                reason="Service intelligence indicates possible Postgrey filtering; perform controlled SMTP/banner checks.",
                confidence=70,
                port=port,
                category="intel",
                family="smtp_postgrey",
                reason_tags=["mail_surface", "postgrey_possible"],
                evidence_sources=["enum.derived.service_intelligence"],
                trigger_signals=["postgrey_possible"],
                estimated_cost="low",
                internal_priority=66,
            )
        )

    return suggestions


def _stack_port_recommendations(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions = []
    port = context["port"]
    profile_text = context["profile_text"]
    evidence_sources = context["surface"]["evidence_sources"]
    katana_results = context["katana_results"]
    markers = set(context["surface"]["markers"])

    if any(token in profile_text for token in ("spring", "actuator", "javamelody")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-spring-actuator-{port}",
                title=f"Spring Actuator Audit on port {port}",
                reason="Spring-like components or Actuators detected. High risk of info-leaks or RCE via env/heapdump.",
                confidence=92,
                port=port,
                category="vuln",
                family="spring_actuator",
                reason_tags=["spring", "actuator"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["spring"],
                estimated_cost="medium",
                internal_priority=93,
            )
        )

    if any(token in profile_text for token in ("firebase", "firestore", "google-services")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-firebase-{port}",
                title=f"Firebase Database Audit on port {port}",
                reason="Firebase SDK or indicators detected. Check for misconfigured (publicly readable) database rules.",
                confidence=95,
                port=port,
                category="vuln",
                family="firebase_audit",
                reason_tags=["firebase", "database_rules"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["firebase"],
                estimated_cost="low",
                internal_priority=95,
            )
        )

    if any(token in profile_text for token in ("docker-api", "containerd", "kubernetes")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-container-exposure-{port}",
                title=f"Container API Exposure Check on port {port}",
                reason="Container management signatures detected. High critical risk of full host takeover.",
                confidence=98,
                port=port,
                category="vuln",
                family="container_exposure",
                reason_tags=["container_api", "admin_surface"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["container_api"],
                estimated_cost="low",
                internal_priority=99,
            )
        )

    if "eyj" in profile_text or "spa" in profile_text or "auth" in profile_text or "token_surface" in markers:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-jwt-{port}",
                title=f"JWT Security Audit on port {port}",
                reason="Tokens or modern JS architecture detected. Auditing for algorithm confusion, none-alg, and kid injection.",
                confidence=88,
                port=port,
                category="vuln",
                family="jwt_audit",
                reason_tags=["token_surface", "auth_surface"],
                evidence_sources=["enum.attack_profile", *evidence_sources],
                trigger_signals=sorted({"token_surface"} if "token_surface" in markers else {"auth_profile"}),
                estimated_cost="medium",
                internal_priority=88,
            )
        )

    if any(token in profile_text for token in ("coldfusion", "aem", "adobe", "telerik")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-enterprise-{port}",
                title=f"Enterprise Stack Audit on port {port}",
                reason="Found signatures of high-value enterprise tech (AEM/ColdFusion). Initiating specialized exploit probes.",
                confidence=95,
                port=port,
                category="vuln",
                family="enterprise_stack",
                reason_tags=["enterprise_stack"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["enterprise_stack"],
                estimated_cost="medium",
                internal_priority=95,
            )
        )

    if any(("package.json" in str(url) or "requirements.txt" in str(url)) for url in katana_results):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-dependency-{port}",
                title=f"Supply Chain Security Check on port {port}",
                reason="Dependency manifest files exposed. Auditing for Dependency Confusion and malicious package hijacking.",
                confidence=90,
                port=port,
                category="vuln",
                family="dependency_exposure",
                reason_tags=["dependency_manifest", "supply_chain"],
                evidence_sources=["enum.katana"],
                trigger_signals=["dependency_manifest"],
                estimated_cost="medium",
                internal_priority=90,
            )
        )

    if any(token in profile_text for token in ("mongodb", "nodejs", "express", "mongoose", "nosql")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-nosql-{port}",
                title=f"NoSQL Injection Audit on port {port}",
                reason="Node.js/NoSQL stack identified. Probing for MongoDB operator injection and login bypass.",
                confidence=88,
                port=port,
                category="vuln",
                family="nosql_audit",
                reason_tags=["nosql", "node_stack"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["nosql"],
                estimated_cost="medium",
                internal_priority=86,
            )
        )

    if any(token in profile_text for token in ("cloudflare", "varnish", "nginx", "akamai", "fastly")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-cache-{port}",
                title=f"Web Cache Integrity Audit on port {port}",
                reason="CDN or advanced reverse proxy detected. Auditing for Cache Poisoning and Deception.",
                confidence=80,
                port=port,
                category="vuln",
                family="cache_integrity",
                reason_tags=["reverse_proxy", "cache_layer"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["cache_layer"],
                estimated_cost="medium",
                internal_priority=76,
            )
        )

    if any(token in profile_text for token in ("java", "spring", "struts", "hibernate", "rmi")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-java-{port}",
                title="Java Deserialization & RCE Audit",
                reason="Java-based tech stack detected. Probing for insecure deserialization gadget chains and Spring4Shell.",
                confidence=95,
                port=port,
                category="vuln",
                family="java_rce",
                reason_tags=["java_stack", "deserialization"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["java_stack"],
                estimated_cost="high",
                internal_priority=94,
            )
        )

    if any(token in profile_text for token in ("angular", "vue", "react", "handlebars", "moustache")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-csti-{port}",
                title="CSTI framework Audit",
                reason="Modern JS framework detected. Auditing for Client-Side Template Injection via math evaluation.",
                confidence=82,
                port=port,
                category="vuln",
                family="csti_audit",
                reason_tags=["client_template", "spa"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["client_template"],
                estimated_cost="medium",
                internal_priority=73,
            )
        )

    if "api_surface" in markers or any(token in profile_text for token in ("api", "v1", "v2", "json")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-shadow-{port}",
                title="API Shadow Hunter Audit",
                reason="API surface detected. Searching for undocumented swagger/openapi definitions and shadow endpoints.",
                confidence=88,
                port=port,
                category="vuln",
                family="api_shadow",
                reason_tags=["api_surface", "shadow_api"],
                evidence_sources=[*evidence_sources, "enum.attack_profile"],
                trigger_signals=sorted({"api_surface"} | ({"api_profile"} if "api" in profile_text or "json" in profile_text else set())),
                estimated_cost="medium",
                internal_priority=78,
            )
        )

    if any(token in profile_text for token in (".pdf", ".docx", ".xlsx", "media", "doc")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-forensics-meta-{port}",
                title="Digital Forensics: Doc Metadata Exfil",
                reason="Document assets detected. Extracting internal environment data and PII from metadata.",
                confidence=75,
                port=port,
                category="vuln",
                family="doc_metadata",
                reason_tags=["document_surface", "metadata"],
                evidence_sources=["enum.attack_profile"],
                trigger_signals=["document_surface"],
                estimated_cost="low",
                internal_priority=62,
            )
        )

    return suggestions


def _surface_port_recommendations(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions = []
    port = context["port"]
    profile_text = context["profile_text"]
    surface = context["surface"]
    markers = set(surface["markers"])
    evidence_sources = surface["evidence_sources"]
    trigger_signals = sorted(markers)

    if context["is_http"] and {"api_surface", "auth_surface", "admin_surface"}.intersection(markers) and "object_reference_surface" in markers:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-idor-{port}",
                title=f"Object Access / BOLA Audit on port {port}",
                reason="Object-reference routes or parameters were discovered on an authenticated/API surface. Validate authorization on cross-object access paths.",
                confidence=89,
                port=port,
                category="vuln",
                family="object_access_authorization",
                reason_tags=["idor", "bola", "authorization"],
                evidence_sources=evidence_sources,
                trigger_signals=[signal for signal in trigger_signals if signal in {"api_surface", "auth_surface", "admin_surface", "object_reference_surface"}],
                estimated_cost="medium",
                internal_priority=89,
            )
        )

    if context["is_http"] and {"admin_surface", "internal_surface"}.intersection(markers):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-admin-internal-{port}",
                title=f"Validate Admin/Internal Route Authorization on port {port}",
                reason="Administrative or internal routes were observed in telemetry. Prioritize authorization and environment segregation checks.",
                confidence=86,
                port=port,
                category="vuln",
                family="admin_internal_authorization",
                reason_tags=["admin_surface", "internal_surface", "authorization"],
                evidence_sources=evidence_sources,
                trigger_signals=[signal for signal in trigger_signals if signal in {"admin_surface", "internal_surface", "auth_surface"}],
                estimated_cost="low",
                internal_priority=86,
            )
        )

    if context["is_http"] and "export_surface" in markers:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-export-{port}",
                title=f"Export / Download Authorization Audit on port {port}",
                reason="Export, download, or report routes were identified. Validate bulk data access control, tenant boundaries, and unsafe direct object access.",
                confidence=84,
                port=port,
                category="vuln",
                family="export_authorization",
                reason_tags=["export_surface", "data_exposure"],
                evidence_sources=evidence_sources,
                trigger_signals=[signal for signal in trigger_signals if signal in {"export_surface", "object_reference_surface", "admin_surface"}],
                estimated_cost="medium",
                internal_priority=84,
            )
        )

    if context["is_http"] and (
        "state_change_surface" in markers
        or ("write_surface" in markers and {"api_surface", "auth_surface", "admin_surface"}.intersection(markers))
    ):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-state-change-{port}",
                title=f"State-Changing Workflow Audit on port {port}",
                reason="State-transition or write-capable routes were discovered on a business/API surface. Review workflow integrity, replay safety, and authorization gates.",
                confidence=83,
                port=port,
                category="vuln",
                family="state_change_logic",
                reason_tags=["business_logic", "state_change"],
                evidence_sources=evidence_sources,
                trigger_signals=[signal for signal in trigger_signals if signal in {"state_change_surface", "write_surface", "api_surface", "auth_surface", "admin_surface"}],
                estimated_cost="medium",
                internal_priority=83,
            )
        )

    if "api_surface" in markers or any(token in profile_text for token in ("api", "json")):
        reason_tags = ["api_surface", "business_logic"]
        if "mass_assignment_surface" in markers or "write_surface" in markers:
            reason_tags.append("mass_assignment")
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-logic-{port}",
                title="Business Logic & Mass Assignment Audit",
                reason="API-heavy surface detected. Testing for auto-binding flaws, state changes, and parameter pollution on object mutation paths.",
                confidence=85,
                port=port,
                category="vuln",
                family="business_logic_mass_assignment",
                reason_tags=reason_tags,
                evidence_sources=[*evidence_sources, "enum.attack_profile"],
                trigger_signals=[signal for signal in trigger_signals if signal in {"api_surface", "mass_assignment_surface", "write_surface", "state_change_surface"}],
                estimated_cost="medium",
                internal_priority=85,
            )
        )

    if "oauth_surface" in markers or any(token in profile_text for token in ("oauth", "openid", "callback", "sso", "auth0")):
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-oauth-{port}",
                title=f"OAuth/OIDC Security Audit on port {port}",
                reason="Authentication flow signatures detected. Auditing for Redirect URI bypass, token leakage, and state-CSRF flaws.",
                confidence=92,
                port=port,
                category="vuln",
                family="oauth_oidc",
                reason_tags=["oauth", "oidc", "auth_flow"],
                evidence_sources=[*evidence_sources, "enum.attack_profile"],
                trigger_signals=[signal for signal in trigger_signals if signal in {"oauth_surface", "auth_surface", "token_surface"}],
                estimated_cost="medium",
                internal_priority=92,
            )
        )

    return suggestions


def _generic_http_recommendations(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions = []
    port = context["port"]
    inj_points = context["injection_points"]

    if context["is_http"]:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-smuggling-{port}",
                title=f"HTTP Smuggling Audit on port {port}",
                reason="Perform desync probes to detect CL.TE/TE.CL vulnerabilities on this HTTP surface.",
                confidence=75,
                port=port,
                category="vuln",
                family="http_smuggling",
                reason_tags=["http_surface", "request_smuggling"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=["http_surface"],
                estimated_cost="high",
                internal_priority=72,
            )
        )
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-vhost-{port}",
                title=f"Virtual Host Brute-Force on port {port}",
                reason="Probe for unmapped subdomains or internal environments via Host header fuzzing.",
                confidence=70,
                port=port,
                category="vuln",
                family="vhost_bruteforce",
                reason_tags=["http_surface", "host_header"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=["http_surface"],
                estimated_cost="medium",
                internal_priority=70,
            )
        )
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-waf-fingerprint-{port}",
                title="WAF & IPS Behavioral Fingerprinting",
                reason="Establishing active security layer signatures to adapt offensive payloads.",
                confidence=90,
                port=port,
                category="vuln",
                family="waf_fingerprint",
                reason_tags=["http_surface", "defense_fingerprint"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=["http_surface"],
                estimated_cost="low",
                internal_priority=60,
            )
        )

    if inj_points:
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-ssti-{port}",
                title=f"Polyglot SSTI Probe on port {port}",
                reason="Widespread parameter reflection observed. Running engine-specific template injection probes.",
                confidence=84,
                port=port,
                category="vuln",
                family="ssti_probe",
                reason_tags=["injection_points", "template_injection"],
                evidence_sources=["enum.injection_points"],
                trigger_signals=["candidate_injection_surface"],
                estimated_cost="high",
                internal_priority=82,
            )
        )

    if port == "80" or context["service"].lower() == "http":
        suggestions.append(
            _build_suggestion(
                suggestion_id=f"cortex-vuln-h2c-{port}",
                title="H2C Smuggling & Tunneling Audit",
                reason="Cleartext HTTP service detected. Auditing for HTTP/2 upgrade tunnel misconfigurations.",
                confidence=78,
                port=port,
                category="vuln",
                family="h2c_smuggling",
                reason_tags=["cleartext_http", "h2c"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=["http_surface"],
                estimated_cost="medium",
                internal_priority=71,
            )
        )

    return suggestions


def _global_recommendations(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions = []
    phases = _as_dict(results.get("phases"))
    vuln = _as_dict(phases.get("vuln"))
    recon_ports = _as_list(_as_dict(phases.get("recon")).get("open_ports"))

    if _as_list(_as_dict(phases.get("osint")).get("historic_urls")):
        suggestions.append(
            _build_suggestion(
                suggestion_id="cortex-enum-historic-validation",
                title="Validate Historic Attack Surface",
                reason="Discovery found legacy URLs in archive.org. High potential for forgotten/vulnerable endpoints.",
                confidence=85,
                port=None,
                category="recon",
                family="historic_surface",
                reason_tags=["historic_urls", "legacy_surface"],
                evidence_sources=["osint.historic_urls"],
                trigger_signals=["historic_surface"],
                estimated_cost="low",
                internal_priority=85,
            )
        )

    nuclei_findings = _as_list(_as_dict(vuln.get("nuclei")).get("findings"))
    if nuclei_findings:
        suggestions.append(
            _build_suggestion(
                suggestion_id="cortex-vuln-triage-nuclei",
                title="Manually triage high-value nuclei findings",
                reason=f"{len(nuclei_findings)} nuclei finding(s) require validation and exploitation context.",
                confidence=88,
                port=None,
                category="vuln",
                family="nuclei_triage",
                reason_tags=["nuclei", "validation"],
                evidence_sources=["vuln.nuclei"],
                trigger_signals=["nuclei_findings"],
                estimated_cost="low",
                internal_priority=88,
            )
        )

    open_infra_ports = sorted(
        {
            int(port_info.get("port"))
            for port_info in recon_ports
            if isinstance(port_info, dict) and port_info.get("port") is not None
        }
        .intersection(INFRA_PORTS)
    )
    if open_infra_ports:
        suggestions.append(
            _build_suggestion(
                suggestion_id="cortex-vuln-infra-exposure",
                title="Infrastructure Exposure Audit",
                reason=f"Identified open administrative or data-layer ports ({', '.join(str(port) for port in open_infra_ports)}). Probing for unauthenticated access is high-value.",
                confidence=98,
                port=None,
                category="vuln",
                family="infra_exposure",
                reason_tags=["infra_exposure", "admin_port"],
                evidence_sources=["recon.open_ports"],
                trigger_signals=[f"open_port_{port}" for port in open_infra_ports],
                estimated_cost="low",
                internal_priority=97,
            )
        )

    return suggestions


def suggest_actions(
    results: Dict[str, Any],
    *,
    max_suggestions: Optional[int] = None,
    max_suggestions_per_port: Optional[int] = None,
) -> List[Dict[str, Any]]:
    phases = _as_dict(results.get("phases"))
    recon_ports = _as_list(_as_dict(phases.get("recon")).get("open_ports"))
    enum = _as_dict(phases.get("enum"))

    limits = _as_dict(_as_dict(enum.get("derived")).get("cortex_limits"))
    resolved_max_suggestions = _coerce_positive_int(
        max_suggestions if max_suggestions is not None else limits.get("max_suggestions"),
        DEFAULT_MAX_SUGGESTIONS,
    )
    resolved_per_port_limit = _coerce_positive_int(
        max_suggestions_per_port if max_suggestions_per_port is not None else limits.get("max_suggestions_per_port"),
        DEFAULT_MAX_SUGGESTIONS_PER_PORT,
    )

    waf_map = _as_dict(enum.get("waf"))
    inj_map = _as_dict(enum.get("injection_points"))
    profile_map = _as_dict(enum.get("attack_profile"))
    katana_map = _as_dict(enum.get("katana"))
    service_tags_by_port = _service_tags_by_port(results)

    raw_suggestions: List[Dict[str, Any]] = []
    sorted_ports = sorted(
        [port_info for port_info in recon_ports if isinstance(port_info, dict) and port_info.get("port") is not None],
        key=lambda item: (
            _port_sort_key(str(item.get("port"))),
            _safe_lower(item.get("service") or item.get("service_name") or ""),
        ),
    )

    for port_info in sorted_ports:
        port = str(port_info.get("port"))
        service = str(port_info.get("service", port_info.get("service_name", "")))
        script_results = _as_dict(port_info.get("script_results"))
        context = {
            "results": results,
            "port": port,
            "service": service,
            "is_http": _is_http_like(service, port),
            "waf_name": _extract_waf_name(waf_map.get(port)),
            "injection_points": _as_list(inj_map.get(port)),
            "profile_text": _profile_text(profile_map.get(port, {})),
            "katana_results": _as_list(katana_map.get(port)),
            "surface": _collect_port_surface(results, port),
            "service_tags": service_tags_by_port.get(port, []),
            "nse_findings": [str(item) for item in _as_list(port_info.get("nse_findings")) if str(item).strip()],
            "script_title": script_results.get("http-title") if isinstance(script_results.get("http-title"), str) else "",
        }

        raw_suggestions.extend(_core_port_recommendations(context))
        raw_suggestions.extend(_stack_port_recommendations(context))
        raw_suggestions.extend(_surface_port_recommendations(context))
        raw_suggestions.extend(_generic_http_recommendations(context))

    raw_suggestions.extend(_global_recommendations(results))

    deduped = _dedupe_suggestions(raw_suggestions)
    return _apply_budget(
        deduped,
        max_suggestions=resolved_max_suggestions,
        max_suggestions_per_port=resolved_per_port_limit,
    )
