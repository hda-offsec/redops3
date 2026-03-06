import re
from urllib.parse import urlparse


class PassiveIntelligenceEngine:
    """Derive passive findings from already collected scan telemetry."""

    ADMIN_HINTS = ("admin", "administrator", "signin", "login", "manage", "wp-admin")
    DEBUG_HINTS = ("debug", "trace", "console", "actuator", "profiler")
    DOC_HINTS = ("swagger", "openapi", "api-doc", "redoc", "graphql", "graphiql")
    BACKUP_HINTS = (".zip", ".tar", ".bak", ".old", "backup", "dump")
    SENSITIVE_HEADERS = ("x-powered-by", "server", "x-aspnet-version", "x-runtime")

    @staticmethod
    def _iter_endpoints(results):
        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}

        # enum.targets stores endpoint discovery per-port
        for _, endpoints in (enum.get("targets", {}) or {}).items():
            if isinstance(endpoints, list):
                for ep in endpoints:
                    if isinstance(ep, str):
                        yield ep

        # ffuf-like endpoints
        ffuf_eps = phases.get("dirbusting", {}).get("ffuf", {}).get("endpoints", [])
        if isinstance(ffuf_eps, list):
            for item in ffuf_eps:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, dict):
                    value = item.get("url") or item.get("endpoint") or item.get("path")
                    if isinstance(value, str):
                        yield value

        # API scanner outputs
        api = enum.get("api", {}) if isinstance(enum.get("api", {}), dict) else {}
        for ep in api.get("discovered_endpoints", []) or []:
            if isinstance(ep, str):
                yield ep

    @staticmethod
    def _mk_fingerprint(*parts):
        normalized = "|".join(str(p or "").strip().lower() for p in parts)
        return normalized

    @classmethod
    def derive_findings(cls, results, target):
        findings = []
        seen = set()
        endpoints = list(cls._iter_endpoints(results))

        def add(title, severity="info", confidence="medium", endpoint="", category="passive_intel", description="", evidence="", metadata=None):
            fp = cls._mk_fingerprint(title, endpoint, severity, category)
            if fp in seen:
                return
            seen.add(fp)
            findings.append({
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "tool_source": "passive_intel_engine",
                "module": "passive_intel",
                "category": category,
                "target": target,
                "endpoint": endpoint,
                "evidence": evidence or description,
                "description": description,
                "metadata": metadata or {},
            })

        for endpoint in endpoints:
            low = endpoint.lower()
            if any(h in low for h in cls.ADMIN_HINTS):
                add(
                    "Administrative Surface Exposed",
                    severity="medium",
                    confidence="medium",
                    endpoint=endpoint,
                    category="authentication_surface",
                    description="Discovered endpoint name indicates administrative/authentication functionality.",
                    metadata={"surface": "admin"},
                )
            if any(h in low for h in cls.DEBUG_HINTS):
                add(
                    "Debug Endpoint Exposed",
                    severity="medium",
                    confidence="medium",
                    endpoint=endpoint,
                    category="debug_surface",
                    description="Discovered endpoint appears to expose debugging or diagnostics capabilities.",
                    metadata={"surface": "debug"},
                )
            if any(h in low for h in cls.DOC_HINTS):
                add(
                    "API Documentation / Introspection Surface",
                    severity="medium",
                    confidence="high",
                    endpoint=endpoint,
                    category="api_exposure",
                    description="Discovered API documentation or introspection endpoint from existing enumeration telemetry.",
                    metadata={"surface": "api_docs"},
                )
            if any(h in low for h in cls.BACKUP_HINTS):
                add(
                    "Backup Artifact Exposure",
                    severity="high",
                    confidence="medium",
                    endpoint=endpoint,
                    category="backup_exposure",
                    description="Endpoint naming indicates potentially downloadable backup artifact.",
                    metadata={"surface": "backup"},
                )
            if "/internal" in low or "/private" in low:
                add(
                    "Internal API Surface Discovered",
                    severity="medium",
                    confidence="medium",
                    endpoint=endpoint,
                    category="internal_api",
                    description="Enumeration captured endpoint path suggesting internal/private API exposure.",
                    metadata={"surface": "internal_api"},
                )
            if "upload" in low:
                add(
                    "Upload Surface Discovered",
                    severity="medium",
                    confidence="medium",
                    endpoint=endpoint,
                    category="upload_surface",
                    description="Enumeration discovered a route associated with file upload functionality.",
                    metadata={"surface": "upload"},
                )

        # Methods and headers from telemetry
        enum = results.get("phases", {}).get("enum", {}) if isinstance(results, dict) else {}
        methods_data = enum.get("http_methods", {}) if isinstance(enum, dict) else {}
        for endpoint, methods in (methods_data or {}).items():
            method_list = [m.upper() for m in methods if isinstance(m, str)] if isinstance(methods, list) else []
            dangerous = [m for m in method_list if m in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
            if dangerous:
                add(
                    "Dangerous HTTP Methods Enabled",
                    severity="medium",
                    confidence="high",
                    endpoint=endpoint,
                    category="http_method_exposure",
                    description=f"Endpoint allows high-risk HTTP methods: {', '.join(sorted(set(dangerous)))}.",
                    evidence=", ".join(sorted(set(dangerous))),
                    metadata={"methods": sorted(set(method_list))},
                )

        headers_map = enum.get("headers", {}) if isinstance(enum, dict) else {}
        if isinstance(headers_map, dict):
            for port, header_data in headers_map.items():
                if not isinstance(header_data, dict):
                    continue
                leaking = []
                for name, value in header_data.items():
                    n = str(name).lower()
                    if n in cls.SENSITIVE_HEADERS:
                        if isinstance(value, dict):
                            value = value.get("value")
                        leaking.append(f"{name}: {value}")
                if leaking:
                    add(
                        "Sensitive Technology Headers Exposed",
                        severity="low",
                        confidence="medium",
                        endpoint=f"port:{port}",
                        category="sensitive_headers",
                        description="Response headers reveal underlying stack details useful for targeting.",
                        evidence="\n".join(leaking),
                        metadata={"port": str(port), "headers": leaking},
                    )

        # JS intelligence surface extraction
        js_deep = enum.get("js_deep_mining", {}) if isinstance(enum, dict) else {}
        discovered = js_deep.get("discovered_endpoints", []) if isinstance(js_deep, dict) else []
        for ep in discovered or []:
            if isinstance(ep, str):
                category = "hidden_route"
                title = "Hidden JavaScript Route Discovered"
                sev = "low"
                if "api" in ep.lower():
                    category = "internal_api"
                    title = "Internal API Route Discovered via JavaScript"
                    sev = "medium"
                add(
                    title,
                    severity=sev,
                    confidence="medium",
                    endpoint=ep,
                    category=category,
                    description="Passive JavaScript analysis extracted this route from client-side assets.",
                    metadata={"source": "js_deep_mining"},
                )

        js_findings = js_deep.get("findings", []) if isinstance(js_deep, dict) else []
        for item in js_findings or []:
            if not isinstance(item, dict):
                continue
            source = item.get("source", "")
            details = item.get("details", {}) if isinstance(item.get("details"), dict) else {}
            for secret in details.get("secrets", []) or []:
                if not isinstance(secret, dict):
                    continue
                value = secret.get("value", "")
                stype = secret.get("type", "Secret")
                if not value:
                    continue
                add(
                    f"JavaScript Secret Exposure: {stype}",
                    severity="high" if "key" in stype.lower() or "token" in stype.lower() else "medium",
                    confidence="medium",
                    endpoint=source,
                    category="secret_exposure",
                    description="JavaScript mining extracted a potential credential or secret-like token.",
                    evidence=value[:200],
                    metadata={"secret_type": stype, "source": source},
                )

        return findings
