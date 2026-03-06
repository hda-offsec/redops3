import re
from urllib.parse import urlparse


class AssetDiscoveryEngine:
    """Extract asset intelligence from existing telemetry only."""

    CLOUD_PATTERNS = (
        "amazonaws.com",
        "cloudfront.net",
        "storage.googleapis.com",
        "azurewebsites.net",
        "digitaloceanspaces.com",
        "blob.core.windows.net",
    )

    @staticmethod
    def _iter_strings(payload):
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(key, str):
                    yield key
                yield from AssetDiscoveryEngine._iter_strings(value)
        elif isinstance(payload, list):
            for value in payload:
                yield from AssetDiscoveryEngine._iter_strings(value)
        elif isinstance(payload, str):
            yield payload

    @staticmethod
    def _extract_hosts(blob):
        if not isinstance(blob, str):
            return []
        hosts = []
        for token in re.findall(r"https?://[A-Za-z0-9._:-]+", blob):
            parsed = urlparse(token)
            if parsed.hostname:
                hosts.append(parsed.hostname.lower())
        for host in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", blob):
            hosts.append(host.lower())
        return hosts

    @staticmethod
    def _classify_asset(host, target):
        host = host.lower()
        target_l = (target or "").lower()
        if any(pat in host for pat in AssetDiscoveryEngine.CLOUD_PATTERNS):
            return "cloud_endpoint", "high"
        if host.startswith("api.") or ".api." in host:
            return "api_host", "high"
        if host.startswith("cdn.") or "cdn" in host:
            return "cdn_host", "medium"
        if host.endswith(".local") or ".internal" in host or ".corp" in host:
            return "internal_domain", "medium"
        if target_l and host.endswith(f".{target_l}"):
            return "subdomain", "high"
        return "external_domain", "low"

    @classmethod
    def derive_findings(cls, results, target):
        findings = []
        seen = set()

        def add(category, discovered_asset, source, confidence, evidence, finding_category="asset_discovery", severity="info"):
            if not discovered_asset or not evidence:
                return
            fp = f"{finding_category}|{discovered_asset}|{source}"
            if fp in seen:
                return
            seen.add(fp)
            findings.append({
                "title": f"Discovered Asset: {discovered_asset}",
                "severity": severity,
                "confidence": confidence,
                "tool_source": "asset_discovery_engine",
                "module": "passive_intel",
                "category": finding_category,
                "target": target,
                "endpoint": discovered_asset,
                "evidence": evidence,
                "description": f"Asset discovery extracted {discovered_asset} from {source} telemetry.",
                "metadata": {
                    "target": target,
                    "discovered_asset": discovered_asset,
                    "source": source,
                    "confidence": confidence,
                    "asset_type": category,
                },
            })

        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}

        dns_subdomains = phases.get("dns", {}).get("subdomains", [])
        for sub in dns_subdomains if isinstance(dns_subdomains, list) else []:
            if isinstance(sub, str):
                asset_type, conf = cls._classify_asset(sub, target)
                add(asset_type, sub.lower(), "dns_records", conf, sub)

        api_eps = enum.get("api", {}).get("discovered_endpoints", []) if isinstance(enum.get("api", {}), dict) else []
        for ep in api_eps if isinstance(api_eps, list) else []:
            if not isinstance(ep, str):
                continue
            for host in cls._extract_hosts(ep):
                asset_type, conf = cls._classify_asset(host, target)
                add(asset_type, host, "api_endpoints", conf, ep)

        endpoint_sources = []
        enum_targets = enum.get("targets", {}) if isinstance(enum, dict) else {}
        if isinstance(enum_targets, dict):
            for _, endpoints in enum_targets.items():
                if isinstance(endpoints, list):
                    endpoint_sources.extend([x for x in endpoints if isinstance(x, str)])

        ffuf_eps = phases.get("dirbusting", {}).get("ffuf", {}).get("endpoints", [])
        if isinstance(ffuf_eps, list):
            for item in ffuf_eps:
                if isinstance(item, str):
                    endpoint_sources.append(item)
                elif isinstance(item, dict):
                    val = item.get("url") or item.get("endpoint") or item.get("path")
                    if isinstance(val, str):
                        endpoint_sources.append(val)

        js_deep = enum.get("js_deep_mining", {}) if isinstance(enum, dict) else {}
        js_eps = js_deep.get("discovered_endpoints", []) if isinstance(js_deep, dict) else []
        if isinstance(js_eps, list):
            endpoint_sources.extend([x for x in js_eps if isinstance(x, str)])

        for source_blob in endpoint_sources:
            for host in cls._extract_hosts(source_blob):
                asset_type, conf = cls._classify_asset(host, target)
                add(asset_type, host, "links_discovered", conf, source_blob)

        headers_map = enum.get("headers", {}) if isinstance(enum, dict) else {}
        if isinstance(headers_map, dict):
            for port, header_data in headers_map.items():
                if not isinstance(header_data, dict):
                    continue
                for header_name, header_value in header_data.items():
                    raw_value = header_value.get("value") if isinstance(header_value, dict) else header_value
                    text = f"{header_name}: {raw_value}"
                    for host in cls._extract_hosts(str(text)):
                        asset_type, conf = cls._classify_asset(host, target)
                        add(asset_type, host, "http_headers", conf, text)

        for blob in cls._iter_strings(results):
            for host in cls._extract_hosts(blob):
                asset_type, conf = cls._classify_asset(host, target)
                source = "scan_telemetry"
                finding_category = "cloud_asset" if any(pat in host for pat in cls.CLOUD_PATTERNS) else "asset_discovery"
                severity = "medium" if finding_category == "cloud_asset" else "info"
                add(asset_type, host, source, conf, blob[:300], finding_category=finding_category, severity=severity)

        return findings


class SecretsIntelligenceEngine:
    """Evidence-driven secret pattern detection from collected scan telemetry."""

    SECRET_PATTERNS = [
        ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
        ("slack_token", re.compile(r"\bxoxp-[0-9A-Za-z-]{20,}\b")),
        ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("oauth_token", re.compile(r"\boa(?:uth)?[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9._-]{16,}")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        ("credential_pair", re.compile(r"\b(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE)),
    ]

    @staticmethod
    def _iter_strings(payload):
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(key, str):
                    yield key
                yield from SecretsIntelligenceEngine._iter_strings(value)
        elif isinstance(payload, list):
            for value in payload:
                yield from SecretsIntelligenceEngine._iter_strings(value)
        elif isinstance(payload, str):
            yield payload

    @classmethod
    def derive_findings(cls, results, target):
        findings = []
        seen = set()

        for blob in cls._iter_strings(results):
            for secret_type, pattern in cls.SECRET_PATTERNS:
                for match in pattern.finditer(blob):
                    evidence = match.group(0)[:220]
                    fp = f"{secret_type}|{evidence}|{target}"
                    if fp in seen:
                        continue
                    seen.add(fp)
                    findings.append({
                        "title": f"Potential Secret Exposure: {secret_type}",
                        "severity": "high" if secret_type in {"private_key", "aws_access_key_id", "github_token"} else "medium",
                        "confidence": "high" if secret_type in {"private_key", "aws_access_key_id", "gcp_api_key", "github_token"} else "medium",
                        "tool_source": "secrets_intelligence_engine",
                        "module": "passive_intel",
                        "category": "secret_exposure",
                        "target": target,
                        "endpoint": "",
                        "evidence": evidence,
                        "description": f"Secret intelligence matched {secret_type} pattern in collected telemetry.",
                        "metadata": {
                            "target": target,
                            "secret_type": secret_type,
                            "source": "scan_telemetry",
                            "confidence": "high" if secret_type in {"private_key", "aws_access_key_id", "gcp_api_key", "github_token"} else "medium",
                        },
                    })

        return findings


class PassiveIntelligenceEngine:
    """Derive passive findings from already collected scan telemetry."""

    ADMIN_HINTS = ("admin", "administrator", "signin", "login", "manage", "wp-admin")
    DEBUG_HINTS = ("debug", "trace", "console", "actuator", "profiler", "/test", "/dev")
    DOC_HINTS = ("swagger", "openapi", "api-doc", "redoc", "graphql", "graphiql")
    BACKUP_HINTS = (".zip", ".tar", ".bak", ".old", "backup", "dump")
    SENSITIVE_HEADERS = ("x-powered-by", "server", "x-aspnet-version", "x-runtime")
    API_DOC_PATTERNS = ("/swagger", "/swagger-ui", "/api-docs", "/graphql", "/openapi.json")
    AUTH_HINTS = ("/login", "/signin", "/auth", "/token", "/oauth", "/session")
    PROTOTYPE_HINTS = ("__proto__", "constructor.prototype", "object.setprototypeof")
    SSRF_PARAM_HINTS = ("url", "uri", "target", "dest", "redirect")
    CLOUD_REF_HINTS = ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net")
    INTERNAL_HOST_HINTS = ("internal", ".cluster.local", ".svc", ".corp")
    SENSITIVE_FILE_HINTS = ("/.env", "/.git/config", "/backup.zip", "/db.sql", "/.git/head", "/.git/logs")

    @staticmethod
    def _iter_telemetry_strings(payload):
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(key, str):
                    yield key
                yield from PassiveIntelligenceEngine._iter_telemetry_strings(value)
        elif isinstance(payload, list):
            for value in payload:
                yield from PassiveIntelligenceEngine._iter_telemetry_strings(value)
        elif isinstance(payload, str):
            yield payload

    @staticmethod
    def _looks_like_jwt(token):
        if not isinstance(token, str):
            return False
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token.split(" ", 1)[1].strip()
        return bool(re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", token))

    @staticmethod
    def _iter_endpoints(results):
        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}
        for _, endpoints in (enum.get("targets", {}) or {}).items():
            if isinstance(endpoints, list):
                for ep in endpoints:
                    if isinstance(ep, str):
                        yield ep
        ffuf_eps = phases.get("dirbusting", {}).get("ffuf", {}).get("endpoints", [])
        if isinstance(ffuf_eps, list):
            for item in ffuf_eps:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, dict):
                    value = item.get("url") or item.get("endpoint") or item.get("path")
                    if isinstance(value, str):
                        yield value
        api = enum.get("api", {}) if isinstance(enum.get("api", {}), dict) else {}
        for ep in api.get("discovered_endpoints", []) or []:
            if isinstance(ep, str):
                yield ep

    @staticmethod
    def _mk_fingerprint(*parts):
        return "|".join(str(p or "").strip().lower() for p in parts)

    @classmethod
    def derive_findings(cls, results, target):
        findings = []
        seen = set()
        endpoints = list(cls._iter_endpoints(results))

        def add(title, severity="info", confidence="medium", endpoint="", category="passive_intel", description="", evidence="", metadata=None, source="passive_telemetry"):
            fp = cls._mk_fingerprint(title, endpoint, severity, category)
            if fp in seen:
                return
            if not (evidence or description):
                return
            seen.add(fp)
            md = metadata or {}
            md.setdefault("source", source)
            md.setdefault("confidence", confidence)
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
                "metadata": md,
            })

        for endpoint in endpoints:
            low = endpoint.lower()
            if any(h in low for h in cls.ADMIN_HINTS):
                add("Administrative Surface Exposed", "medium", "medium", endpoint, "authentication_surface", "Discovered endpoint name indicates administrative/authentication functionality.", endpoint)
            if any(h in low for h in cls.DEBUG_HINTS):
                add("Debug Endpoint Exposed", "medium", "medium", endpoint, "debug_surface", "Discovered endpoint appears to expose debugging or diagnostics capabilities.", endpoint)
            if any(h in low for h in cls.DOC_HINTS):
                add("API Documentation / Introspection Surface", "medium", "high", endpoint, "api_exposure", "Discovered API documentation or introspection endpoint from existing enumeration telemetry.", endpoint)
            if any(pat in low for pat in cls.API_DOC_PATTERNS):
                add("Documented API Surface Exposed", "low", "high", endpoint, "api_surface", "Path pattern maps to API documentation or schema endpoint.", endpoint)
            if any(h in low for h in cls.AUTH_HINTS):
                add("Authentication Surface Exposed", "medium", "medium", endpoint, "auth_surface", "Authentication-related endpoint discovered in existing telemetry.", endpoint)
            if any(h in low for h in cls.BACKUP_HINTS):
                add("Backup Artifact Surface", "high", "medium", endpoint, "backup_surface", "Backup-style endpoint or artifact reference discovered from telemetry.", endpoint)
            if any(h in low for h in cls.SENSITIVE_FILE_HINTS):
                severity = "high" if ".git/" in low else "medium"
                category = "git_exposure" if ".git/" in low else "sensitive_file_exposure"
                add("Exposed Git Repository Path Detected" if category == "git_exposure" else "Sensitive File Path Discovered", severity, "high", endpoint, category, "Telemetry references sensitive file path likely accessible to attackers.", endpoint)

        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}

        inj_points = enum.get("injection_points", {}) if isinstance(enum, dict) else {}
        for port, params in inj_points.items():
            for param in params if isinstance(params, list) else []:
                if isinstance(param, str) and any(h in param.lower() for h in cls.SSRF_PARAM_HINTS):
                    add("Potential SSRF Input Surface", "info", "medium", f"port:{port}", "ssrf_surface", "Discovered parameter indicates user-controlled remote destination semantics.", param, {"parameter": param, "port": str(port)})

        methods_data = enum.get("http_methods", {}) if isinstance(enum, dict) else {}
        for endpoint, methods in (methods_data or {}).items():
            method_list = [m.upper() for m in methods if isinstance(m, str)] if isinstance(methods, list) else []
            dangerous = [m for m in method_list if m in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
            if dangerous:
                add("Dangerous HTTP Methods Enabled", "medium", "high", endpoint, "http_method_exposure", f"Endpoint allows high-risk HTTP methods: {', '.join(sorted(set(dangerous)))}.", ", ".join(sorted(set(dangerous))), {"methods": sorted(set(method_list))})

        headers_map = enum.get("headers", {}) if isinstance(enum, dict) else {}
        if isinstance(headers_map, dict):
            for port, header_data in headers_map.items():
                if not isinstance(header_data, dict):
                    continue
                leaking = []
                allow_origin = None
                allow_credentials = None
                auth_header = None
                cookie_header = None
                for name, value in header_data.items():
                    raw = value.get("value") if isinstance(value, dict) else value
                    n = str(name).lower()
                    v = str(raw) if raw is not None else ""
                    if n in cls.SENSITIVE_HEADERS:
                        leaking.append(f"{name}: {v}")
                    if n == "access-control-allow-origin":
                        allow_origin = v.strip()
                    elif n == "access-control-allow-credentials":
                        allow_credentials = v.strip().lower()
                    elif n == "authorization":
                        auth_header = v
                    elif n == "set-cookie":
                        cookie_header = v
                if leaking:
                    add("Sensitive Technology Headers Exposed", "low", "medium", f"port:{port}", "sensitive_headers", "Response headers reveal underlying stack details useful for targeting.", "\n".join(leaking), {"port": str(port), "headers": leaking}, source="http_headers")
                if allow_origin == "*" and allow_credentials == "true":
                    add("Dangerous CORS Configuration Detected", "high", "high", f"port:{port}", "cors_misconfiguration", "Telemetry shows Access-Control-Allow-Origin=* with Access-Control-Allow-Credentials=true.", "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true", {"port": str(port)})
                if auth_header and cls._looks_like_jwt(auth_header):
                    add("JWT Token Observed in Authorization Header", "medium", "medium", f"port:{port}", "jwt_exposure", "Bearer-style JWT token pattern detected in collected response/request header telemetry.", auth_header[:200], {"port": str(port), "location": "authorization_header"})
                if cookie_header and cls._looks_like_jwt(cookie_header):
                    add("JWT Token Observed in Cookie", "medium", "medium", f"port:{port}", "jwt_exposure", "JWT token pattern detected within cookie telemetry.", cookie_header[:200], {"port": str(port), "location": "cookie"})

        js_deep = enum.get("js_deep_mining", {}) if isinstance(enum, dict) else {}
        for ep in js_deep.get("discovered_endpoints", []) if isinstance(js_deep, dict) else []:
            if isinstance(ep, str):
                category = "internal_api" if "api" in ep.lower() else "hidden_route"
                title = "Internal API Route Discovered via JavaScript" if category == "internal_api" else "Hidden JavaScript Route Discovered"
                sev = "medium" if category == "internal_api" else "low"
                add(title, sev, "medium", ep, category, "Passive JavaScript analysis extracted this route from client-side assets.", ep, {"source": "js_deep_mining"})

        js_findings = js_deep.get("findings", []) if isinstance(js_deep, dict) else []
        for item in js_findings if isinstance(js_findings, list) else []:
            if not isinstance(item, dict):
                continue
            source = item.get("source", "")
            details = item.get("details", {}) if isinstance(item.get("details"), dict) else {}
            for secret in details.get("secrets", []) if isinstance(details.get("secrets", []), list) else []:
                if not isinstance(secret, dict) or not secret.get("value"):
                    continue
                stype = secret.get("type", "Secret")
                value = secret.get("value", "")
                add(f"JavaScript Secret Exposure: {stype}", "high" if "key" in stype.lower() or "token" in stype.lower() else "medium", "medium", source, "secret_exposure", "JavaScript mining extracted a potential credential or secret-like token.", value[:200], {"secret_type": stype, "source": source}, source="javascript")
                if cls._looks_like_jwt(value):
                    add("JWT Token Observed in JavaScript Telemetry", "medium", "medium", source, "jwt_exposure", "JavaScript telemetry includes token matching JWT structure.", value[:200], {"location": "javascript", "source": source}, source="javascript")

        for blob in cls._iter_telemetry_strings(results):
            text = blob.lower().strip()
            if not text:
                continue
            if "169.254.169.254" in text:
                add("Metadata Service Endpoint Referenced", "medium", "medium", "", "metadata_service_exposure", "Collected telemetry references cloud metadata endpoint IP.", blob[:200])
                add("Internal IP Exposure in Telemetry", "low", "medium", "", "internal_ip_exposure", "Collected telemetry contains internal-address metadata exposure indicators.", blob[:200])
            if any(h in text for h in cls.CLOUD_REF_HINTS):
                add("Cloud Storage Reference Observed", "info", "medium", "", "cloud_storage_reference", "Passive telemetry references cloud object storage endpoint patterns.", blob[:200])
            if any(h in text for h in cls.INTERNAL_HOST_HINTS):
                add("Internal Service Hostname Referenced", "low", "medium", "", "internal_hostname_exposure", "Telemetry contains internal hostname/domain suffix indicator.", blob[:200])
            if "api_key" in text or "apikey" in text:
                add("Potential API Key Exposure in Telemetry", "medium", "medium", "", "api_key_exposure", "Raw collected telemetry contains API key marker strings.", blob[:200])
            if "token" in text and any(marker in text for marker in ["=", ":"]):
                add("Potential Token Leakage in Telemetry", "medium", "medium", "", "token_leakage", "Raw collected telemetry contains token marker patterns.", blob[:200])
            if ".git/config" in text or ".git/head" in text or ".git/logs" in text:
                add("Exposed Git Repository Artifact Referenced", "high", "high", "", "git_exposure", "Telemetry references sensitive .git repository artifacts.", blob[:200], source="scan_output")

        findings.extend(AssetDiscoveryEngine.derive_findings(results, target))
        findings.extend(SecretsIntelligenceEngine.derive_findings(results, target))

        deduped = []
        final_seen = set()
        for item in findings:
            fp = cls._mk_fingerprint(item.get("title"), item.get("endpoint"), item.get("category"), item.get("evidence"))
            if fp in final_seen:
                continue
            final_seen.add(fp)
            deduped.append(item)

        return deduped
