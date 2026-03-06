import re
from datetime import datetime
from urllib.parse import urlparse, parse_qsl


class AssetDiscoveryEngine:
    """Extract asset intelligence from existing telemetry only."""

    CLOUD_PATTERNS = (
        "amazonaws.com",
        "cloudfront.net",
        "s3.amazonaws.com",
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

    @classmethod
    def _provider_for_host(cls, host):
        host = (host or "").lower()
        provider_map = {
            "amazonaws.com": "aws",
            "s3.amazonaws.com": "aws",
            "cloudfront.net": "aws",
            "storage.googleapis.com": "gcp",
            "azurewebsites.net": "azure",
            "digitaloceanspaces.com": "digitalocean",
            "blob.core.windows.net": "azure",
        }
        for suffix, provider in provider_map.items():
            if suffix in host:
                return provider
        return "unknown"

    @staticmethod
    def _classify_asset(host, target):
        host = host.lower()
        target_l = (target or "").lower()
        if any(pat in host for pat in AssetDiscoveryEngine.CLOUD_PATTERNS):
            return "cloud_resource", "medium"
        if host.startswith("api.") or ".api." in host:
            return "api_host", "high"
        if host.startswith("cdn.") or "cdn" in host:
            return "cdn_host", "medium"
        if host.endswith(".local") or ".internal" in host or ".corp" in host:
            return "internal_domain", "medium"
        if target_l and (host == target_l or host.endswith(f".{target_l}")):
            return "subdomain", "medium"
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
            metadata = {
                "target": target,
                "discovered_asset": discovered_asset,
                "source": source,
                "confidence": confidence,
                "asset_type": category,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            if finding_category == "cloud_asset":
                metadata["provider"] = cls._provider_for_host(discovered_asset)
            findings.append({
                "title": f"Discovered Asset: {discovered_asset}",
                "severity": severity,
                "confidence": confidence,
                "tool_source": "passive_intel",
                "module": "passive_intel",
                "category": finding_category,
                "target": target,
                "endpoint": discovered_asset,
                "evidence": evidence,
                "raw_output": evidence,
                "signal_ids": [],
                "description": f"Asset discovery extracted {discovered_asset} from {source} telemetry.",
                "metadata": metadata,
            })

        for blob in cls._iter_strings(results):
            for host in cls._extract_hosts(blob):
                asset_type, conf = cls._classify_asset(host, target)
                source = "scan_telemetry"
                is_cloud = any(pat in host for pat in cls.CLOUD_PATTERNS)
                finding_category = "cloud_asset" if is_cloud else "asset_discovery"
                severity = "medium" if is_cloud else "info"
                add(asset_type, host, source, conf, blob[:300], finding_category=finding_category, severity=severity)

        return findings


class SecretsIntelligenceEngine:
    """Evidence-driven secret pattern detection from collected scan telemetry."""

    SECRET_PATTERNS = [
        ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("aws_access_key_marker", re.compile(r"\bAWS_ACCESS_KEY_ID\b")),
        ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{30,40}\b")),
        ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("oauth_token", re.compile(r"\boa(?:uth)?[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9._-]{16,}", re.IGNORECASE)),
        ("basic_auth", re.compile(r"\bbasic\s+[A-Za-z0-9+/]{8,}={0,2}", re.IGNORECASE)),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
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
                        "severity": "high",
                        "confidence": "high" if secret_type in {"private_key", "aws_access_key_id", "gcp_api_key", "github_token"} else "medium",
                        "tool_source": "passive_intel",
                        "module": "passive_intel",
                        "category": "secret_exposure",
                        "target": target,
                        "endpoint": "",
                        "evidence": evidence,
                        "raw_output": blob[:500],
                        "signal_ids": [],
                        "description": f"Secret intelligence matched {secret_type} pattern in collected telemetry.",
                        "metadata": {
                            "target": target,
                            "secret_type": secret_type,
                            "source": "scan_telemetry",
                            "location": "telemetry_blob",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
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

    SUBDOMAIN_RE = re.compile(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
    API_RE = re.compile(r"(?:fetch\(|axios\.|XMLHttpRequest|['\"])(/[^'\"\s]+)")
    PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\-\.]+)=")

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

    @staticmethod
    def _mk_fingerprint(*parts):
        return "|".join(str(p or "").strip().lower() for p in parts)

    @classmethod
    def _infer_subdomains(cls, blob, target_domain):
        found = set()
        t = (target_domain or "").lower().strip()
        if not t:
            return found
        for match in cls.SUBDOMAIN_RE.finditer(blob):
            host = match.group(1).lower().strip(".")
            if host == t or host.endswith(f".{t}"):
                found.add(host)
        return found

    @classmethod
    def _infer_api_endpoints(cls, blob):
        endpoints = set()
        for match in cls.API_RE.finditer(blob):
            candidate = match.group(1)
            if any(marker in candidate.lower() for marker in ["/api/", "/v1/", "/v2/", "/graphql"]):
                endpoints.add(candidate)
        return endpoints

    @classmethod
    def derive_findings(cls, results, target):
        findings = []
        seen = set()
        target_domain = (target or "").split(":")[0]

        def add(title, severity="info", confidence="medium", endpoint="", category="passive_intel", description="", evidence="", metadata=None, source="passive_telemetry", parameter=""):
            fp = cls._mk_fingerprint(title, endpoint, severity, category, parameter)
            if fp in seen or not (evidence or description):
                return
            seen.add(fp)
            md = metadata or {}
            md.setdefault("source", source)
            md.setdefault("confidence", confidence)
            md.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
            findings.append({
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "tool_source": "passive_intel",
                "module": "passive_intel",
                "category": category,
                "target": target,
                "endpoint": endpoint,
                "parameter": parameter,
                "evidence": evidence or description,
                "description": description,
                "raw_output": evidence or description,
                "signal_ids": [],
                "metadata": md,
            })

        endpoints = list(cls._iter_endpoints(results))
        for endpoint in endpoints:
            low = endpoint.lower()
            if any(h in low for h in cls.AUTH_HINTS):
                add("Authentication Surface Exposed", "medium", "medium", endpoint, "auth_surface", "Authentication-related endpoint discovered in existing telemetry.", endpoint)
            if any(h in low for h in cls.API_DOC_PATTERNS):
                add("Documented API Surface Exposed", "low", "high", endpoint, "api_surface", "Path pattern maps to API documentation or schema endpoint.", endpoint)

        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}
        headers_map = enum.get("headers", {}) if isinstance(enum, dict) else {}
        if isinstance(headers_map, dict):
            for port, header_data in headers_map.items():
                if not isinstance(header_data, dict):
                    continue
                allow_origin = str(header_data.get("Access-Control-Allow-Origin") or header_data.get("access-control-allow-origin") or "").strip()
                allow_credentials = str(header_data.get("Access-Control-Allow-Credentials") or header_data.get("access-control-allow-credentials") or "").strip().lower()
                if allow_origin == "*" and allow_credentials == "true":
                    add(
                        "Dangerous CORS Configuration Detected",
                        "high",
                        "high",
                        f"port:{port}",
                        "cors_misconfiguration",
                        "Telemetry shows Access-Control-Allow-Origin=* with Access-Control-Allow-Credentials=true.",
                        "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                        metadata={"port": str(port)},
                    )

        inj_points = enum.get("injection_points", {}) if isinstance(enum, dict) else {}
        for port, params in inj_points.items():
            for param in params if isinstance(params, list) else []:
                if isinstance(param, str) and any(h in param.lower() for h in cls.PROTOTYPE_HINTS):
                    add(
                        "Prototype Pollution Input Surface",
                        "medium",
                        "medium",
                        f"port:{port}",
                        "prototype_pollution_surface",
                        "Discovered prototype-pollution marker within parameter telemetry.",
                        param,
                        metadata={"parameter": param, "port": str(port)},
                    )
                if isinstance(param, str) and any(h in param.lower() for h in cls.SSRF_PARAM_HINTS):
                    add(
                        "Potential SSRF Input Surface",
                        "info",
                        "medium",
                        f"port:{port}",
                        "ssrf_surface",
                        "Discovered parameter indicates user-controlled remote destination semantics.",
                        param,
                        metadata={"parameter": param, "port": str(port)},
                    )

        for blob in cls._iter_telemetry_strings(results):
            text = blob.lower().strip()
            if not text:
                continue

            for subdomain in cls._infer_subdomains(blob, target_domain):
                add(
                    title=f"Subdomain Inferred: {subdomain}",
                    severity="info",
                    confidence="medium",
                    endpoint=subdomain,
                    category="asset_discovery",
                    description="Subdomain inferred from passive telemetry artifact.",
                    evidence=blob[:220],
                    metadata={"discovered_asset": subdomain, "source": "passive_telemetry", "target": target},
                    source="subdomain_inference",
                )

            for api_ep in cls._infer_api_endpoints(blob):
                add(
                    title=f"API Endpoint Discovered: {api_ep}",
                    severity="info",
                    confidence="medium",
                    endpoint=api_ep,
                    category="api_surface",
                    description="API endpoint inferred from JavaScript/XHR/fetch/axios telemetry.",
                    evidence=blob[:220],
                    metadata={"endpoint": api_ep, "method": "unknown", "source": "passive_telemetry", "target": target},
                    source="api_inference",
                )

            for param in cls.PARAM_RE.findall(blob):
                add(
                    title=f"Parameter Surface Discovered: {param}",
                    severity="info",
                    confidence="medium",
                    endpoint="",
                    category="parameter_surface",
                    parameter=param,
                    description="Parameter candidate discovered from query/body/json telemetry.",
                    evidence=blob[:220],
                    metadata={"parameter": param, "source": "passive_telemetry", "target": target},
                    source="parameter_inference",
                )

            parsed = urlparse(blob) if blob.startswith("http") else None
            if parsed and parsed.query:
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                    add(
                        title=f"Parameter Surface Discovered: {key}",
                        severity="info",
                        confidence="medium",
                        category="parameter_surface",
                        parameter=key,
                        description="Parameter candidate discovered from URL query telemetry.",
                        evidence=blob[:220],
                        metadata={"parameter": key, "source": "url_query", "target": target},
                        source="parameter_inference",
                    )

            if "169.254.169.254" in text:
                add("Metadata Service Endpoint Referenced", "medium", "medium", "", "metadata_service_exposure", "Collected telemetry references cloud metadata endpoint IP.", blob[:200])
            if any(h in text for h in cls.CLOUD_REF_HINTS):
                add("Cloud Storage Reference Observed", "info", "medium", "", "cloud_storage_reference", "Passive telemetry references cloud object storage endpoint patterns.", blob[:200])
            if "token" in text and any(marker in text for marker in ["=", ":"]):
                add("Potential Token Leakage in Telemetry", "medium", "medium", "", "token_leakage", "Raw collected telemetry contains token marker patterns.", blob[:200])
            if cls._looks_like_jwt(blob) or re.search(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", blob):
                add("JWT Token Observed in Telemetry", "medium", "medium", "", "jwt_exposure", "Telemetry includes token matching JWT structure.", blob[:200])

        findings.extend(AssetDiscoveryEngine.derive_findings(results, target))
        findings.extend(SecretsIntelligenceEngine.derive_findings(results, target))

        deduped = []
        final_seen = set()
        for item in findings:
            fp = cls._mk_fingerprint(item.get("title"), item.get("endpoint"), item.get("category"), item.get("evidence"), item.get("parameter"))
            if fp in final_seen:
                continue
            final_seen.add(fp)
            deduped.append(item)

        return deduped
