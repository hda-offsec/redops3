import re
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, unquote
import ipaddress

from scan_engine.helpers.finding_schema import normalize_finding_shape


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
        "herokuapp.com",
        "netlify.app",
        "vercel.app",
        "oraclecloud.com",
        "softlayer.com"
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
        
        # URL decode blob to avoid artifacts like %22 (quote) being seen as '22' at start of host
        blob = unquote(blob)
        
        hosts = []
        for token in re.findall(r"https?://[A-Za-z0-9._:-]+", blob):
            try:
                parsed = urlparse(token)
                if parsed.hostname:
                    hosts.append(parsed.hostname.lower())
            except: pass

        # Refined regex: must start with a letter or digit, but not a hyphen.
        # Avoids common banner artifacts like '220-hostname'
        for host in re.findall(r"\b(?:[a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}\b", blob):
            h = host.lower()
            # Reject if it looks like a response code artifact (e.g. 220-upload.hove.io)
            if re.match(r"^\d{3}-", h):
                h = h[4:]
            hosts.append(h)
        return list(set(hosts))

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
            "herokuapp.com": "heroku",
            "netlify.app": "netlify",
            "vercel.app": "vercel",
            "oraclecloud.com": "oracle",
            "softlayer.com": "ibm",
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

        def add(
            category,
            discovered_asset,
            source,
            confidence,
            evidence,
            finding_category="asset_discovery",
            severity="info",
        ):
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
            findings.append(
                normalize_finding_shape(
                    {
                        "title": f"Discovered Asset: {discovered_asset}",
                        "severity": severity,
                        "confidence": confidence,
                        "tool_source": "passive_intel",
                        "tool": "passive_intel",
                        "module": "passive_intel",
                        "category": finding_category,
                        "target": target,
                        "endpoint": discovered_asset,
                        "evidence": evidence,
                        "raw_output": evidence,
                        "signal_ids": [],
                        "description": f"Asset discovery extracted {discovered_asset} from {source} telemetry.",
                        "metadata": metadata,
                        "source": source,
                    },
                    source=source,
                )
            )

        for blob in cls._iter_strings(results):
            for host in cls._extract_hosts(blob):
                asset_type, conf = cls._classify_asset(host, target)
                source = "scan_telemetry"
                is_cloud = any(pat in host for pat in cls.CLOUD_PATTERNS)
                finding_category = "cloud_asset" if is_cloud else "asset_discovery"
                severity = "medium" if is_cloud else "info"
                add(
                    asset_type,
                    host,
                    source,
                    conf,
                    blob[:300],
                    finding_category=finding_category,
                    severity=severity,
                )

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
        ("slack_token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b")),
        ("stripe_key", re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b")),
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
                    findings.append(
                        {
                            "title": f"Potential Secret Exposure: {secret_type}",
                            "severity": "high",
                            "confidence": (
                                "high"
                                if secret_type in {
                                    "private_key",
                                    "aws_access_key_id",
                                    "gcp_api_key",
                                    "github_token",
                                    "slack_token",
                                    "stripe_key",
                                }
                                else "medium"
                            ),
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
                        }
                    )

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
    TECH_VERSION_RE = re.compile(r"([A-Za-z0-9._+-]+)[\/-]v?(\d+(?:\.\d+){1,3})", re.IGNORECASE)
    JS_LIB_RE = re.compile(r"\b(jquery|bootstrap|react|vue|angular|next|lodash)[-.]v?(\d+(?:\.\d+){1,3})", re.IGNORECASE)
    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    IP_PROVIDER_HINTS = [
        (ipaddress.ip_network("34.0.0.0/8"), "gcp"),
        (ipaddress.ip_network("35.0.0.0/8"), "gcp"),
        (ipaddress.ip_network("52.0.0.0/8"), "aws"),
        (ipaddress.ip_network("54.0.0.0/8"), "aws"),
        (ipaddress.ip_network("13.64.0.0/11"), "azure"),
        (ipaddress.ip_network("20.0.0.0/11"), "azure"),
        (ipaddress.ip_network("104.16.0.0/12"), "cloudflare"),
        (ipaddress.ip_network("172.64.0.0/13"), "cloudflare"),
    ]

    LOCAL_CVE_RULES = {}

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

        def add(
            title,
            severity="info",
            confidence="medium",
            endpoint="",
            category="passive_intel",
            description="",
            evidence="",
            metadata=None,
            source="passive_telemetry",
            parameter="",
        ):
            fp = cls._mk_fingerprint(title, endpoint, severity, category, parameter)
            if fp in seen or not (evidence or description):
                return
            seen.add(fp)
            md = metadata or {}
            md.setdefault("source", source)
            md.setdefault("confidence", confidence)
            md.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")

            field_sources = md.get("field_sources") if isinstance(md.get("field_sources"), dict) else {}
            if endpoint:
                field_sources.setdefault("endpoint", source)
            if parameter:
                field_sources.setdefault("parameter", source)
            if evidence:
                field_sources.setdefault("evidence", source)
            if md.get("provider"):
                field_sources.setdefault("provider", source)
            if md.get("component"):
                field_sources.setdefault("component", source)
            if md.get("version"):
                field_sources.setdefault("version", source)
            if field_sources:
                md["field_sources"] = field_sources

            findings.append(
                normalize_finding_shape(
                    {
                        "title": title,
                        "severity": severity,
                        "confidence": confidence,
                        "tool_source": "passive_intel",
                        "tool": "passive_intel",
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
                        "source": source,
                    },
                    source=source,
                )
            )

        endpoints = list(cls._iter_endpoints(results))
        for endpoint in endpoints:
            low = endpoint.lower()
            if any(h in low for h in cls.AUTH_HINTS):
                add(
                    "Authentication Surface Exposed",
                    "medium",
                    "medium",
                    endpoint,
                    "auth_surface",
                    "Authentication-related endpoint discovered in existing telemetry.",
                    endpoint,
                )
            if any(h in low for h in cls.API_DOC_PATTERNS):
                add(
                    "Documented API Surface Exposed",
                    "low",
                    "high",
                    endpoint,
                    "api_surface",
                    "Path pattern maps to API documentation or schema endpoint.",
                    endpoint,
                )

        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        enum = phases.get("enum", {}) if isinstance(phases, dict) else {}
        headers_map = enum.get("headers", {}) if isinstance(enum, dict) else {}
        if isinstance(headers_map, dict):
            for port, header_data in headers_map.items():
                if not isinstance(header_data, dict):
                    continue
                allow_origin = str(
                    header_data.get("Access-Control-Allow-Origin")
                    or header_data.get("access-control-allow-origin")
                    or ""
                ).strip()
                allow_credentials = str(
                    header_data.get("Access-Control-Allow-Credentials")
                    or header_data.get("access-control-allow-credentials")
                    or ""
                ).strip().lower()
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
            # Pre-processing: URL decode to handle %22 and other artifacts
            blob_decoded = unquote(blob)
            text = blob_decoded.lower().strip()
            if not text:
                continue

            for subdomain in cls._infer_subdomains(blob_decoded, target_domain):
                add(
                    title=f"Subdomain Inferred: {subdomain}",
                    severity="info",
                    confidence="medium",
                    endpoint=subdomain,
                    category="asset_discovery",
                    description="Subdomain inferred from passive telemetry artifact.",
                    evidence=blob[:220],
                    metadata={
                        "discovered_asset": subdomain,
                        "source": "passive_telemetry",
                        "target": target,
                    },
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
                    metadata={
                        "endpoint": api_ep,
                        "method": "unknown",
                        "source": "passive_telemetry",
                        "target": target,
                    },
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
                    metadata={
                        "parameter": param,
                        "source": "passive_telemetry",
                        "target": target,
                    },
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
                        metadata={
                            "parameter": key,
                            "source": "url_query",
                            "target": target,
                        },
                        source="parameter_inference",
                    )

            if "169.254.169.254" in text:
                add(
                    "Metadata Service Endpoint Referenced",
                    "medium",
                    "medium",
                    "",
                    "metadata_service_exposure",
                    "Collected telemetry references cloud metadata endpoint IP.",
                    blob[:200],
                )
            if any(h in text for h in cls.CLOUD_REF_HINTS):
                add(
                    "Cloud Storage Reference Observed",
                    "info",
                    "medium",
                    "",
                    "cloud_storage_reference",
                    "Passive telemetry references cloud object storage endpoint patterns.",
                    blob[:200],
                )
            if "token" in text and any(marker in text for marker in ["=", ":"]):
                add(
                    "Potential Token Leakage in Telemetry",
                    "medium",
                    "medium",
                    "",
                    "token_leakage",
                    "Raw collected telemetry contains token marker patterns.",
                    blob[:200],
                )
            if cls._looks_like_jwt(blob) or re.search(
                r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                blob,
            ):
                add(
                    "JWT Token Observed in Telemetry",
                    "medium",
                    "medium",
                    "",
                    "jwt_exposure",
                    "Telemetry includes token matching JWT structure.",
                    blob[:200],
                )

            for host in AssetDiscoveryEngine._extract_hosts(blob):
                provider = AssetDiscoveryEngine._provider_for_host(host)
                if provider != "unknown":
                    infra_category = "cloud_asset" if provider in {"aws", "gcp", "azure"} else "infra_discovery"
                    add(
                        title=f"Infrastructure Provider Hint: {host}",
                        severity="info",
                        confidence="medium",
                        endpoint=host,
                        category=infra_category,
                        description="Provider/CDN inference from passive host telemetry.",
                        evidence=blob[:220],
                        metadata={
                            "target": target,
                            "discovered_asset": host,
                            "provider": provider,
                            "source": "passive_telemetry",
                            "confidence": "medium",
                        },
                        source="infra_provider_inference",
                    )
                if host.endswith(".local") or ".internal" in host or host.endswith(".corp"):
                    add(
                        title=f"Internal Hostname Referenced: {host}",
                        severity="medium",
                        confidence="high",
                        endpoint=host,
                        category="infra_discovery",
                        description="Internal hostname referenced in collected telemetry.",
                        evidence=blob[:220],
                        metadata={
                            "target": target,
                            "discovered_asset": host,
                            "provider": "internal",
                            "source": "passive_telemetry",
                            "confidence": "high",
                        },
                        source="infra_internal_host",
                    )

            for ip_raw in cls.IP_RE.findall(blob):
                try:
                    ip_obj = ipaddress.ip_address(ip_raw)
                except ValueError:
                    continue
                provider = "unknown"
                for network, hint in cls.IP_PROVIDER_HINTS:
                    if ip_obj in network:
                        provider = hint
                        break
                if provider != "unknown":
                    add(
                        title=f"IP Range Provider Hint: {ip_raw}",
                        severity="info",
                        confidence="low",
                        endpoint=ip_raw,
                        category="infra_discovery",
                        description="Cloud/provider ASN hint inferred from observed IP range.",
                        evidence=blob[:220],
                        metadata={
                            "target": target,
                            "discovered_asset": ip_raw,
                            "provider": provider,
                            "source": "ip_range_mapping",
                            "confidence": "low",
                        },
                        source="infra_ip_hint",
                    )

            for match in cls.JS_LIB_RE.finditer(blob):
                component, version = match.group(1).lower(), match.group(2)
                add(
                    title=f"Technology Fingerprint: {component}",
                    severity="info",
                    confidence="high",
                    endpoint="",
                    category="tech_fingerprint",
                    description="Component and version extracted from static asset naming pattern.",
                    evidence=match.group(0),
                    metadata={
                        "component": component,
                        "version": version,
                        "source": "js_asset_path",
                        "confidence": "high",
                    },
                    source="tech_js_pattern",
                )
                add(
                    title=f"Dependency Surface: {component} {version}",
                    severity="low",
                    confidence="high",
                    endpoint="",
                    category="dependency_surface",
                    description="Dependency version evidence extracted from telemetry artifacts.",
                    evidence=match.group(0),
                    metadata={
                        "component": component,
                        "version": version,
                        "source": "js_asset_path",
                        "confidence": "high",
                    },
                    source="dependency_surface",
                )

            for match in cls.TECH_VERSION_RE.finditer(blob):
                component, version = match.group(1).lower(), match.group(2)
                if component in {"http", "https"} or len(component) < 3:
                    continue
                if component in {"apache", "nginx", "express", "next.js", "wordpress"}:
                    add(
                        title=f"Technology Fingerprint: {component}",
                        severity="info",
                        confidence="medium",
                        endpoint="",
                        category="tech_fingerprint",
                        description="Version clue extracted from banner/header/path telemetry.",
                        evidence=match.group(0),
                        metadata={
                            "component": component,
                            "version": version,
                            "source": "banner_or_path",
                            "confidence": "medium",
                        },
                        source="tech_banner_pattern",
                    )

        tech_findings = [f for f in findings if f.get("category") in {"tech_fingerprint", "dependency_surface"}]
        if not cls.LOCAL_CVE_RULES and tech_findings:
            related_components = sorted(
                {
                    (f.get("metadata") or {}).get("component")
                    for f in tech_findings
                    if isinstance(f.get("metadata"), dict) and (f.get("metadata") or {}).get("component")
                }
            )
            add(
                title="CVE Intelligence Hook Active (No Local Rules)",
                severity="info",
                confidence="high",
                endpoint="",
                category="next_step",
                description="No deterministic local CVE map is configured; CVE candidate generation is safely disabled.",
                evidence="local_cve_rules=empty",
                metadata={
                    "title": "Build local CVE mapping dataset",
                    "description": "Add deterministic local CVE rules to enable cve_candidate correlation.",
                    "rationale": "Telemetry has component/version clues but repository has no CVE mapping source.",
                    "related_signal_ids": [],
                    "related_finding_ids": [],
                    "component": ", ".join(related_components[:3]) if related_components else "dependency_surface",
                    "attack_priority": "low",
                    "action_priority": 20,
                    "action_type": "intel_gap",
                    "estimated_value": "medium",
                    "estimated_complexity": "low",
                },
                source="cve_intelligence_hook",
            )

        high_signal = len([f for f in findings if f.get("severity") in {"medium", "high", "critical"}])
        if high_signal:
            add(
                title="Cortex Next Step: Prioritize Highest-Confidence Attack Paths",
                severity="info",
                confidence="high",
                endpoint="",
                category="attack_plan",
                description="Deterministic planning recommends exploiting top evidence-backed chains before low-confidence probes.",
                evidence=f"signal_strength={high_signal}",
                metadata={
                    "title": "Prioritize evidence-backed routes",
                    "description": "Investigate SSRF metadata paths, JS-derived admin routes, and authenticated API vectors if present.",
                    "rationale": "Plan derived from correlated findings, telemetry evidence, and deterministic severity/confidence ordering.",
                    "related_signal_ids": [],
                    "related_finding_ids": [],
                    "attack_chain": "evidence_backed_chain",
                    "attack_priority": "high" if high_signal >= 8 else "medium",
                    "action_priority": 80 if high_signal >= 8 else 60,
                    "action_type": "guided_probe",
                    "estimated_value": "high",
                    "estimated_complexity": "medium",
                },
                source="cortex_planner",
            )

        findings.extend(AssetDiscoveryEngine.derive_findings(results, target))
        findings.extend(SecretsIntelligenceEngine.derive_findings(results, target))

        existing_categories = {(f.get("category") or "") for f in findings}
        mission_catalog = [
            {
                "objective_type": "authenticated_api_path",
                "required_categories": ["auth_surface", "api_surface"],
                "title": "Mission Prep: Authenticated API Path",
                "description": "Authentication and API telemetry overlap; prepare authenticated endpoint abuse workflow.",
                "required_conditions": ["authentication surface", "api surface"],
                "recommended_next_steps": ["validate auth flow tokens", "test role boundaries on discovered APIs"],
            },
            {
                "objective_type": "cloud_credential_path",
                "required_categories": ["secret_exposure", "cloud_asset"],
                "title": "Mission Prep: Cloud Credential Path",
                "description": "Cloud assets and credential artifacts overlap; prioritize containment-safe credential validation.",
                "required_conditions": ["cloud asset telemetry", "credential/token evidence"],
                "recommended_next_steps": ["scope token permissions", "validate least-privilege gaps"],
            },
            {
                "objective_type": "source_code_leak_path",
                "required_categories": ["git_exposure", "secret_exposure"],
                "title": "Mission Prep: Source Code Leak Path",
                "description": "Source-recovery indicators and secret telemetry overlap; prepare controlled source triage.",
                "required_conditions": ["repository exposure", "secret evidence"],
                "recommended_next_steps": ["verify repository exposure", "map leaked secrets to active services"],
            },
        ]

        for mission in mission_catalog:
            if not all(req in existing_categories for req in mission["required_categories"]):
                continue
            support = [
                f for f in findings
                if (f.get("category") or "") in set(mission["required_categories"])
            ]
            related_finding_ids = [f.get("id_stable") for f in support if f.get("id_stable")]
            supporting_signals = []
            for finding in support:
                supporting_signals.extend(
                    finding.get("signal_ids") if isinstance(finding.get("signal_ids"), list) else []
                )
            add(
                title=mission["title"],
                severity="medium",
                confidence="high" if len(support) >= 2 else "medium",
                endpoint=target,
                category="mission_prep",
                description=mission["description"],
                evidence="; ".join(
                    sorted({f.get("title", "") for f in support if f.get("title")})
                )[:500],
                metadata={
                    "objective_type": mission["objective_type"],
                    "required_conditions": mission["required_conditions"],
                    "supporting_findings": related_finding_ids,
                    "supporting_signals": sorted({sid for sid in supporting_signals if sid is not None}),
                    "recommended_next_steps": mission["recommended_next_steps"],
                    "confidence": "high" if len(support) >= 2 else "medium",
                    "attack_priority": "high",
                },
                source="mission_planner",
            )
            add(
                title=f"Objective Path: {mission['objective_type']}",
                severity="info",
                confidence="medium",
                endpoint=target,
                category="objective_path",
                description="Objective path derived from mission prep prerequisites and deterministic category correlation.",
                evidence=mission["description"],
                metadata={
                    "objective_type": mission["objective_type"],
                    "required_conditions": mission["required_conditions"],
                    "supporting_findings": related_finding_ids,
                    "supporting_signals": sorted({sid for sid in supporting_signals if sid is not None}),
                    "recommended_next_steps": mission["recommended_next_steps"],
                    "confidence": "medium",
                    "attack_priority": "medium",
                },
                source="mission_planner",
            )

        deduped = []
        final_seen = set()
        for item in findings:
            fp = cls._mk_fingerprint(
                item.get("title"),
                item.get("endpoint"),
                item.get("category"),
                item.get("evidence"),
                item.get("parameter"),
            )
            if fp in final_seen:
                continue
            final_seen.add(fp)
            deduped.append(item)

        return deduped