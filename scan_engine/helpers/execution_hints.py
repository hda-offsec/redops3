from urllib.parse import parse_qs, urlparse


API_HINTS = ("/api", "/rest", "/v1", "/v2", "/v3", "swagger", "openapi", "graphql")
AUTH_HINTS = ("/auth", "/login", "/signin", "/logout", "/session", "/sso")
OAUTH_HINTS = ("oauth", "oidc", "openid", "callback", "authorize", "/token")
ADMIN_HINTS = ("admin", "dashboard", "manage", "internal", "console", "debug", "actuator")
EXPORT_HINTS = ("download", "export", "report", "archive", "backup")
STATE_CHANGE_HINTS = ("activate", "approve", "cancel", "deactivate", "invite", "publish", "refund", "restore", "revoke", "share")
OBJECT_REFERENCE_PARAMS = {"account_id", "id", "object_id", "owner_id", "tenant_id", "user_id", "uuid"}
MASS_ASSIGNMENT_PARAMS = {"account_id", "owner", "owner_id", "permission", "permissions", "plan", "role", "roles", "state", "status", "tenant_id"}
DEFAULT_MODULE_BUDGETS = {
    "api_fuzzer": 16,
    "business_logic": 16,
    "logic_assault": 18,
    "oauth": 8,
    "access_control": 12,
    "ssti": 10,
    "jwt": 8,
    "parameter_miner": 12,
}


def _iter_list_items(value):
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        for candidate_key in ("endpoints", "findings", "vulns"):
            if isinstance(value.get(candidate_key), list):
                return list(value.get(candidate_key))
    return []


def _service_proto_map(results):
    mapping = {}
    for item in (results or {}).get("phases", {}).get("recon", {}).get("open_ports", []) or []:
        if not isinstance(item, dict) or item.get("port") is None:
            continue
        port = str(item.get("port"))
        svc = str(item.get("service", item.get("service_name", ""))).lower()
        if port in {"443", "8443"} or "https" in svc or "ssl" in svc:
            mapping[port] = "https"
        else:
            mapping[port] = "http"
    return mapping


def _coerce_url(target, proto_map, port, candidate):
    if not isinstance(candidate, str):
        return None
    text = candidate.strip()
    if not text:
        return None
    if text.startswith("http://") or text.startswith("https://"):
        return text
    if not target:
        return None
    path = text if text.startswith("/") else f"/{text}"
    proto = proto_map.get(str(port), "http")
    port = str(port)
    if (proto == "http" and port == "80") or (proto == "https" and port == "443"):
        return f"{proto}://{target}{path}"
    return f"{proto}://{target}:{port}{path}"


def _matches_port(url, port):
    if not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.port is not None:
            return str(parsed.port) == str(port)
        if parsed.scheme == "https":
            return str(port) == "443"
        if parsed.scheme == "http":
            return str(port) == "80"
    except Exception:
        return False
    return f":{port}" in url


def _stable_unique(values):
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _collect_port_urls(results, port):
    port = str(port)
    target = (results or {}).get("target", "")
    proto_map = _service_proto_map(results)
    enum_phase = (results or {}).get("phases", {}).get("enum", {})
    vuln_phase = (results or {}).get("phases", {}).get("vuln", {})

    urls = set()

    def remember(items, *, port_bound=False):
        for item in items:
            if isinstance(item, dict):
                candidate = item.get("url") or item.get("endpoint") or item.get("target") or item.get("path")
            else:
                candidate = item
            normalized = _coerce_url(target, proto_map, port, candidate)
            if not normalized:
                continue
            if port_bound and not _matches_port(normalized, port):
                continue
            urls.add(normalized)

    remember(enum_phase.get("targets", {}).get(port, []) or [])
    remember(enum_phase.get("katana", {}).get(port, []) or [])
    remember(enum_phase.get("injection_points", {}).get(port, []) or [])
    remember(enum_phase.get("api", {}).get(port, []) or [])
    remember(enum_phase.get("api", {}).get("discovered_endpoints", []) or [], port_bound=True)
    remember(enum_phase.get("normalized", {}).get(port, []) or [])

    normalized_bucket = enum_phase.get("normalized", {}).get(port, {})
    if isinstance(normalized_bucket, dict):
        remember(normalized_bucket.get("endpoints", []) or [])

    derived = enum_phase.get("derived", {}) if isinstance(enum_phase, dict) else {}
    per_port_surface = derived.get("surface_expansion", {}).get("per_port", {}).get(port, {})
    if isinstance(per_port_surface, dict):
        remember(per_port_surface.get("derived_endpoints", []) or [])

    js_mining = derived.get("js_expert_mining", {}).get(port, {})
    if isinstance(js_mining, dict):
        remember(js_mining.get("discovered_endpoints", []) or [])

    surface_mapping = vuln_phase.get("surface_mapping", {}).get(port, {})
    if isinstance(surface_mapping, dict):
        for items in (surface_mapping.get("tree", {}) or {}).values():
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict):
                    remember([item.get("path")])

    for module_name in ("api_expert", "api_shadow", "logic_assault", "403_bypass", "acl_bypass"):
        payload = vuln_phase.get(module_name)
        remember(_iter_list_items(payload.get(port) if isinstance(payload, dict) and port in payload else payload))

    return sorted(urls)


def _classify_url(url):
    low = str(url or "").lower()
    parsed = urlparse(str(url or ""))
    params = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True).keys()}
    tags = set()
    if any(hint in low for hint in API_HINTS):
        tags.add("api")
    if any(hint in low for hint in AUTH_HINTS):
        tags.add("auth")
    if any(hint in low for hint in OAUTH_HINTS):
        tags.add("oauth")
    if any(hint in low for hint in ADMIN_HINTS):
        tags.add("admin")
    if any(hint in low for hint in EXPORT_HINTS):
        tags.add("export")
    if any(hint in low for hint in STATE_CHANGE_HINTS):
        tags.add("state_change")
    if any(token in low for token in ("token", "jwt", "bearer", "apikey", "api_key")):
        tags.add("token")
    if low.endswith(".js"):
        tags.add("js")
    if "graphql" in low:
        tags.add("graphql")
    if "upload" in low or "import" in low or "media" in low or "profile" in low:
        tags.add("upload")
    if "?" in low:
        tags.add("query")
    if any(param in params for param in OBJECT_REFERENCE_PARAMS):
        tags.add("object")
    if any(param in params for param in MASS_ASSIGNMENT_PARAMS):
        tags.add("mass_assignment")
    if any(segment.isdigit() for segment in parsed.path.split("/") if segment):
        tags.add("object")
    if any(len(segment) >= 8 and all(ch in "0123456789abcdef-" for ch in segment.lower()) for segment in parsed.path.split("/") if segment):
        tags.add("object")
    return tags, params


def _score_url(url, desired_tags):
    tags, params = _classify_url(url)
    score = 0
    for tag in desired_tags:
        if tag in tags:
            score += 4
    if "query" in tags:
        score += 1
    if "object" in tags:
        score += 2
    if params.intersection(MASS_ASSIGNMENT_PARAMS):
        score += 2
    return score, tags, params


def _select_urls(urls, desired_tags, limit):
    ranked = []
    all_params = set()
    for url in urls:
        score, tags, params = _score_url(url, desired_tags)
        if desired_tags and score <= 0:
            continue
        all_params.update(params)
        ranked.append((score, url, tags))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    selected = [url for _, url, _ in ranked[:limit]]
    return selected, _stable_unique(all_params)


def derive_execution_hints(results: dict) -> dict:
    phases = (results or {}).get("phases", {})
    enum_phase = phases.get("enum", {})
    vuln_phase = phases.get("vuln", {})
    derived = enum_phase.get("derived", {})

    caps = {"seed_priority": 200, "nuclei_extra_tags": 3}

    target = (results or {}).get("target", "")
    recon_ports = phases.get("recon", {}).get("open_ports", [])
    injection_points = enum_phase.get("injection_points", {})
    api = enum_phase.get("api", {})
    waf = enum_phase.get("waf", {})
    surface_expansion = derived.get("surface_expansion", {})
    wordpress = vuln_phase.get("wordpress", {})
    cortex_recommendations = derived.get("cortex_recommendations", [])

    port_proto = _service_proto_map(results)
    reason_map = {}

    def _as_url(port, endpoint):
        return _coerce_url(target, port_proto, port, endpoint)

    def _push(url, reason, priority=0):
        if not isinstance(url, str) or not url.startswith("http"):
            return
        entry = reason_map.setdefault(url, {"priority": priority, "reasons": []})
        if priority > entry["priority"]:
            entry["priority"] = priority
        if reason not in entry["reasons"]:
            entry["reasons"].append(reason)

    for port, urls in injection_points.items():
        port_waf = waf.get(str(port), "")
        waf_penalty = 2 if port_waf else 0
        for u in urls if isinstance(urls, list) else []:
            _push(u, "injection_point", priority=100 - waf_penalty)

    per_port_surface = surface_expansion.get("per_port", {}) if isinstance(surface_expansion, dict) else {}
    for port, bucket in per_port_surface.items():
        for endpoint in bucket.get("derived_endpoints", []) if isinstance(bucket, dict) else []:
            normalized = _as_url(port, endpoint)
            _push(normalized, f"surface_expansion:{port}", priority=80)

    for endpoint in api.get("discovered_endpoints", []) if isinstance(api, dict) else []:
        _push(endpoint, "api_discovered", priority=70)

    wp_paths = ["/wp-json", "/xmlrpc.php", "/wp-admin", "/wp-login.php"]
    for port in wordpress.keys() if isinstance(wordpress, dict) else []:
        for path in wp_paths:
            _push(_as_url(port, path), f"wordpress:{port}", priority=60)

    ranked = sorted(reason_map.items(), key=lambda x: (-x[1]["priority"], x[0]))
    seed_priority = [item[0] for item in ranked[: caps["seed_priority"]]]
    reason_map_out = {item[0]: item[1]["reasons"] for item in ranked[: caps["seed_priority"]]}

    extra_tags = []
    nuclei_reason = []
    if wordpress:
        extra_tags.append("wordpress")
        nuclei_reason.append("wordpress_signal")
    if api.get("discovered_endpoints"):
        extra_tags.append("exposures")
        nuclei_reason.append("api_signal")
    if enum_phase.get("whatweb"):
        extra_tags.append("tech")
        nuclei_reason.append("whatweb_signal")
    extra_tags = extra_tags[: caps["nuclei_extra_tags"]]

    per_port_module_hints = {}
    prioritized_modules = []
    for item in recon_ports:
        if not isinstance(item, dict) or item.get("port") is None:
            continue
        port = str(item.get("port"))
        port_urls = _collect_port_urls(results, port)
        if not port_urls:
            continue
        port_recs = [
            rec for rec in cortex_recommendations
            if isinstance(rec, dict) and str(rec.get("port") or "") == port
        ]
        requested_modules = set()
        for rec in port_recs:
            driver = (rec.get("metadata") or {}).get("execution_driver", {})
            if not isinstance(driver, dict):
                continue
            requested_modules.update(driver.get("modules", []) or [])

        module_hints = {}
        selectors = {
            "api_fuzzer": {"desired_tags": {"api", "object", "auth", "admin", "export", "graphql"}, "extra_params": True},
            "business_logic": {"desired_tags": {"api", "state_change", "mass_assignment", "query", "object"}, "extra_params": True},
            "logic_assault": {"desired_tags": {"api", "object", "auth", "admin", "export", "query"}, "extra_params": True},
            "oauth": {"desired_tags": {"oauth", "auth", "token"}, "extra_params": False},
            "access_control": {"desired_tags": {"admin", "auth", "export"}, "extra_params": False},
            "ssti": {"desired_tags": {"query", "api", "graphql"}, "extra_params": True},
            "jwt": {"desired_tags": {"auth", "token", "api", "js"}, "extra_params": False},
            "parameter_miner": {"desired_tags": {"api", "query", "auth", "admin", "object"}, "extra_params": True},
        }

        for module_name, config in selectors.items():
            if requested_modules and module_name not in requested_modules and not (
                module_name == "oauth" and "oauth_expert" in requested_modules
            ) and not (
                module_name == "jwt" and "jwt_expert" in requested_modules
            ) and not (
                module_name == "access_control" and {"acl_scanner", "bypass_expert"}.intersection(requested_modules)
            ):
                continue

            selected, params = _select_urls(
                port_urls,
                config["desired_tags"],
                DEFAULT_MODULE_BUDGETS[module_name],
            )
            if not selected:
                continue
            module_hints[module_name] = {
                "seed_priority": selected,
                "reason_map": {
                    url: ["cortex_execution_driver", *reason_map_out.get(url, [])]
                    for url in selected
                },
                "interesting_params": params if config.get("extra_params") else [],
            }

        if "access_control" in module_hints:
            protected = module_hints["access_control"]["seed_priority"]
            module_hints["access_control"]["protected_urls"] = protected

        if "business_logic" in module_hints:
            business_urls = module_hints["business_logic"]["seed_priority"]
            hpp_urls = [url for url in business_urls if "?" in url]
            mass_urls = [
                url for url in business_urls
                if {"api", "object", "mass_assignment", "state_change"}.intersection(_classify_url(url)[0])
            ]
            module_hints["business_logic"]["hpp_urls"] = hpp_urls[: DEFAULT_MODULE_BUDGETS["business_logic"]]
            module_hints["business_logic"]["mass_assignment_urls"] = mass_urls[: DEFAULT_MODULE_BUDGETS["business_logic"]]

        if "logic_assault" in module_hints:
            module_hints["logic_assault"]["protected_urls"] = [
                url for url in module_hints["logic_assault"]["seed_priority"]
                if {"admin", "auth", "export"}.intersection(_classify_url(url)[0])
            ][: DEFAULT_MODULE_BUDGETS["logic_assault"]]

        if module_hints:
            per_port_module_hints[port] = module_hints
            prioritized_modules.extend(sorted(module_hints.keys()))

    return {
        "version": 2,
        "dalfox": {
            "seed_priority": seed_priority,
            "reason_map": reason_map_out,
        },
        "nuclei": {
            "extra_tags": extra_tags,
            "reason": nuclei_reason,
        },
        "per_port": per_port_module_hints,
        "prioritized_modules": _stable_unique(prioritized_modules),
    }
