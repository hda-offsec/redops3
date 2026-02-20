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

    port_proto = {}
    for item in recon_ports:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        if port is None:
            continue
        svc = str(item.get("service", item.get("service_name", ""))).lower()
        if port in [443, 8443] or "https" in svc or "ssl" in svc:
            port_proto[str(port)] = "https"
        else:
            port_proto[str(port)] = "http"

    reason_map = {}

    def _as_url(port, endpoint):
        port = str(port)
        if isinstance(endpoint, str) and endpoint.startswith("http"):
            return endpoint
        if not target:
            return None
        if not isinstance(endpoint, str):
            return None
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        proto = port_proto.get(str(port), "http")
        if (proto == "http" and str(port) == "80") or (proto == "https" and str(port) == "443"):
            return f"{proto}://{target}{path}"
        return f"{proto}://{target}:{port}{path}"

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

    ranked = sorted(reason_map.items(), key=lambda x: x[1]["priority"], reverse=True)
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

    return {
        "version": 1,
        "dalfox": {
            "seed_priority": seed_priority,
            "reason_map": reason_map_out,
        },
        "nuclei": {
            "extra_tags": extra_tags,
            "reason": nuclei_reason,
        },
    }
