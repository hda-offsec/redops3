from datetime import datetime, timezone


def derive_surface_expansion(results: dict) -> dict:
    phases = (results or {}).get("phases", {})
    enum_phase = phases.get("enum", {})
    vuln_phase = phases.get("vuln", {})
    recon_ports = phases.get("recon", {}).get("open_ports", [])

    caps = {
        "per_port_endpoints": 20,
        "per_port_params": 30,
        "global_endpoints": 30,
        "spa_candidates": 10,
        "api_candidates": 10,
        "wordpress_candidates": 6,
        "js_signal_candidates": 10,
    }

    per_port = {}
    global_endpoints = []
    global_reasons = []

    injection_points = enum_phase.get("injection_points", {})
    targets = enum_phase.get("targets", {})
    api = enum_phase.get("api", {})
    js_secrets = enum_phase.get("js_secrets", {})
    attack_profile = enum_phase.get("attack_profile", {})
    wordpress_data = vuln_phase.get("wordpress", {})
    graphql_data = vuln_phase.get("graphql", {})

    default_spa = [
        "/", "/app", "/dashboard", "/login", "/register",
        "/assets", "/static", "/main.js", "/runtime.js", "/vendor.js",
    ]
    default_api = [
        "/api", "/api/v1", "/api/v2", "/api/docs", "/openapi.json",
        "/swagger", "/swagger.json", "/graphql", "/graphiql", "/rest",
    ]
    wp_endpoints = ["/wp-json", "/xmlrpc.php", "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes"]
    js_signal_endpoints = [
        "/assets/app.js", "/assets/main.js", "/static/js/main.js", "/static/js/bundle.js", "/bundle.js",
        "/webpack.runtime.js", "/manifest.json", "/service-worker.js", "/robots.txt", "/sitemap.xml",
    ]

    def _add_unique(bucket, value, cap):
        if value and value not in bucket and len(bucket) < cap:
            bucket.append(value)

    def _profile_has_spa(profile_obj):
        txt = str(profile_obj).lower()
        return any(k in txt for k in ["react", "angular", "vue", "spa"])

    known_ports = []
    for p_info in recon_ports:
        if isinstance(p_info, dict) and p_info.get("port") is not None:
            known_ports.append(str(p_info.get("port")))

    candidate_ports = set(known_ports)
    candidate_ports.update(str(k) for k in targets.keys())
    candidate_ports.update(str(k) for k in injection_points.keys())
    candidate_ports.update(str(k) for k in attack_profile.keys())
    candidate_ports.update(str(k) for k in wordpress_data.keys())

    for port in sorted(candidate_ports):
        derived_endpoints = []
        derived_params = []
        reasons = []

        port_profile = attack_profile.get(port, {})
        has_spa = _profile_has_spa(port_profile)
        if has_spa:
            for ep in default_spa[: caps["spa_candidates"]]:
                _add_unique(derived_endpoints, ep, caps["per_port_endpoints"])
            reasons.append("spa_signal")

        has_api_signal = bool(api.get("discovered_endpoints")) or bool(graphql_data)
        if has_api_signal:
            for ep in default_api[: caps["api_candidates"]]:
                _add_unique(derived_endpoints, ep, caps["per_port_endpoints"])
            reasons.append("api_surface_signal")

        if wordpress_data.get(port):
            for ep in wp_endpoints[: caps["wordpress_candidates"]]:
                _add_unique(derived_endpoints, ep, caps["per_port_endpoints"])
            reasons.append("wordpress_signal")

        if js_secrets.get(port):
            for ep in js_signal_endpoints[: caps["js_signal_candidates"]]:
                _add_unique(derived_endpoints, ep, caps["per_port_endpoints"])
            reasons.append("js_secrets_signal")

        for seed in injection_points.get(str(port), []):
            if "?" in str(seed):
                query_str = str(seed).split("?", 1)[-1]
                for raw_param in query_str.split("&"):
                    key = raw_param.split("=", 1)[0].strip()
                    if key:
                        _add_unique(derived_params, key, caps["per_port_params"])

        if derived_endpoints or derived_params or reasons:
            per_port[port] = {
                "derived_endpoints": derived_endpoints[: caps["per_port_endpoints"]],
                "derived_params": derived_params[: caps["per_port_params"]],
                "reasons": reasons,
            }

            for ep in derived_endpoints:
                _add_unique(global_endpoints, ep, caps["global_endpoints"])
            for r in reasons:
                if r not in global_reasons:
                    global_reasons.append(r)

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "per_port": per_port,
        "global": {
            "derived_endpoints": global_endpoints[: caps["global_endpoints"]],
            "reasons": global_reasons,
        },
        "caps": caps,
    }
