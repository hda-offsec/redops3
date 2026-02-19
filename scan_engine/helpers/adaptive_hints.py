def derive_adaptive_hints(results) -> dict:
    hints = {}
    phases = (results or {}).get("phases", {})
    enum_phase = phases.get("enum", {})
    derived = enum_phase.get("derived", {})

    service_intelligence = derived.get("service_intelligence", {})
    cortex_recommendations = derived.get("cortex_recommendations", [])

    for port, intel in service_intelligence.items():
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue

        tags = intel.get("tags", []) if isinstance(intel, dict) else []
        boost = 0
        if "api_surface" in tags:
            boost += 5
        if "postgrey_possible" in tags:
            boost += 3
        if boost:
            hints[f"enum_{port_int}"] = {"priority_boost": boost}

    for rec in cortex_recommendations:
        if not isinstance(rec, dict):
            continue
        if rec.get("category") != "vuln":
            continue

        port = rec.get("port")
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue

        task_id = f"vuln_{port_int}"
        current = hints.get(task_id, {}).get("priority_boost", 0)
        hints[task_id] = {"priority_boost": current + 4}

    return hints
