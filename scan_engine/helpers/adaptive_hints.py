def derive_adaptive_hints(results) -> dict:
    """
    V6 Logic: Analyzes intelligence results (from Strategic Analysis)
    and produces priority boosts for the TaskScheduler.
    """
    hints = {}
    phases = (results or {}).get("phases", {})
    enum_phase = phases.get("enum", {})
    derived = enum_phase.get("derived", {})

    service_intelligence = derived.get("service_intelligence", [])
    cortex_recommendations = derived.get("cortex_recommendations", [])
    tech_stack = results.get("phases", {}).get("vuln", {}).get("tech", {})

    # 1. Boost based on Service Intelligence Tags
    for intel in service_intelligence:
        if not isinstance(intel, dict): continue
        
        port = intel.get("port")
        if not port: continue
        
        tags = intel.get("tags", [])
        boost = 0
        
        # High-value surface boosts
        if "api_surface" in tags: boost += 10
        if "web_surface" in tags: boost += 5
        if "wordpress" in tags: boost += 15
        if "postgrey_possible" in tags: boost += 3
        
        if boost:
            # Boost both enumeration and vuln tasks for this port
            hints[f"enum_{port}"] = {"priority_boost": boost}
            hints[f"vuln_{port}"] = {"priority_boost": boost // 2}

    # 2. Boost based on Tech Stack Modernization
    # Modern stacks (React/Angular) often have more logic-driven vulnerabilities
    if tech_stack:
        mod_level = tech_stack.get("modernization_level", "")
        if mod_level in ["Modern", "Cutting Edge"]:
            # Boost all web-related tasks slightly
            for task_id in hints:
                hints[task_id]["priority_boost"] += 5

    # 3. Heavy Boost based on Cortex Recommendations
    for rec in cortex_recommendations:
        if not isinstance(rec, dict): continue
        
        # If cortex explicitly recommends priority, we double down
        port = rec.get("port")
        if not port: continue

        task_id = f"vuln_{port}"
        current = hints.get(task_id, {}).get("priority_boost", 0)
        
        # Confidence-weighted boost
        confidence_factor = rec.get("confidence", 50) / 100
        boost_value = int(12 * confidence_factor)
        
        if task_id not in hints: hints[task_id] = {}
        hints[task_id]["priority_boost"] = current + boost_value

    return hints
