
def validate_results_schema(results: dict) -> list:
    warnings = []
    if not isinstance(results, dict):
        return ["results_not_dict"]

    phases = results.get("phases", {})
    enum_phase = phases.get("enum", {})
    derived = enum_phase.get("derived", {})

    if not isinstance(derived, dict):
        warnings.append("enum_derived_not_dict")
        return warnings

    if "surface_expansion" in derived:
        se = derived.get("surface_expansion")
        if not isinstance(se, dict):
            warnings.append("surface_expansion_not_dict")
        else:
            per_port = se.get("per_port", {})
            if not isinstance(per_port, dict):
                warnings.append("surface_expansion_per_port_not_dict")
            else:
                for port, item in per_port.items():
                    if not isinstance(item, dict):
                        warnings.append(f"surface_expansion_per_port_item_not_dict:{port}")
                        continue
                    if len(item.get("derived_endpoints", []) or []) > 20:
                        warnings.append(f"surface_expansion_endpoint_cap_exceeded:{port}")
                    if len(item.get("derived_params", []) or []) > 30:
                        warnings.append(f"surface_expansion_param_cap_exceeded:{port}")
            global_obj = se.get("global", {})
            if isinstance(global_obj, dict):
                if len(global_obj.get("derived_endpoints", []) or []) > 30:
                    warnings.append("surface_expansion_global_endpoint_cap_exceeded")

    if "execution_hints" in derived:
        hints = derived.get("execution_hints")
        if not isinstance(hints, dict):
            warnings.append("execution_hints_not_dict")
        else:
            dalfox = hints.get("dalfox", {})
            if isinstance(dalfox, dict):
                if len(dalfox.get("seed_priority", []) or []) > 200:
                    warnings.append("execution_hints_seed_priority_cap_exceeded")
            nuclei = hints.get("nuclei", {})
            if isinstance(nuclei, dict):
                if len(nuclei.get("extra_tags", []) or []) > 3:
                    warnings.append("execution_hints_nuclei_extra_tags_cap_exceeded")

    for key in ["attack_profile", "mutation_strategy"]:
        value = enum_phase.get(key)
        if value is not None and not isinstance(value, dict):
            warnings.append(f"{key}_not_dict")

    return warnings
