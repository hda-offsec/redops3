from typing import Any, Dict, List


def _is_http_like(service_name: str, port: str) -> bool:
    service = (service_name or "").lower()
    return ("http" in service) or (str(port) in {"80", "443", "8080", "8443"})


def _has_wp_signal(results: Dict[str, Any], port: str) -> bool:
    enum_tech = results.get("phases", {}).get("enum", {}).get("tech", {})
    vuln_wp = results.get("phases", {}).get("vuln", {}).get("wordpress", {})
    whatweb = results.get("phases", {}).get("enum", {}).get("whatweb", {}).get("technologies", {})

    port_whatweb = whatweb.get(str(port), []) if isinstance(whatweb, dict) else []
    if any("wordpress" in str(t).lower() for t in port_whatweb):
        return True

    if isinstance(vuln_wp, dict) and str(port) in vuln_wp:
        return True

    if isinstance(enum_tech, dict):
        text = str(enum_tech).lower()
        if "wordpress" in text:
            return True

    return False





def _service_intel_recommendations(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    service_intel = results.get("phases", {}).get("enum", {}).get("derived", {}).get("service_intelligence", [])
    if not isinstance(service_intel, list):
        return recs

    for item in service_intel:
        if not isinstance(item, dict):
            continue
        tags = item.get("tags", [])
        if not isinstance(tags, list):
            continue
        port = item.get("port")
        port_str = str(port) if port is not None else None

        if "postgrey_possible" in tags:
            recs.append({
                "id": f"cortex-intel-smtp-postgrey-{port_str or 'unknown'}",
                "title": f"Validate SMTP banner behavior on port {port_str or 'unknown'}",
                "reason": "Service intelligence indicates possible Postgrey filtering; perform controlled SMTP/banner checks.",
                "confidence": 70,
                "port": port_str,
                "category": "intel",
            })

        if "api_surface" in tags:
            recs.append({
                "id": f"cortex-enum-api-followup-{port_str or 'unknown'}",
                "title": f"Expand API endpoint validation on port {port_str or 'unknown'}",
                "reason": "Service intelligence tags suggest API/GraphQL surface requiring targeted endpoint verification.",
                "confidence": 73,
                "port": port_str,
                "category": "enum",
            })

    return recs


def suggest_actions(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    suggestions: List[Dict[str, Any]] = []
    phases = results.get("phases", {})
    recon_ports = phases.get("recon", {}).get("open_ports", [])
    enum = phases.get("enum", {})
    vuln = phases.get("vuln", {})

    waf_map = enum.get("waf", {}) if isinstance(enum.get("waf", {}), dict) else {}
    inj_map = enum.get("injection_points", {}) if isinstance(enum.get("injection_points", {}), dict) else {}
    profile_map = enum.get("attack_profile", {}) if isinstance(enum.get("attack_profile", {}), dict) else {}

    for port_info in recon_ports:
        port = str(port_info.get("port"))
        service = str(port_info.get("service", port_info.get("service_name", "")))

        if _is_http_like(service, port) and len(inj_map.get(port, []) or []) > 0:
            suggestions.append({
                "id": f"cortex-enum-param-xss-{port}",
                "title": f"Prioritize parameter fuzzing and XSS follow-up on port {port}",
                "reason": "HTTP surface with discovered injection points indicates likely input-driven attack paths.",
                "confidence": 82,
                "port": port,
                "category": "enum",
            })

        if waf_map.get(port):
            suggestions.append({
                "id": f"cortex-intel-waf-strategy-{port}",
                "title": f"Use WAF-aware payload strategy on port {port}",
                "reason": f"Detected WAF ({waf_map.get(port)}) may block naive payloads and require tuned probing.",
                "confidence": 78,
                "port": port,
                "category": "intel",
            })

        profile = profile_map.get(port, {})
        profile_text = " ".join(str(v).lower() for v in profile.values()) if isinstance(profile, dict) else str(profile).lower()
        if any(token in profile_text for token in ("spa", "react", "angular", "vue", "svelte", "webpack")):
            suggestions.append({
                "id": f"cortex-enum-js-mining-{port}",
                "title": f"Deep Client-Side Mining on port {port}",
                "reason": "Modern SPA/Bundle detected. Injected Deep JS Mining Expert to recover hidden routes and internal endpoints.",
                "confidence": 90,
                "port": port,
                "category": "enum",
            })

        if "graphql" in profile_text or "apollo" in profile_text:
            suggestions.append({
                "id": f"cortex-vuln-graphql-{port}",
                "title": f"Intense GraphQL Probing on port {port}",
                "reason": "GraphQL interface detected. Requires introspection audit and object injection testing.",
                "confidence": 85,
                "port": port,
                "category": "vuln",
            })

        if _has_wp_signal(results, port):
            suggestions.append({
                "id": f"cortex-vuln-wordpress-{port}",
                "title": f"Prioritize WordPress checks on port {port}",
                "reason": "WordPress technology signals detected and existing WP module support is available.",
                "confidence": 80,
                "port": port,
                "category": "vuln",
            })

    nuclei_findings = vuln.get("nuclei", {}).get("findings", []) if isinstance(vuln.get("nuclei", {}), dict) else []
    if nuclei_findings:
        suggestions.append({
            "id": "cortex-vuln-triage-nuclei",
            "title": "Manually triage high-value nuclei findings",
            "reason": f"{len(nuclei_findings)} nuclei finding(s) require validation and exploitation context.",
            "confidence": 88,
            "port": None,
            "category": "vuln",
        })

    suggestions.extend(_service_intel_recommendations(results))
    return suggestions
