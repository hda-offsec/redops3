from typing import Any, Dict, List


def _safe_text(value: Any) -> str:
    return str(value or "").lower()


def _has_wordpress_signal(results: Dict[str, Any], port: str) -> bool:
    enum = results.get("phases", {}).get("enum", {})
    vuln = results.get("phases", {}).get("vuln", {})

    whatweb_tech = enum.get("whatweb", {}).get("technologies", {})
    if isinstance(whatweb_tech, dict):
        port_tech = whatweb_tech.get(str(port), [])
        if any("wordpress" in _safe_text(t) for t in (port_tech or [])):
            return True

    vuln_wp = vuln.get("wordpress", {})
    if isinstance(vuln_wp, dict) and str(port) in vuln_wp:
        return True

    enum_tech = enum.get("tech", {})
    return "wordpress" in _safe_text(enum_tech)


def _has_api_signal(results: Dict[str, Any], port: str) -> bool:
    enum = results.get("phases", {}).get("enum", {})

    api = enum.get("api", {})
    if isinstance(api, dict):
        per_port = api.get(str(port), [])
        if per_port:
            return True
        for endpoint in api.get("discovered_endpoints", []) or []:
            if isinstance(endpoint, str) and "graphql" in endpoint.lower():
                return True

    graphql_findings = results.get("phases", {}).get("vuln", {}).get("graphql", [])
    if isinstance(graphql_findings, list) and graphql_findings:
        return True

    return False


def derive_service_intel(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    intel: List[Dict[str, Any]] = []
    open_ports = results.get("phases", {}).get("recon", {}).get("open_ports", [])

    for port_info in open_ports or []:
        port = str(port_info.get("port"))
        service = _safe_text(port_info.get("service", port_info.get("service_name", "")))
        banner = _safe_text(port_info.get("banner", ""))

        tags: List[str] = []
        confidence = 50
        notes: List[str] = []

        if "http" in service:
            tags.append("web_surface")
            confidence = max(confidence, 70)

        if port == "25" or "smtp" in service:
            tags.append("mail_surface")
            confidence = max(confidence, 70)
            notes.append("SMTP-like banner detected")

        if "postgrey" in banner or "postgrey" in service:
            tags.append("postgrey_possible")
            confidence = max(confidence, 72)

        if _has_wordpress_signal(results, port):
            tags.append("wordpress")
            confidence = max(confidence, 80)

        if _has_api_signal(results, port):
            tags.append("api_surface")
            confidence = max(confidence, 72)

        if tags:
            intel.append({
                "port": port,
                "service": service,
                "tags": tags,
                "confidence": confidence,
                "notes": "; ".join(notes) if notes else "service-derived tags",
            })

    return intel
