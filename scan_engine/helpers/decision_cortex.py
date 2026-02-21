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

        # --- EXPERT ADDITIONS: Spring Boot, Firebase, Docker ---
        if any(tok in profile_text for tok in ("spring", "actuator", "javamelody")):
            suggestions.append({
                "id": f"cortex-vuln-spring-actuator-{port}",
                "title": f"Spring Actuator Audit on port {port}",
                "reason": "Spring-like components or Actuators detected. High risk of info-leaks or RCE via env/heapdump.",
                "confidence": 92,
                "port": port,
                "category": "vuln",
            })

        if any(tok in profile_text for tok in ("firebase", "firestore", "google-services")):
            suggestions.append({
                "id": f"cortex-vuln-firebase-{port}",
                "title": f"Firebase Database Audit on port {port}",
                "reason": "Firebase SDK or indicators detected. Check for misconfigured (publicly readable) database rules.",
                "confidence": 95,
                "port": port,
                "category": "vuln",
            })

        if any(tok in profile_text for tok in ("docker-api", "containerd", "kubernetes")):
             suggestions.append({
                "id": f"cortex-vuln-container-exposure-{port}",
                "title": f"Container API Exposure Check on port {port}",
                "reason": "Container management signatures detected. High critical risk of full host takeover.",
                "confidence": 98,
                "port": port,
                "category": "vuln",
            })

        # --- V6: ADVANCED EXPERT SUGGESTIONS ---
        if _is_http_like(service, port):
            suggestions.append({
                "id": f"cortex-vuln-smuggling-{port}",
                "title": f"HTTP Smuggling Audit on port {port}",
                "reason": "Perform desync probes to detect CL.TE/TE.CL vulnerabilities on this HTTP surface.",
                "confidence": 75,
                "port": port,
                "category": "vuln",
            })
            suggestions.append({
                "id": f"cortex-vuln-vhost-{port}",
                "title": f"Virtual Host Brute-Force on port {port}",
                "reason": "Probe for unmapped subdomains or internal environments via Host header fuzzing.",
                "confidence": 70,
                "port": port,
                "category": "vuln",
            })

        if "eyj" in profile_text or "spa" in profile_text or "auth" in profile_text:
            suggestions.append({
                "id": f"cortex-vuln-jwt-{port}",
                "title": f"JWT Security Audit on port {port}",
                "reason": "Tokens or modern JS architecture detected. Auditing for algorithm confusion, none-alg, and kid injection.",
                "confidence": 88,
                "port": port,
                "category": "vuln",
            })

        if any(tok in profile_text for tok in ("coldfusion", "aem", "adobe", "telerik")):
            suggestions.append({
                "id": f"cortex-vuln-enterprise-{port}",
                "title": f"Enterprise Stack Audit on port {port}",
                "reason": "Found signatures of high-value enterprise tech (AEM/ColdFusion). Initiating specialized exploit probes.",
                "confidence": 95,
                "port": port,
                "category": "vuln",
            })

        # Check for dependency files in Katana results
        katana_results = enum.get("katana", {}).get(port, [])
        if any(("package.json" in str(u) or "requirements.txt" in str(u)) for u in katana_results):
             suggestions.append({
                "id": f"cortex-vuln-dependency-{port}",
                "title": f"Supply Chain Security Check on port {port}",
                "reason": "Dependency manifest files exposed. Auditing for Dependency Confusion and malicious package hijacking.",
                "confidence": 90,
                "port": port,
                "category": "vuln",
            })

        if len(inj_map.get(port, []) or []) > 0:
            suggestions.append({
                "id": f"cortex-vuln-ssti-{port}",
                "title": f"Polyglot SSTI Probe on port {port}",
                "reason": "Widespread parameter reflection observed. Running engine-specific template injection probes.",
                "confidence": 84,
                "port": port,
                "category": "vuln",
            })

        # --- WAVE 2: STRATEGIC LOGIC & INFRA RECOMMENDATIONS ---
        if any(tok in profile_text for tok in ("oauth", "openid", "callback", "sso", "auth0")):
             suggestions.append({
                "id": f"cortex-vuln-oauth-{port}",
                "title": f"OAuth/OIDC Security Audit on port {port}",
                "reason": "Authentication flow signatures detected. Auditing for Redirect URI bypass and state-CSRF flaws.",
                "confidence": 92,
                "port": port,
                "category": "vuln",
            })

        if any(tok in profile_text for tok in ("mongodb", "nodejs", "express", "mongoose", "nosql")):
            suggestions.append({
                "id": f"cortex-vuln-nosql-{port}",
                "title": f"NoSQL Injection Audit on port {port}",
                "reason": "Node.js/NoSQL stack identified. Probing for MongoDB operator injection and login bypass.",
                "confidence": 88,
                "port": port,
                "category": "vuln",
            })

        if any(tok in profile_text for tok in ("cloudflare", "varnish", "nginx", "akamai", "fastly")):
             suggestions.append({
                "id": f"cortex-vuln-cache-{port}",
                "title": f"Web Cache Integrity Audit on port {port}",
                "reason": "CDN or advanced reverse proxy detected. Auditing for Cache Poisoning and Deception.",
                "confidence": 80,
                "port": port,
                "category": "vuln",
            })

        if "api" in profile_text or "json" in profile_text:
             suggestions.append({
                "id": f"cortex-vuln-logic-{port}",
                "title": f"Business Logic & Mass Assignment Audit",
                "reason": "API-heavy surface detected. Testing for auto-binding flaws and Parameter Pollution.",
                "confidence": 85,
                "port": port,
                "category": "vuln",
            })

        # Check for open infra ports from recon data
        open_ports = [p.get('port') for p in enum.get('recon', {}).get('open_ports', [])]
        infra_ports = [6379, 11211, 2375, 27017, 9200]
        if any(p in open_ports for p in infra_ports):
            suggestions.append({
                "id": "cortex-vuln-infra-exposure",
                "title": "Infrastructure Exposure Audit",
                "reason": "Identified open administrative or data-layer ports (Redis/Docker/NoSQL). Probing for unauth access.",
                "confidence": 98,
                "category": "vuln",
            })

    # Historic Surface Priority
    if results.get("phases", {}).get("osint", {}).get("historic_urls"):
        suggestions.append({
            "id": "cortex-enum-historic-validation",
            "title": "Validate Historic Attack Surface",
            "reason": "Discovery found legacy URLs in archive.org. High potential for forgotten/vulnerable endpoints.",
            "confidence": 85,
            "port": None,
            "category": "recon",
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
