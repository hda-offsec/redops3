from datetime import datetime

from core.extensions import db
from core.models import Finding
from scan_engine.helpers.finding_schema import merge_chain_explanation, merge_field_sources


def _exists(scan_id, title):
    return Finding.query.filter_by(scan_id=scan_id, title=title, tool_source="correlation_engine").first() is not None


def _collect_signal_ids(items):
    ids = []
    for f in items:
        if isinstance(f.signal_ids, list):
            ids.extend([x for x in f.signal_ids if isinstance(x, int)])
    return sorted(set(ids))


def _add_chain(scan_id, title, description, severity="medium", confidence="medium", metadata=None, source_findings=None, reproduction=None):
    if _exists(scan_id, title):
        return None
    source_findings = source_findings or []
    signal_ids = _collect_signal_ids(source_findings)
    endpoint = next((f.endpoint for f in source_findings if getattr(f, "endpoint", None)), None)
    target = next((f.target for f in source_findings if getattr(f, "target", None)), None)
    parameter = next((f.parameter for f in source_findings if getattr(f, "parameter", None)), None)
    
    evidence_parts = []
    raw_parts = []
    source_titles = []
    import json
    for f in source_findings:
        source_titles.append(f"- **{getattr(f, 'title', 'Unknown')}** ({getattr(f, 'endpoint', 'No URL')})")
        
        ev = getattr(f, "evidence", None)
        if isinstance(ev, dict):
            try: ev = json.dumps(ev, indent=2)
            except: ev = str(ev)
        elif not isinstance(ev, str): ev = str(ev) if ev else ""
        if ev: evidence_parts.append(f"[{f.tool_source}] {ev}")
        
        ro = getattr(f, "raw_output", None)
        if isinstance(ro, dict):
            try: ro = json.dumps(ro, indent=2)
            except: ro = str(ro)
        elif not isinstance(ro, str): ro = str(ro) if ro else ""
        if ro: raw_parts.append(f"[{f.tool_source}] {ro}")
        
    combined_evidence = "\n\n".join(evidence_parts)[:4000]
    combined_raw = "\n\n".join(raw_parts)[:4000]
    
    enriched_description = f"{description}\n\n**Linked Findings Leading to this Chain:**\n" + "\n".join(source_titles)
    
    source_categories = sorted({(f.category or "general") for f in source_findings})
    related_finding_ids = [f.id for f in source_findings if getattr(f, "id", None) is not None]

    repro_text = reproduction or "Validate each source finding and pivot through the listed chain links."
    if endpoint:
        repro_text = repro_text.replace("{{endpoint}}", endpoint)
    if target:
        repro_text = repro_text.replace("{{target}}", target)

    chain_explanation = merge_chain_explanation(
        (metadata or {}).get("chain_explanation"),
        {
            "reason": description,
            "source_categories": source_categories,
            "related_signal_ids": signal_ids,
            "related_finding_ids": related_finding_ids,
            "combined_evidence_summary": (combined_evidence or description)[:400],
            "likely_next_action": repro_text,
        },
    )
    metadata_payload = dict(metadata or {"tags": ["attack_chain"]})
    metadata_payload["chain_explanation"] = chain_explanation
    metadata_payload["related_finding_ids"] = related_finding_ids
    metadata_payload["field_sources"] = merge_field_sources(
        metadata_payload.get("field_sources"),
        {"evidence": "correlation_engine", "raw_output": "correlation_engine"},
    )

    finding = Finding(
        scan_id=scan_id,
        title=title,
        description=enriched_description,
        severity=severity,
        confidence=confidence,
        tool_source="correlation_engine",
        module="correlation",
        category="attack_chain",
        target=target,
        endpoint=endpoint,
        metadata_json={**metadata_payload, "timestamp": datetime.utcnow().isoformat() + "Z"},
        evidence=combined_evidence or description,
        raw_output=combined_raw or description,
        signal_ids=signal_ids or [],
        parameter=parameter,
        reproduction=repro_text,
    )
    db.session.add(finding)
    return finding


def run_attack_chain_correlation(scan_id):
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        return 0

    titles = [f"{(f.title or '').lower()} {(f.description or '').lower()}" for f in findings]
    created = 0

    has_dir_exposure = any("directory listing" in t or ".git" in t for t in titles)
    has_backup = any("backup" in t or ".zip" in t or ".tar" in t for t in titles)
    if has_dir_exposure and has_backup:
        source = [f for f, t in zip(findings, titles) if ("directory listing" in t or ".git" in t or "backup" in t or ".zip" in t or ".tar" in t)]
        if _add_chain(
            scan_id,
            "Attack Chain: Directory Exposure + Backup Archive",
            "Correlation detected exposed directories together with backup artifacts. This chain materially increases risk of source disclosure.",
            severity="high",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["directory_exposure", "backup_archive"]},
            source_findings=source,
            reproduction=(
                "1. Naviguer dans les répertoires exposés identifiés ({{endpoint}}).\n"
                "2. Tenter de télécharger les archives de backup (.zip, .tar, .bak, etc.) détectées.\n"
                "3. Analyser le contenu localement pour extraire des fichiers de configuration ou du code source."
            )
        ):
            created += 1

    has_version_leak = any("version" in t and ("server" in t or "header" in t or "technology" in t) for t in titles)
    has_nuclei_or_cve = any("cve" in t or "nuclei" in (f.tool_source or "").lower() for f, t in zip(findings, titles))
    if has_version_leak and has_nuclei_or_cve:
        source = [f for f, t in zip(findings, titles) if ("version" in t or "cve" in t or "nuclei" in (f.tool_source or "").lower())]
        if _add_chain(
            scan_id,
            "Attack Chain: Version Leak + Known CVE Signal",
            "Correlation linked technology/version disclosure with CVE-aligned scanner output. Prioritize exploitability validation.",
            severity="high",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["version_leak", "cve_signal"]},
            source_findings=source,
        ):
            created += 1

    has_upload = any("upload" in t for t in titles)
    has_put = any("put" in t and "method" in t for t in titles)
    if has_upload and has_put:
        source = [f for f, t in zip(findings, titles) if ("upload" in t or ("put" in t and "method" in t))]
        if _add_chain(
            scan_id,
            "Attack Chain: Upload Endpoint + PUT Allowed",
            "Correlation found upload capability alongside permissive PUT handling. Validate for arbitrary file write and webshell vectors.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["upload_endpoint", "put_allowed"]},
            source_findings=source,
            reproduction=(
                "1. Tester la méthode PUT sur l'endpoint d'upload ({{endpoint}}) avec un fichier bénin.\n"
                "2. Si réussi, tenter de téléverser un fichier avec une extension exécutable ou un contenu contournant les filtres.\n"
                "3. Vérifier si le fichier est accessible et exécuté par le serveur."
            )
        ):
            created += 1

    has_js_endpoint = any("javascript" in t or "js" in (f.tool_source or "").lower() for f, t in zip(findings, titles))
    has_hidden_api = any("hidden endpoint" in t or "internal api" in t for t in titles)
    if has_js_endpoint and has_hidden_api:
        source = [f for f, t in zip(findings, titles) if ("javascript" in t or "hidden endpoint" in t or "internal api" in t or "js" in (f.tool_source or "").lower())]
        if _add_chain(
            scan_id,
            "Attack Chain: JS Discovery + Hidden API",
            "Client-side JavaScript intelligence identified hidden/internal API routes. These often bypass standard surface protections.",
            severity="medium",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["js_discovery", "hidden_api"]},
            source_findings=source,
        ):
            created += 1

    has_admin = any("admin" in t and ("panel" in t or "endpoint" in t or "login" in t) for t in titles)
    has_cors = any("cors" in t and ("misconfig" in t or "allow-origin" in t or "wildcard" in t) for t in titles)
    if has_admin and has_cors:
        source = [f for f, t in zip(findings, titles) if ("admin" in t or "cors" in t)]
        if _add_chain(
            scan_id,
            "Attack Chain: Admin Surface + CORS Misconfiguration",
            "Correlation detected exposed admin functionality combined with permissive CORS. This can enable credentialed cross-origin abuse and token exfiltration.",
            severity="high",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["admin_surface", "cors_misconfiguration"]},
            source_findings=source,
        ):
            created += 1

    has_secret = any("secret" in t or "token" in t or "api key" in t or "credential" in t for t in titles)
    has_internal = any("internal" in t or "swagger" in t or "graphql" in t or "debug" in t for t in titles)
    if has_secret and has_internal:
        source = [f for f, t in zip(findings, titles) if ("secret" in t or "token" in t or "internal" in t or "swagger" in t or "graphql" in t or "debug" in t)]
        if _add_chain(
            scan_id,
            "Attack Chain: Secret Exposure + Internal API Surface",
            "Correlation linked secret leakage and internal API exposure. This often leads to immediate authenticated access against hidden services.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["secret_exposure", "internal_api_surface"]},
            source_findings=source,
            reproduction=(
                "1. Récupérer les jetons/clés mentionnés dans les découvertes sources (voir l'onglet Findings pour les détails de l'exposition de clé).\n"
                "2. Tester manuellement si ces clés permettent d'interagir avec les APIs ou les interfaces identifiées ({{endpoint}}).\n"
                "3. Vérifier si ces accès permettent une 'escalade de privilèges' (accéder à des données d'autres clients ou des fonctions système)."
            )
        ):
            created += 1


    has_api_key = any("api key" in t or "token" in t for t in titles)
    has_privileged = any("admin" in t or "privileged" in t or "auth" in t for t in titles)
    if has_api_key and has_privileged:
        source = [f for f, t in zip(findings, titles) if ("api key" in t or "token" in t or "admin" in t or "privileged" in t or "auth" in t)]
        if _add_chain(
            scan_id,
            "Attack Chain: API Key Exposure + Privileged Surface",
            "Detected leaked token/API key indicators alongside privileged endpoints. Validate direct authenticated access and role escalation pathways.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["api_key_exposure", "privileged_surface"]},
            source_findings=source,
            reproduction=(
                "1. Récupérer les jetons/clés mentionnés dans les découvertes sources (voir l'onglet Findings pour les détails de l'exposition de clé).\n"
                "2. Tester manuellement si ces clés permettent d'interagir avec les APIs ou les interfaces identifiées ({{endpoint}}).\n"
                "3. Vérifier si ces accès permettent une 'escalade de privilèges' (accéder à des données d'autres clients ou des fonctions système)."
            )
        ):
            created += 1

    has_auth_surface = any("login" in t or "signin" in t or "authentication" in t for t in titles)
    has_js_route = any("javascript" in t or "js" in (f.tool_source or "").lower() or "hidden route" in t for f, t in zip(findings, titles))
    if has_auth_surface and has_js_route:
        source = [f for f, t in zip(findings, titles) if ("login" in t or "signin" in t or "authentication" in t or "javascript" in t or "hidden route" in t or "js" in (f.tool_source or "").lower())]
        if _add_chain(
            scan_id,
            "Attack Chain: JavaScript Routes + Authentication Surface",
            "JavaScript-mined routes overlap with authentication endpoints, increasing risk of bypass vectors and undocumented auth flows.",
            severity="high",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["js_routes", "authentication_surface"]},
            source_findings=source,
        ):
            created += 1

    has_auth_surface = any(
        (f.category or "") == "auth_surface" or "authentication surface" in t
        for f, t in zip(findings, titles)
    )
    has_sensitive_headers = any(
        (f.category or "") == "sensitive_headers" or "sensitive technology headers" in t
        for f, t in zip(findings, titles)
    )
    if has_auth_surface and has_sensitive_headers:
        source = [
            f for f, t in zip(findings, titles)
            if (f.category or "") in {"auth_surface", "sensitive_headers"}
            or "authentication surface" in t
            or "sensitive technology headers" in t
        ]
        if _add_chain(
            scan_id,
            "Attack Chain: Auth Surface + Sensitive Headers",
            "Authentication endpoints were correlated with stack-disclosing headers. This combination improves attacker fingerprinting and targeted auth abuse.",
            severity="high",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["auth_surface", "sensitive_headers"]},
            source_findings=source,
        ):
            created += 1

    has_api_surface = any((f.category or "") == "api_surface" for f in findings)
    has_token_exposure = any((f.category or "") in {"token_leakage", "jwt_exposure", "api_key_exposure"} for f in findings)
    if has_api_surface and has_token_exposure:
        source = [
            f for f in findings
            if (f.category or "") in {"api_surface", "token_leakage", "jwt_exposure", "api_key_exposure"}
        ]
        if _add_chain(
            scan_id,
            "Attack Chain: API Surface + Token Exposure",
            "API discovery telemetry overlaps with exposed token material, indicating potential direct authenticated abuse paths.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["api_surface", "token_exposure"]},
            source_findings=source,
        ):
            created += 1

    has_upload_surface = any((f.category or "") == "upload_surface" for f in findings)
    has_dangerous_methods = any((f.category or "") == "http_method_exposure" for f in findings)
    if has_upload_surface and has_dangerous_methods:
        source = [f for f in findings if (f.category or "") in {"upload_surface", "http_method_exposure"}]
        if _add_chain(
            scan_id,
            "Attack Chain: Upload Surface + Dangerous HTTP Methods",
            "Upload-capable routes were correlated with dangerous HTTP methods, increasing arbitrary file write and route abuse risk.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["upload_surface", "dangerous_http_methods"]},
            source_findings=source,
        ):
            created += 1

    has_js_routes = any((f.category or "") in {"hidden_route", "internal_api"} for f in findings)
    if has_js_routes and has_auth_surface:
        source = [f for f in findings if (f.category or "") in {"hidden_route", "internal_api", "auth_surface"}]
        if _add_chain(
            scan_id,
            "Attack Chain: JS Routes + Auth Surface",
            "JavaScript-discovered route intelligence intersects with authentication surfaces, indicating possible undocumented auth flows.",
            severity="high",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["js_routes", "auth_surface"]},
            source_findings=source,
        ):
            created += 1


    has_git = any((f.category or "") == "git_exposure" or ".git" in t for f, t in zip(findings, titles))
    has_source = any("source" in t or "repository" in t for t in titles)
    has_secrets = any((f.category or "") == "secret_exposure" or "secret" in t or "token" in t for f, t in zip(findings, titles))
    if has_git and has_source and has_secrets:
        source = [f for f, t in zip(findings, titles) if (f.category or "") in {"git_exposure", "secret_exposure"} or ".git" in t or "source" in t or "repository" in t]
        if _add_chain(
            scan_id,
            "Attack Chain: Git Exposure + Source + Secrets",
            "Detected git exposure correlated with source artifacts and secret material. This chain indicates critical credential compromise potential.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["git_exposure", "source_code", "secrets"]},
            source_findings=source,
            reproduction=(
                "1. Utiliser un outil de dump Git (ex: git-dumper) pour extraire l'historique complet de {{endpoint}}.\n"
                "2. Rechercher des secrets ou des configurations sensibles dans les versions antérieures (git log -p).\n"
                "3. Mapper les secrets trouvés aux services actifs pour confirmer l'accès."
            )
        ):
            created += 1

    has_js_api = any((f.category or "") in {"api_surface", "internal_api", "hidden_route"} or "javascript" in t for f, t in zip(findings, titles))
    has_auth_param = any((f.category or "") in {"parameter_surface", "auth_surface", "authentication_surface"} or "auth" in t or "login" in t for f, t in zip(findings, titles))
    has_token = any((f.category or "") in {"token_leakage", "jwt_exposure", "api_key_exposure", "secret_exposure"} or "token" in t or "jwt" in t for f, t in zip(findings, titles))
    if has_js_api and has_auth_param and has_token:
        source = [f for f, t in zip(findings, titles) if (f.category or "") in {"api_surface", "internal_api", "hidden_route", "parameter_surface", "auth_surface", "authentication_surface", "token_leakage", "jwt_exposure", "api_key_exposure", "secret_exposure"} or "javascript" in t or "token" in t]
        if _add_chain(
            scan_id,
            "Attack Chain: JS API + Auth Parameter + Token",
            "Correlated JavaScript/API discovery with authentication parameters and token evidence, indicating a likely authenticated abuse chain.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["js_api", "auth_parameter", "token"]},
            source_findings=source,
        ):
            created += 1

    if created:
        db.session.commit()
    return created
