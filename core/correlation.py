from core.extensions import db
from core.models import Finding


def _exists(scan_id, title):
    return Finding.query.filter_by(scan_id=scan_id, title=title, tool_source="correlation_engine").first() is not None


def _collect_signal_ids(items):
    ids = []
    for f in items:
        if isinstance(f.signal_ids, list):
            ids.extend([x for x in f.signal_ids if isinstance(x, int)])
    return sorted(set(ids))


def _add_chain(scan_id, title, description, severity="medium", confidence="medium", metadata=None, source_findings=None):
    if _exists(scan_id, title):
        return None
    source_findings = source_findings or []
    signal_ids = _collect_signal_ids(source_findings)
    endpoint = next((f.endpoint for f in source_findings if getattr(f, "endpoint", None)), None)
    target = next((f.target for f in source_findings if getattr(f, "target", None)), None)
    finding = Finding(
        scan_id=scan_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        tool_source="correlation_engine",
        module="correlation",
        category="attack_chain",
        target=target,
        endpoint=endpoint,
        metadata_json=metadata or {"tags": ["attack_chain"]},
        evidence=description,
        signal_ids=signal_ids or None,
        reproduction="Validate each source finding and pivot through the listed chain links.",
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

    if created:
        db.session.commit()
    return created
