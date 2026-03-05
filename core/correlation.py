from core.extensions import db
from core.models import Finding


def _exists(scan_id, title):
    return Finding.query.filter_by(scan_id=scan_id, title=title, tool_source="correlation_engine").first() is not None


def _add_chain(scan_id, title, description, severity="medium", confidence="medium", metadata=None):
    if _exists(scan_id, title):
        return None
    finding = Finding(
        scan_id=scan_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        tool_source="correlation_engine",
        module="correlation",
        category="attack_chain",
        metadata_json=metadata or {"tags": ["attack_chain"]},
        evidence=description,
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
        if _add_chain(
            scan_id,
            "Attack Chain: Directory Exposure + Backup Archive",
            "Correlation detected exposed directories together with backup artifacts. This chain materially increases risk of source disclosure.",
            severity="high",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["directory_exposure", "backup_archive"]},
        ):
            created += 1

    has_version_leak = any("version" in t and ("server" in t or "header" in t or "technology" in t) for t in titles)
    has_nuclei_or_cve = any("cve" in t or "nuclei" in (f.tool_source or "").lower() for f, t in zip(findings, titles))
    if has_version_leak and has_nuclei_or_cve:
        if _add_chain(
            scan_id,
            "Attack Chain: Version Leak + Known CVE Signal",
            "Correlation linked technology/version disclosure with CVE-aligned scanner output. Prioritize exploitability validation.",
            severity="high",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["version_leak", "cve_signal"]},
        ):
            created += 1

    has_upload = any("upload" in t for t in titles)
    has_put = any("put" in t and "method" in t for t in titles)
    if has_upload and has_put:
        if _add_chain(
            scan_id,
            "Attack Chain: Upload Endpoint + PUT Allowed",
            "Correlation found upload capability alongside permissive PUT handling. Validate for arbitrary file write and webshell vectors.",
            severity="critical",
            confidence="high",
            metadata={"tags": ["attack_chain"], "chain": ["upload_endpoint", "put_allowed"]},
        ):
            created += 1

    has_js_endpoint = any("javascript" in t or "js" in (f.tool_source or "").lower() for f, t in zip(findings, titles))
    has_hidden_api = any("hidden endpoint" in t or "internal api" in t for t in titles)
    if has_js_endpoint and has_hidden_api:
        if _add_chain(
            scan_id,
            "Attack Chain: JS Discovery + Hidden API",
            "Client-side JavaScript intelligence identified hidden/internal API routes. These often bypass standard surface protections.",
            severity="medium",
            confidence="medium",
            metadata={"tags": ["attack_chain"], "chain": ["js_discovery", "hidden_api"]},
        ):
            created += 1

    if created:
        db.session.commit()
    return created
