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
    
    display_titles = source_titles[:15]
    if len(source_titles) > 15:
        display_titles.append(f"\n_... and {len(source_titles) - 15} more linked findings._")
        
    enriched_description = f"{description}\n\n**Linked Findings Leading to this Chain:**\n" + "\n".join(display_titles)
    
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

    if severity == "critical" and confidence != "high":
        severity = "high"
        title = f"{title} (Unvalidated)"
        
    # V12: Label unvalidated hypotheses as candidates
    if confidence == "low" or "[unverified]" in description.lower():
        title = f"Candidate Correlation: {title}"
        if severity in ["critical", "high"]:
            severity = "medium"

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
        metadata_json={**metadata_payload, "timestamp": datetime.utcnow().isoformat() + "Z", "verified": confidence == "high"},
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

    # Group findings by target (host/domain)
    # We use the target field, but if empty, we fall back to the base domain of the endpoint
    from urllib.parse import urlparse
    grouped = {}
    for f in findings:
        host = f.target
        if not host and f.endpoint:
            try: host = urlparse(f.endpoint).netloc
            except: pass
        if not host: host = "global"
        
        if host not in grouped: grouped[host] = []
        grouped[host].append(f)

    created = 0

    for host, host_findings in grouped.items():
        titles = [f"{(f.title or '').lower()} {(f.description or '').lower()}" for f in host_findings]

        # 1. Directory Exposure + Backup
        has_dir_exposure = any("directory listing" in t or ".git" in t for t in titles)
        has_backup = any("backup" in t or ".zip" in t or ".tar" in t for t in titles)
        if has_dir_exposure and has_backup:
            source = [f for f, t in zip(host_findings, titles) if ("directory listing" in t or ".git" in t or "backup" in t or ".zip" in t or ".tar" in t)]
            if _add_chain(
                scan_id,
                f"Attack Chain: Directory Exposure + Backup ({host})",
                f"Detected exposed directories together with backup archives on **{host}**. This chain materially increases risk of source code and sensitive data disclosure.",
                severity="high",
                confidence="high",
                metadata={"tags": ["attack_chain"], "target": host},
                source_findings=source,
            ):
                created += 1

        # 2. Version Leak + CVE
        has_version_leak = any("version" in t and ("server" in t or "header" in t or "technology" in t) for t in titles)
        has_nuclei_or_cve = any("cve" in t or "nuclei" in (f.tool_source or "").lower() for f, t in zip(host_findings, titles))
        if has_version_leak and has_nuclei_or_cve:
            source = [f for f, t in zip(host_findings, titles) if ("version" in t or "cve" in t or "nuclei" in (f.tool_source or "").lower())]
            if _add_chain(
                scan_id,
                f"Attack Chain: Version Leak + Known CVE ({host})",
                f"Correlated technology/version disclosure with CVE-aligned scanner outputs on **{host}**. Prioritize exploitability validation for confirmed vulnerabilities.",
                severity="high",
                confidence="medium",
                source_findings=source,
            ):
                created += 1

        # 3. Secret Exposure + Internal API
        def is_leaked_secret(f):
            cat = (getattr(f, 'category', '') or '').lower()
            title = (getattr(f, 'title', '') or '').lower()
            confidence = str(getattr(f, "confidence", "") or "").lower()
            has_secret_marker = any(x in cat for x in ["secret", "token", "key"]) or any(
                token in title for token in ["api key", "token", "secret", "jwt"]
            )
            if not has_secret_marker:
                return False
            # Correlation should not require strict high confidence;
            # medium/high lineage-backed secret signals are sufficient for chain generation.
            return confidence in {"medium", "high", "certain", ""}

        has_secret = any(is_leaked_secret(f) for f in host_findings)
        has_internal = any("internal" in t or "swagger" in t or "graphql" in t or "debug" in t for t in titles)
        if has_secret and has_internal:
            source = [f for f, t in zip(host_findings, titles) if (is_leaked_secret(f) or any(x in t for x in ["internal", "swagger", "graphql", "debug"]))]
            chain_title = "Attack Chain: Secret Exposure + Internal API Surface"
            if host != "global":
                chain_title = f"{chain_title} ({host})"
            if _add_chain(
                scan_id,
                chain_title,
                f"Correlated secret leakage with internal API exposure on **{host}**. This path often leads to immediate authenticated access against non-public services.",
                severity="critical",
                confidence="high",
                source_findings=source,
                metadata={"tags": ["attack_chain"], "target": host},
            ):
                created += 1

        # 4. JS API + Auth Parameter + Token
        has_js_api = any((f.category or "") in {"api_surface", "internal_api", "hidden_route"} or "javascript" in t for f, t in zip(host_findings, titles))
        has_auth_param = any((f.category or "") in {"parameter_surface", "auth_surface", "authentication_surface"} or "auth" in t or "login" in t for f, t in zip(host_findings, titles))
        has_token = any((f.category or "") in {"token_leakage", "jwt_exposure", "api_key_exposure", "secret_exposure"} or "token" in t or "jwt" in t for f, t in zip(host_findings, titles))
        
        if has_js_api and has_auth_param and has_token:
            source = [f for f, t in zip(host_findings, titles) if (f.category or "") in {"api_surface", "internal_api", "hidden_route", "parameter_surface", "auth_surface", "authentication_surface", "token_leakage", "jwt_exposure", "api_key_exposure", "secret_exposure"} or "javascript" in t or "token" in t]
            if _add_chain(
                scan_id,
                f"Attack Chain: JS API + Auth Params + Token ({host})",
                f"Combined discovery of API routes, authentication parameters, and token evidence on **{host}**. High likelihood of authenticated abuse path.",
                severity="critical",
                confidence="high",
                source_findings=source,
            ):
                created += 1

    if created:
        db.session.commit()
    return created
