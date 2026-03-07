from collections import defaultdict

from sqlalchemy import func

from core.extensions import db
from core.models import Asset, AssetTargetLink, Finding, Mission, Scan, Target


OBJECTIVE_TYPES = {
    "admin_access",
    "authenticated_api_access",
    "source_code_leak",
    "cloud_credential_access",
    "internal_pivot",
    "external_recon",
}


def _latest_scan_ids_for_targets(target_ids):
    if not target_ids:
        return []
    rows = (
        db.session.query(func.max(Scan.id))
        .filter(Scan.target_id.in_(target_ids))
        .group_by(Scan.target_id)
        .all()
    )
    return [row[0] for row in rows if row and row[0] is not None]


def link_asset_target(asset, target, link_type="observed", confidence="medium", source=None, metadata=None):
    existing = AssetTargetLink.query.filter_by(asset_id=asset.id, target_id=target.id).first()
    if existing:
        return existing
    link = AssetTargetLink(
        asset_id=asset.id,
        target_id=target.id,
        link_type=link_type,
        confidence=confidence,
        source=source,
        metadata_json=metadata if isinstance(metadata, dict) else None,
    )
    db.session.add(link)
    db.session.flush()
    return link


def ensure_asset_for_target(mission_id, target, source="target_submission"):
    if not mission_id or not target:
        return None
    identifier = (target.identifier or "").strip().lower()
    if not identifier:
        return None
    asset = Asset.query.filter_by(mission_id=mission_id, identifier=identifier).first()
    if not asset:
        asset = Asset(
            mission_id=mission_id,
            type="domain",
            identifier=identifier,
            label=target.identifier,
            confidence="medium",
            source=source,
            provenance={"source": source, "target_id": target.id},
            tags=["target_linked"],
        )
        db.session.add(asset)
        db.session.flush()
    link_asset_target(asset, target, source=source, metadata={"auto_linked": True})
    return asset


def _serialize_finding(f):
    metadata = f.metadata_json if isinstance(f.metadata_json, dict) else {}
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "id_stable": f.id_stable,
        "title": f.title,
        "severity": f.severity,
        "confidence": f.confidence,
        "category": f.category,
        "target": f.target,
        "endpoint": f.endpoint,
        "signal_ids": f.signal_ids or [],
        "metadata": metadata,
        "evidence": f.evidence,
        "raw_output": f.raw_output,
    }


def synthesize_cross_asset_paths(mission_id):
    mission = Mission.query.get(mission_id)
    if not mission:
        return []
    paths = []
    target_ids = [t.id for t in mission.targets]
    latest_ids = _latest_scan_ids_for_targets(target_ids)
    if not latest_ids:
        return []
    findings = Finding.query.filter(Finding.scan_id.in_(latest_ids)).all()

    by_scan = defaultdict(list)
    for f in findings:
        by_scan[f.scan_id].append(f)

    all_findings = findings

    def build(category, title, rationale, related):
        related_asset_ids = sorted(
            {
                link.asset_id
                for f in related
                for link in (f.scan.target.asset_links if f.scan and f.scan.target else [])
            }
        )
        related_target_ids = sorted(
            {f.scan.target_id for f in related if f.scan and f.scan.target_id is not None}
        )
        related_finding_ids = sorted({f.id for f in related if f.id is not None})
        related_signal_ids = sorted(
            {
                sid
                for f in related
                for sid in ((f.signal_ids or []) if isinstance(f.signal_ids, list) else [])
                if isinstance(sid, int)
            }
        )
        if len(related_asset_ids) < 2:
            return None
        return {
            "category": category,
            "title": title,
            "severity": "high",
            "confidence": "medium",
            "rationale": rationale,
            "attack_priority": "high",
            "related_asset_ids": related_asset_ids,
            "related_target_ids": related_target_ids,
            "related_finding_ids": related_finding_ids,
            "related_signal_ids": related_signal_ids,
            "supporting_findings": [_serialize_finding(f) for f in related],
        }

    secret_findings = [f for f in all_findings if (f.category or "") in {"token_leakage", "jwt_exposure", "api_key_exposure"} or "token" in ((f.title or "") + " " + (f.description or "")).lower()]
    api_surface = [f for f in all_findings if (f.category or "") in {"api_surface", "auth_surface"}]
    if secret_findings and api_surface:
        combined = secret_findings + api_surface
        item = build(
            "objective_path",
            "Objective Path: Cross-Asset Token Reuse Toward API Access",
            "Token or secret leakage on one asset and API/authentication surface on a separate asset indicate a mission-level authenticated access path.",
            combined,
        )
        if item:
            paths.append(item)

    js_endpoint = [f for f in all_findings if (f.category or "") in {"js_route_discovery", "api_surface"} or "javascript" in ((f.title or "") + " " + (f.description or "")).lower()]
    admin_surface = [f for f in all_findings if "admin" in ((f.title or "") + " " + (f.description or "")).lower() or (f.category or "") == "auth_surface"]
    if js_endpoint and admin_surface:
        combined = js_endpoint + admin_surface
        item = build(
            "attack_chain",
            "Attack Chain: JS Recon to Cross-Asset Admin Surface",
            "Evidence links JavaScript or API route discovery to privileged/admin interfaces across multiple assets.",
            combined,
        )
        if item:
            paths.append(item)

    cloud_refs = [f for f in all_findings if (f.category or "") in {"cloud_asset", "cloud_exposure", "cloud_storage_exposure"} or "s3" in ((f.title or "") + " " + (f.description or "")).lower()]
    if cloud_refs and len({f.scan.target_id for f in cloud_refs if f.scan}) > 1:
        item = build(
            "mission_prep",
            "Mission Prep: Cloud Reference Expands Perimeter",
            "Multiple assets reference cloud resources, indicating expanded mission perimeter and cross-asset pivot opportunities.",
            cloud_refs,
        )
        if item:
            paths.append(item)

    return paths


def aggregate_mission_intelligence(mission_id, limit=10):
    mission = Mission.query.get_or_404(mission_id)
    targets = Target.query.filter_by(mission_id=mission.id).all()
    target_ids = [t.id for t in targets]
    latest_scan_ids = _latest_scan_ids_for_targets(target_ids)
    scans = Scan.query.filter(Scan.id.in_(latest_scan_ids)).all() if latest_scan_ids else []

    findings = Finding.query.filter(Finding.scan_id.in_(latest_scan_ids)).all() if latest_scan_ids else []
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    top_findings = sorted(
        findings,
        key=lambda f: (severity_rank.get((f.severity or "info").lower(), 0), f.id or 0),
        reverse=True,
    )[:limit]

    objective_paths = [
        _serialize_finding(f)
        for f in findings
        if (f.category or "") in {"objective_path", "mission_prep", "attack_chain", "next_step"}
    ]

    cross_asset_paths = synthesize_cross_asset_paths(mission.id)

    assets = Asset.query.filter_by(mission_id=mission.id).order_by(Asset.created_at.asc()).all()

    return {
        "mission": {
            "id": mission.id,
            "name": mission.name,
            "description": mission.description,
            "status": mission.status,
            "objectives": mission.objectives_json or [],
            "created_at": mission.created_at.isoformat() if mission.created_at else None,
        },
        "assets": [
            {
                "id": a.id,
                "type": a.type,
                "identifier": a.identifier,
                "label": a.label,
                "confidence": a.confidence,
                "source": a.source,
                "provenance": a.provenance,
                "tags": a.tags or [],
                "target_ids": sorted({l.target_id for l in a.target_links}),
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in assets
        ],
        "targets": [
            {
                "id": t.id,
                "identifier": t.identifier,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "asset_ids": sorted({link.asset_id for link in t.asset_links}),
            }
            for t in targets
        ],
        "latest_scan_ids": latest_scan_ids,
        "findings_total": len(findings),
        "top_findings": [_serialize_finding(f) for f in top_findings],
        "objective_paths": objective_paths[:limit],
        "cross_asset_paths": cross_asset_paths,
        "next_steps": [
            p
            for p in cross_asset_paths
            if p.get("category") in {"mission_prep", "objective_path", "attack_chain"}
        ][:limit],
        "graph_summary": {
            "node_count": len(scans) + len(assets) + len(targets) + len(findings),
            "edge_count": len(targets) + sum(len(a.target_links) for a in assets),
        },
    }
