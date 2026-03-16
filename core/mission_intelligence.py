import re
from datetime import datetime
from urllib.parse import urlparse, parse_qsl
import ipaddress

from scan_engine.helpers.finding_schema import normalize_finding_shape


from scan_engine.helpers.passive_intel_engine import (
    AssetDiscoveryEngine,
    SecretsIntelligenceEngine,
    PassiveIntelligenceEngine,
)


from core.models import (
    Asset,
    AssetTargetLink,
    AuthIdentityMap,
    Finding,
    Mission,
    OperatorAction,
    ReplayVaultEntry,
    Scan,
    Signal,
    Target,
    db,
)
from core.quality_metrics import build_quality_metrics


MISSION_STATES = {"draft", "active", "paused", "completed", "archived"}
OBJECTIVE_TYPES = {
    "authenticated_api_path",
    "cloud_credential_path",
    "source_code_leak_path",
    "identity_privilege_path",
    "data_exfiltration_path",
}
ACTION_STATUSES = {"suggested", "reviewed", "queued", "executed", "blocked", "invalidated", "skipped"}

_ALLOWED_STATUS_TRANSITIONS = {
    "suggested": {"reviewed", "blocked", "invalidated", "skipped"},
    "reviewed": {"queued", "blocked", "invalidated", "skipped"},
    "queued": {"executed", "blocked", "invalidated", "skipped"},
    "blocked": {"reviewed", "queued", "invalidated", "skipped"},
    "skipped": {"reviewed", "invalidated"},
    "invalidated": {"reviewed"},
    "executed": set(),
}


def normalize_mission_status(status):
    normalized = str(status or "draft").strip().lower()
    return normalized if normalized in MISSION_STATES else "draft"


def normalize_objective_type(objective_type):
    value = str(objective_type or "").strip().lower()
    return value if value in OBJECTIVE_TYPES else None


def _as_int_list(values):
    if not isinstance(values, list):
        return []
    out = []
    seen = set()
    for item in values:
        try:
            value = int(item)
        except (TypeError, ValueError):
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _serialize_operator_action(action):
    metadata = action.metadata_json if isinstance(action.metadata_json, dict) else {}
    return {
        "id": action.id,
        "mission_id": action.mission_id,
        "action_key": action.action_key,
        "objective_type": action.objective_type,
        "action_type": action.action_type,
        "title": action.title,
        "description": action.description,
        "rationale": action.rationale,
        "status": action.status,
        "confidence": round(float(action.confidence or 0.0), 4),
        "attack_priority": action.attack_priority,
        "estimated_value": action.estimated_value,
        "estimated_complexity": action.estimated_complexity,
        "related_asset_ids": _as_int_list(action.related_asset_ids),
        "related_target_ids": _as_int_list(action.related_target_ids),
        "related_finding_ids": _as_int_list(action.related_finding_ids),
        "related_signal_ids": _as_int_list(action.related_signal_ids),
        "required_conditions": sorted(str(x) for x in (action.required_conditions or []) if str(x).strip()),
        "blocker_summary": metadata.get("blocker_summary") if isinstance(metadata.get("blocker_summary"), dict) else {},
        "evidence_summary": action.evidence_summary,
        "metadata": metadata,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "updated_at": action.updated_at.isoformat() if action.updated_at else None,
    }


def _serialize_finding(finding):
    metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
    return {
        "id": finding.id,
        "id_stable": finding.id_stable,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "title": finding.title,
        "category": finding.category,
        "tool_source": finding.tool_source,
        "tool": finding.tool,
        "module": finding.module,
        "target": finding.target,
        "endpoint": finding.endpoint,
        "signal_ids": _as_int_list(finding.signal_ids),
        "metadata": metadata,
    }


def ensure_asset_for_target(mission_id, target, source="mission_binding"):
    if not mission_id or target is None:
        return None
    identifier = str(getattr(target, "identifier", "") or "").strip().lower()
    if not identifier:
        return None
    asset = Asset.query.filter_by(mission_id=mission_id, identifier=identifier).first()
    if asset:
        return asset
    asset = Asset(
        mission_id=mission_id,
        type="domain",
        identifier=identifier,
        label=getattr(target, "identifier", identifier),
        confidence="medium",
        source=source,
        provenance={"source": source, "observation_only": True},
        tags=["auto-bound"],
    )
    db.session.add(asset)
    db.session.flush()
    return asset


def link_asset_target(asset_id, target_id, source="mission_binding", link_type="observed"):
    if not asset_id or not target_id:
        return None
    existing = AssetTargetLink.query.filter_by(asset_id=asset_id, target_id=target_id).first()
    if existing:
        return existing
    link = AssetTargetLink(
        asset_id=asset_id,
        target_id=target_id,
        source=source,
        link_type=link_type,
        confidence="medium",
        metadata_json={"source": source, "observation_only": True},
    )
    db.session.add(link)
    db.session.flush()
    return link


def _collect_mission_rows(mission_id, limit=100):
    mission = Mission.query.get_or_404(mission_id)
    target_ids = [t.id for t in Target.query.filter_by(mission_id=mission_id).order_by(Target.id.asc()).all()]
    scans = Scan.query.filter(Scan.target_id.in_(target_ids)).order_by(Scan.id.desc()).limit(max(limit, 1)).all() if target_ids else []
    scan_ids = [s.id for s in scans]

    findings_q = Finding.query.filter(Finding.scan_id.in_(scan_ids)) if scan_ids else Finding.query.filter_by(id=-1)
    findings = findings_q.order_by(Finding.id.desc()).limit(max(limit * 3, 1)).all()

    signals_q = Signal.query.filter(Signal.scan_id.in_(scan_ids)) if scan_ids else Signal.query.filter_by(id=-1)
    signals = signals_q.order_by(Signal.id.desc()).limit(max(limit * 3, 1)).all()

    replay_entries = ReplayVaultEntry.query.filter_by(mission_id=mission_id).order_by(ReplayVaultEntry.id.desc()).limit(max(limit, 1)).all()
    auth_observations = AuthIdentityMap.query.filter_by(mission_id=mission_id).order_by(AuthIdentityMap.id.desc()).limit(max(limit, 1)).all()
    operator_actions = OperatorAction.query.filter_by(mission_id=mission_id).order_by(OperatorAction.id.desc()).limit(max(limit, 1)).all()

    return mission, findings, signals, replay_entries, auth_observations, operator_actions


def aggregate_mission_quality_metrics(mission_id, limit=100):
    mission, findings, _signals, replay_entries, auth_observations, operator_actions = _collect_mission_rows(mission_id, limit=limit)
    objective_paths = [
        item.metadata_json
        for item in findings
        if isinstance(item.metadata_json, dict)
        and item.category == "objective_path"
        and item.metadata_json.get("objective_type")
    ]
    next_steps = [
        item.metadata_json
        for item in findings
        if isinstance(item.metadata_json, dict)
        and item.category == "next_step"
    ]
    return {
        "mission_id": mission.id,
        "replay_observations": len(replay_entries),
        "auth_identity_observations": len(auth_observations),
        **build_quality_metrics(
            findings=[_serialize_finding(item) for item in findings],
            operator_actions=[_serialize_operator_action(item) for item in operator_actions],
            objectives=mission.objectives_json or [],
            objective_paths=objective_paths,
            next_steps=next_steps,
        ),
    }


def aggregate_mission_intelligence(mission_id, limit=100):
    mission, findings, signals, replay_entries, auth_observations, operator_actions = _collect_mission_rows(mission_id, limit=limit)

    objective_paths = []
    next_steps = []
    for finding in findings:
        if not isinstance(finding.metadata_json, dict):
            continue
        if finding.category == "objective_path":
            objective_paths.append(finding.metadata_json)
        elif finding.category == "next_step":
            next_steps.append(finding.metadata_json)

    return {
        "mission": {
            "id": mission.id,
            "name": mission.name,
            "status": normalize_mission_status(mission.status),
            "priority": str(mission.priority or "medium").lower(),
            "scope_summary": mission.scope_summary,
            "tags": sorted({str(tag).strip().lower() for tag in (mission.tags_json or []) if str(tag).strip()}),
            "objectives": mission.objectives_json or [],
        },
        "counts": {
            "findings": len(findings),
            "signals": len(signals),
            "replay_observations": len(replay_entries),
            "auth_identity_observations": len(auth_observations),
            "operator_actions": len(operator_actions),
        },
        "findings": [_serialize_finding(item) for item in findings],
        "operator_actions": [_serialize_operator_action(item) for item in operator_actions],
        "objective_paths": sorted(
            objective_paths,
            key=lambda item: (
                str(item.get("objective_type") or ""),
                str(item.get("attack_priority") or ""),
                str(item.get("title") or ""),
            ),
        ),
        "recommended_next_steps": sorted(
            next_steps,
            key=lambda item: (
                str(item.get("attack_priority") or ""),
                str(item.get("title") or ""),
            ),
        ),
        "quality_metrics": aggregate_mission_quality_metrics(mission_id, limit=limit),
    }


def update_operator_action_status(mission_id, action_id, next_status):
    status = str(next_status or "").strip().lower()
    if status not in ACTION_STATUSES:
        return None, "invalid_transition"

    action = OperatorAction.query.filter_by(id=action_id, mission_id=mission_id).first()
    if not action:
        return None, "not_found"

    current_status = str(action.status or "suggested").strip().lower()
    if status != current_status and status not in _ALLOWED_STATUS_TRANSITIONS.get(current_status, set()):
        return None, "invalid_transition"

    action.status = status
    db.session.commit()
    return _serialize_operator_action(action), None
