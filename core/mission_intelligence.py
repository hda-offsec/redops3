import re
import hashlib
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
    validation = metadata.get("validation") if isinstance(metadata.get("validation"), dict) else {}
    reproducibility = metadata.get("reproducibility") if isinstance(metadata.get("reproducibility"), dict) else {}
    references = metadata.get("references") if isinstance(metadata.get("references"), list) else []
    command = (
        validation.get("command")
        or reproducibility.get("command")
        or finding.repro_command
        or finding.reproduction
        or ""
    )
    impact = (
        metadata.get("impact")
        or metadata.get("impact_area")
        or (finding.risk_scorecard.get("impact") if isinstance(finding.risk_scorecard, dict) else None)
    )
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "id_stable": finding.id_stable,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "title": finding.title,
        "description": finding.description,
        "category": finding.category,
        "tool_source": finding.tool_source,
        "tool": finding.tool,
        "module": finding.module,
        "target": finding.target,
        "endpoint": finding.endpoint,
        "parameter": finding.parameter,
        "payload": finding.payload,
        "evidence": finding.evidence,
        "raw_output": finding.raw_output,
        "reproduction": finding.reproduction,
        "repro_command": finding.repro_command,
        "command": command,
        "impact": impact,
        "remediation": finding.remediation,
        "request": finding.request,
        "response": finding.response,
        "references": [str(item) for item in references if str(item).strip()],
        "result_state": metadata.get("result_state"),
        "risk_scorecard": finding.risk_scorecard if isinstance(finding.risk_scorecard, dict) else {},
        "signal_ids": _as_int_list(finding.signal_ids),
        "metadata": metadata,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
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


def link_asset_target(asset_id_or_obj, target_id_or_obj, source="mission_binding", link_type="observed", metadata=None):
    asset_id = int(getattr(asset_id_or_obj, "id", asset_id_or_obj) or 0)
    target_id = int(getattr(target_id_or_obj, "id", target_id_or_obj) or 0)
    if not asset_id or not target_id:
        return None
    existing = AssetTargetLink.query.filter_by(asset_id=asset_id, target_id=target_id).first()
    if existing:
        if isinstance(metadata, dict) and metadata:
            existing_meta = existing.metadata_json if isinstance(existing.metadata_json, dict) else {}
            merged = {**existing_meta, **metadata}
            if merged != existing_meta:
                existing.metadata_json = merged
        return existing
    metadata_payload = {"source": source, "observation_only": True}
    if isinstance(metadata, dict):
        for key, value in metadata.items():
            if value not in (None, ""):
                metadata_payload[key] = value
    link = AssetTargetLink(
        asset_id=asset_id,
        target_id=target_id,
        source=source,
        link_type=link_type,
        confidence="medium",
        metadata_json=metadata_payload,
    )
    db.session.add(link)
    db.session.flush()
    return link


def is_valid_action_transition(current_status, next_status):
    current = str(current_status or "suggested").strip().lower()
    target = str(next_status or "").strip().lower()
    if target not in ACTION_STATUSES:
        return False
    if target == current:
        return True
    return target in _ALLOWED_STATUS_TRANSITIONS.get(current, set())


def _severity_rank(value):
    sev = str(value or "info").strip().lower()
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(sev, 1)


def _priority_from_severity(value):
    sev = str(value or "info").strip().lower()
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


def _value_from_severity(value):
    sev = str(value or "info").strip().lower()
    if sev in {"critical", "high"}:
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


def _complexity_from_category(category):
    cat = str(category or "").strip().lower()
    if any(token in cat for token in ("rce", "deserialization", "supply_chain", "auth")):
        return "high"
    if any(token in cat for token in ("ssrf", "sqli", "xss", "token", "secret")):
        return "medium"
    return "low"


def _extract_related_ids(finding):
    related_signal_ids = sorted(
        {
            int(item)
            for item in (finding.signal_ids if isinstance(finding.signal_ids, list) else [])
            if isinstance(item, int)
        }
    )
    related_asset_ids = set()
    related_target_ids = set()

    scan = getattr(finding, "scan", None)
    if scan is not None:
        target_id = getattr(scan, "target_id", None)
        if isinstance(target_id, int):
            related_target_ids.add(target_id)
        scan_target = getattr(scan, "target", None)
        if scan_target is not None:
            tid = getattr(scan_target, "id", None)
            if isinstance(tid, int):
                related_target_ids.add(tid)
            for link in getattr(scan_target, "asset_links", []) or []:
                aid = getattr(link, "asset_id", None)
                if isinstance(aid, int):
                    related_asset_ids.add(aid)

    return sorted(related_asset_ids), sorted(related_target_ids), related_signal_ids


def derive_operator_actions(objectives, findings):
    objective_items = objectives if isinstance(objectives, list) else []
    finding_items = findings if isinstance(findings, list) else []
    findings_by_id = {}
    for item in finding_items:
        fid = getattr(item, "id", None)
        if isinstance(fid, int):
            findings_by_id[fid] = item

    actions = []
    for objective in sorted(
        [item for item in objective_items if isinstance(item, dict)],
        key=lambda item: (
            str(item.get("objective_type") or ""),
            str(item.get("priority") or ""),
            str(item.get("confidence") or ""),
        ),
    ):
        objective_type = str(objective.get("objective_type") or "").strip().lower()
        if not objective_type:
            continue

        supporting_ids = [
            int(fid)
            for fid in (objective.get("supporting_findings") if isinstance(objective.get("supporting_findings"), list) else [])
            if isinstance(fid, int)
        ]
        selected_findings = [findings_by_id[fid] for fid in supporting_ids if fid in findings_by_id]
        if not selected_findings:
            selected_findings = [
                item
                for item in finding_items
                if str(getattr(item, "category", "") or "").strip().lower() in objective_type
            ]

        selected_findings = sorted(
            selected_findings,
            key=lambda item: (
                -_severity_rank(getattr(item, "severity", "info")),
                str(getattr(item, "title", "") or ""),
                int(getattr(item, "id", 0) or 0),
            ),
        )

        related_finding_ids = [int(getattr(item, "id", 0)) for item in selected_findings if isinstance(getattr(item, "id", None), int)]
        related_asset_ids = set()
        related_target_ids = set()
        related_signal_ids = set()
        titles = []

        for finding in selected_findings:
            titles.append(str(getattr(finding, "title", "") or ""))
            assets, targets, signals = _extract_related_ids(finding)
            related_asset_ids.update(assets)
            related_target_ids.update(targets)
            related_signal_ids.update(signals)

        recommended_steps = objective.get("recommended_next_steps") if isinstance(objective.get("recommended_next_steps"), list) else []
        required_conditions = objective.get("required_conditions") if isinstance(objective.get("required_conditions"), list) else []

        blocker_reasons = []
        if not related_finding_ids:
            blocker_reasons.append("no_supporting_findings")
        if not related_signal_ids and not objective.get("supporting_signals"):
            blocker_reasons.append("missing_signal_lineage")

        blocker_summary = {
            "blocker_count": len(blocker_reasons),
            "reasons": blocker_reasons,
        }
        status = "blocked" if blocker_reasons else "suggested"

        top_finding = selected_findings[0] if selected_findings else None
        attack_priority = _priority_from_severity(getattr(top_finding, "severity", "medium") if top_finding else "medium")
        estimated_value = _value_from_severity(getattr(top_finding, "severity", "medium") if top_finding else "medium")
        estimated_complexity = _complexity_from_category(getattr(top_finding, "category", "") if top_finding else objective_type)

        evidence_summary = (
            f"{len(related_finding_ids)} supporting finding(s), "
            f"{len(related_signal_ids)} linked signal(s), "
            f"top vectors: {', '.join(sorted({title for title in titles if title})[:3]) or 'n/a'}"
        )
        rationale = (
            f"Objective `{objective_type}` is supported by deterministic linkage to observed findings and lineage metadata."
        )
        title = f"Objective Action: {objective_type.replace('_', ' ').title()}"
        description = (
            f"Validate and operationalize objective path `{objective_type}` based on supporting evidence."
            + (f" Suggested next steps: {', '.join(str(step) for step in recommended_steps[:3])}." if recommended_steps else "")
        )

        confidence_value = objective.get("confidence")
        try:
            confidence = float(confidence_value)
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, round(confidence, 4)))

        key_seed = "|".join(
            [
                objective_type,
                ",".join(str(fid) for fid in sorted(related_finding_ids)),
                ",".join(str(sid) for sid in sorted(related_signal_ids)),
                ",".join(str(aid) for aid in sorted(related_asset_ids)),
            ]
        )
        action_key = hashlib.sha256(key_seed.encode("utf-8")).hexdigest()

        action = {
            "action_key": action_key,
            "objective_type": objective_type,
            "action_type": "guided_probe",
            "title": title,
            "description": description,
            "rationale": rationale,
            "status": status,
            "confidence": confidence,
            "attack_priority": attack_priority,
            "estimated_value": estimated_value,
            "estimated_complexity": estimated_complexity,
            "required_conditions": sorted(str(item) for item in required_conditions if str(item).strip()),
            "related_asset_ids": sorted(related_asset_ids),
            "related_target_ids": sorted(related_target_ids),
            "related_finding_ids": sorted(set(related_finding_ids)),
            "related_signal_ids": sorted(related_signal_ids),
            "evidence_summary": evidence_summary,
            "blocker_summary": blocker_summary,
            "metadata": {
                "recommended_next_steps": [str(step) for step in recommended_steps if str(step).strip()],
                "supporting_findings": sorted(set(related_finding_ids)),
                "supporting_signals": sorted(related_signal_ids),
            },
        }
        actions.append(action)

    return sorted(
        actions,
        key=lambda item: (
            str(item.get("status") or ""),
            str(item.get("attack_priority") or ""),
            str(item.get("title") or ""),
            str(item.get("action_key") or ""),
        ),
    )


def _execution_dashboard(objectives, objective_paths, actions, next_steps):
    action_items = actions if isinstance(actions, list) else []
    status_counter = {}
    for item in action_items:
        status = str(item.get("status") or "suggested").strip().lower()
        status_counter[status] = status_counter.get(status, 0) + 1

    value_rank = {"high": 3, "medium": 2, "low": 1}
    priority_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    status_rank = {"suggested": 3, "reviewed": 2, "queued": 1, "blocked": 0, "invalidated": 0, "skipped": 0, "executed": 0}

    def score(item):
        confidence = item.get("confidence")
        try:
            conf_value = float(confidence)
        except (TypeError, ValueError):
            conf_value = 0.0
        return (
            status_rank.get(str(item.get("status") or "").lower(), 0),
            value_rank.get(str(item.get("estimated_value") or "low").lower(), 1),
            priority_rank.get(str(item.get("attack_priority") or "low").lower(), 1),
            conf_value,
            str(item.get("title") or ""),
        )

    most_valuable = None
    if action_items:
        most_valuable = sorted(action_items, key=score, reverse=True)[0]

    return {
        "action_counts_by_status": {key: status_counter[key] for key in sorted(status_counter.keys())},
        "most_valuable_next_action": most_valuable,
        "objective_count": len(objectives if isinstance(objectives, list) else []),
        "objective_path_count": len(objective_paths if isinstance(objective_paths, list) else []),
        "next_step_count": len(next_steps if isinstance(next_steps, list) else []),
    }


def _derive_cross_asset_paths(findings):
    candidates = []
    for finding in findings:
        if _severity_rank(getattr(finding, "severity", "info")) < _severity_rank("medium"):
            continue
        asset_ids, target_ids, signal_ids = _extract_related_ids(finding)
        candidates.append(
            {
                "finding": finding,
                "asset_ids": asset_ids,
                "target_ids": target_ids,
                "signal_ids": signal_ids,
            }
        )

    if len(candidates) < 2:
        return []

    lineage_candidates = [
        item
        for item in candidates
        if item["asset_ids"] or item["target_ids"] or item["signal_ids"]
    ]
    if len(lineage_candidates) < 2:
        return []

    shared_signal_ids = sorted(
        {
            signal_id
            for signal_id in {sid for item in lineage_candidates for sid in item["signal_ids"]}
            if sum(signal_id in item["signal_ids"] for item in lineage_candidates) >= 2
        }
    )
    shared_asset_ids = sorted(
        {
            asset_id
            for asset_id in {aid for item in lineage_candidates for aid in item["asset_ids"]}
            if sum(asset_id in item["asset_ids"] for item in lineage_candidates) >= 2
        }
    )
    shared_target_ids = sorted(
        {
            target_id
            for target_id in {tid for item in lineage_candidates for tid in item["target_ids"]}
            if sum(target_id in item["target_ids"] for item in lineage_candidates) >= 2
        }
    )
    if not shared_signal_ids and not shared_asset_ids and not shared_target_ids:
        return []

    ordered = sorted(
        lineage_candidates,
        key=lambda item: (
            -_severity_rank(getattr(item["finding"], "severity", "info")),
            str(getattr(item["finding"], "title", "") or ""),
            int(getattr(item["finding"], "id", 0) or 0),
        ),
    )
    selected = ordered[: min(5, len(ordered))]
    related_asset_ids = sorted({aid for item in selected for aid in item["asset_ids"]})
    related_target_ids = sorted({tid for item in selected for tid in item["target_ids"]})
    related_finding_ids = sorted(
        {
            int(getattr(item["finding"], "id", 0))
            for item in selected
            if isinstance(getattr(item["finding"], "id", None), int)
        }
    )
    related_signal_ids = sorted({sid for item in selected for sid in item["signal_ids"]})
    if not related_finding_ids:
        return []

    categories = [
        str(getattr(item["finding"], "category", "") or "general")
        for item in selected
        if str(getattr(item["finding"], "category", "") or "").strip()
    ]
    unique_categories = sorted({cat for cat in categories if cat})
    objective_type = "authenticated_api_path" if "auth_surface" in unique_categories or "token_leakage" in unique_categories else "source_code_leak_path"
    attack_priority = _priority_from_severity(getattr(selected[0]["finding"], "severity", "medium"))
    title = f"Correlated Cross-Asset Path: {' -> '.join(unique_categories[:3]) or 'multi_vector'}"
    rationale = (
        "Multiple medium/high confidence vectors were observed across linked assets/targets, "
        "forming a deterministic mission path candidate."
    )

    return [
        {
            "objective_type": objective_type,
            "category": "objective_path",
            "title": title,
            "rationale": rationale,
            "attack_priority": attack_priority,
            "related_asset_ids": related_asset_ids,
            "related_target_ids": related_target_ids,
            "related_finding_ids": related_finding_ids,
            "related_signal_ids": related_signal_ids,
            "metadata": {
                "categories": unique_categories,
                "shared_asset_ids": shared_asset_ids,
                "shared_target_ids": shared_target_ids,
                "shared_signal_ids": shared_signal_ids,
            },
        }
    ]


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
    targets = Target.query.filter_by(mission_id=mission_id).order_by(Target.id.asc()).all()
    assets = Asset.query.filter_by(mission_id=mission_id).order_by(Asset.id.asc()).all()

    objective_paths = []
    next_steps = []
    for finding in findings:
        if not isinstance(finding.metadata_json, dict):
            continue
        if finding.category == "objective_path":
            objective_paths.append(finding.metadata_json)
        elif finding.category == "next_step":
            next_steps.append(finding.metadata_json)

    derived_paths = _derive_cross_asset_paths(findings)
    combined_objective_paths = [*objective_paths, *derived_paths]

    serialized_findings = [_serialize_finding(item) for item in findings]
    top_findings = sorted(
        serialized_findings,
        key=lambda item: (
            -_severity_rank(item.get("severity")),
            str(item.get("confidence") or ""),
            str(item.get("title") or ""),
            int(item.get("id") or 0),
        ),
    )[:25]
    actions_from_objectives = derive_operator_actions(mission.objectives_json or [], findings)
    dashboard = _execution_dashboard(mission.objectives_json or [], combined_objective_paths, actions_from_objectives, next_steps)

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
        "findings_total": len(findings),
        "findings": serialized_findings,
        "top_findings": top_findings,
        "assets": [
            {
                "id": asset.id,
                "type": asset.type,
                "identifier": asset.identifier,
                "label": asset.label,
                "confidence": asset.confidence,
                "source": asset.source,
                "provenance": asset.provenance if isinstance(asset.provenance, dict) else {},
                "tags": sorted(str(tag) for tag in (asset.tags or []) if str(tag).strip()),
                "target_ids": sorted({link.target_id for link in (asset.target_links or []) if isinstance(link.target_id, int)}),
            }
            for asset in assets
        ],
        "targets": [
            {
                "id": target.id,
                "identifier": target.identifier,
                "asset_ids": sorted({link.asset_id for link in (target.asset_links or []) if isinstance(link.asset_id, int)}),
            }
            for target in targets
        ],
        "operator_actions": [_serialize_operator_action(item) for item in operator_actions],
        "objective_paths": sorted(
            combined_objective_paths,
            key=lambda item: (
                str(item.get("objective_type") or ""),
                str(item.get("attack_priority") or ""),
                str(item.get("title") or ""),
            ),
        ),
        "cross_asset_paths": sorted(
            derived_paths,
            key=lambda item: (
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
        "derived_operator_actions": actions_from_objectives,
        "execution_dashboard": dashboard,
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
    if not is_valid_action_transition(current_status, status):
        return None, "invalid_transition"

    action.status = status
    db.session.commit()
    return _serialize_operator_action(action), None
