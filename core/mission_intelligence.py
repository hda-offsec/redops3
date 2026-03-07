from collections import defaultdict
import hashlib

from sqlalchemy import func

from core.extensions import db
from core.models import Asset, AssetTargetLink, Finding, Mission, OperatorAction, Scan, Target
from core.quality_metrics import build_quality_metrics


MISSION_STATES = {
    "draft",
    "recon",
    "mapping",
    "exploitation_prep",
    "objective_tracking",
    "completed",
    "archived",
    "active",  # legacy compatibility
}

OBJECTIVE_TYPES = {
    "admin_access",
    "authenticated_api_access",
    "source_code_access",
    "cloud_credential_access",
    "internal_pivot",
    "external_recon",
    "sensitive_data_access",
}

LEGACY_OBJECTIVE_TYPE_MAP = {
    "source_code_leak": "source_code_access",
}



ACTION_STATUSES = {
    "suggested",
    "reviewed",
    "queued",
    "executed",
    "skipped",
    "blocked",
    "invalidated",
}

ACTION_STATUS_TRANSITIONS = {
    "suggested": {"reviewed", "blocked", "invalidated", "skipped"},
    "reviewed": {"queued", "blocked", "invalidated", "skipped"},
    "queued": {"executed", "blocked", "invalidated", "skipped"},
    "executed": set(),
    "blocked": {"reviewed", "queued", "invalidated", "skipped"},
    "skipped": {"reviewed", "invalidated"},
    "invalidated": {"reviewed"},
}

OBJECTIVE_VALIDATION_GUIDANCE = {
    "admin_access": [
        "Inspect auth, token, and admin-route relationships before testing privileged paths.",
        "Validate upload and admin endpoints using non-destructive request variants.",
        "Review privileged API routes and method-level access controls.",
    ],
    "authenticated_api_access": [
        "Inspect token-bearing flows and where credentials are accepted.",
        "Validate auth parameters and token transport behavior safely.",
        "Review API endpoints/methods for object-level authorization gaps.",
    ],
    "cloud_credential_access": [
        "Inspect SSRF-like parameters and URL fetch behaviors with bounded inputs.",
        "Review metadata service clues and provider-linked hosts in evidence.",
        "Validate cloud-facing surfaces with non-destructive metadata path checks.",
    ],
    "source_code_access": [
        "Inspect git exposure and retrievable repository artifacts.",
        "Review backup/source artifacts for safe retrieval opportunities.",
        "Correlate discovered secrets and internal hostnames across assets.",
    ],
}

OBJECTIVE_ACTION_RECIPES = {
    "admin_access": [
        ("review_auth_flow", "Review auth flow consistency"),
        ("inspect_admin_route", "Review hidden admin path"),
        ("validate_upload_surface", "Validate upload route behavior safely"),
    ],
    "authenticated_api_access": [
        ("inspect_token_usage", "Review token usage across API routes"),
        ("validate_auth_parameters", "Validate auth parameter behavior"),
        ("review_api_methods", "Review privileged API methods"),
    ],
    "cloud_credential_access": [
        ("safe_ssrf_validation", "Attempt safe SSRF validation"),
        ("review_provider_clues", "Review cloud provider metadata clues"),
    ],
    "source_code_access": [
        ("inspect_git_exposure", "Inspect git exposure"),
        ("review_source_artifacts", "Review backup/source artifacts"),
    ],
}

OBJECTIVE_RULES = {
    "admin_access": {
        "categories": {"auth_surface", "auth_bypass", "access_control"},
        "keywords": {"admin", "dashboard", "privilege", "rbac", "auth"},
        "required_conditions": ["validated admin or privileged route", "auth entry point identified"],
        "recommended_probe": "Review privileged routes and session/token handling on linked targets.",
    },
    "authenticated_api_access": {
        "categories": {"api_surface", "auth_surface", "jwt_exposure", "token_leakage"},
        "keywords": {"api", "bearer", "token", "jwt", "oauth", "graphql"},
        "required_conditions": ["token or auth surface evidence", "reachable API endpoint"],
        "recommended_probe": "Validate token-authenticated API requests on discovered endpoints.",
    },
    "source_code_access": {
        "categories": {"git_exposure", "source_exposure", "backup_exposure"},
        "keywords": {"git", ".env", "source", "repository", "backup"},
        "required_conditions": ["source artifact exposed", "retrievable source path"],
        "recommended_probe": "Inspect exposed source artifacts and map credential/material reuse paths.",
    },
    "cloud_credential_access": {
        "categories": {"cloud_asset", "cloud_exposure", "cloud_storage_exposure", "ssrf", "metadata_exposure"},
        "keywords": {"s3", "metadata", "iam", "aws", "gcp", "azure", "cloud"},
        "required_conditions": ["cloud reference or metadata surface", "cross-system cloud dependency"],
        "recommended_probe": "Review metadata-accessible parameters and cloud identity references.",
    },
    "internal_pivot": {
        "categories": {"network_exposure", "internal_service_exposure", "ssrf", "lfi"},
        "keywords": {"internal", "pivot", "rfc1918", "localhost", "intranet"},
        "required_conditions": ["pivot-capable surface", "internal addressability evidence"],
        "recommended_probe": "Inspect SSRF/LFI-influenced paths for internal network reachability.",
    },
    "external_recon": {
        "categories": {"subdomain_takeover", "surface_discovery", "api_surface", "js_route_discovery"},
        "keywords": {"subdomain", "endpoint", "surface", "external", "js"},
        "required_conditions": ["externally reachable target", "surface discovery evidence"],
        "recommended_probe": "Expand endpoint and service mapping on externally exposed assets.",
    },
    "sensitive_data_access": {
        "categories": {"token_leakage", "api_key_exposure", "jwt_exposure", "secret_exposure", "data_exposure"},
        "keywords": {"secret", "credential", "password", "key", "token", "pii"},
        "required_conditions": ["sensitive data indicator", "retrievable sensitive context"],
        "recommended_probe": "Review data leakage findings and validate exposure scope.",
    },
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


def normalize_mission_status(status):
    incoming = (status or "").strip().lower()
    if incoming in MISSION_STATES:
        return incoming
    if incoming == "":
        return "draft"
    return "active"


def normalize_objective_type(objective_type):
    incoming = (objective_type or "").strip().lower()
    incoming = LEGACY_OBJECTIVE_TYPE_MAP.get(incoming, incoming)
    return incoming if incoming in OBJECTIVE_TYPES else None


def _severity_weight(severity):
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }.get((severity or "info").lower(), 0)


def _priority_weight(priority):
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get((priority or "low").lower(), 1)


def _to_id_list(values):
    if not isinstance(values, list):
        return []
    return sorted({int(v) for v in values if isinstance(v, int)})


def _normalize_action_status(status):
    incoming = (status or "suggested").strip().lower()
    return incoming if incoming in ACTION_STATUSES else "suggested"


def is_valid_action_transition(current_status, next_status):
    current = _normalize_action_status(current_status)
    target = _normalize_action_status(next_status)
    if current == target:
        return True
    return target in ACTION_STATUS_TRANSITIONS.get(current, set())


def _action_key(action):
    key_material = "|".join([
        str(action.get("objective_type") or ""),
        str(action.get("action_type") or ""),
        ",".join(str(x) for x in action.get("related_asset_ids", [])),
        ",".join(str(x) for x in action.get("related_target_ids", [])),
        ",".join(str(x) for x in action.get("related_finding_ids", [])),
    ])
    digest = hashlib.sha1(key_material.encode("utf-8")).hexdigest()
    return f"oa:{digest[:20]}"


def _severity_hint(findings):
    if any((f.severity or "").lower() == "critical" for f in findings):
        return "critical"
    if any((f.severity or "").lower() == "high" for f in findings):
        return "high"
    if any((f.severity or "").lower() == "medium" for f in findings):
        return "medium"
    return "low"


def _value_from_findings(findings):
    scores = []
    for finding in findings:
        metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
        scores.append(float(metadata.get("exploit_score", 0) or 0))
    average = round(sum(scores) / max(1, len(scores)), 2)
    if average >= 75:
        return "high"
    if average >= 40:
        return "medium"
    return "low"


def _build_action_blockers(objective, supporting_findings):
    blockers = []
    missing_evidence = []
    if not objective.get("supporting_signals"):
        blockers.append("no_signal_lineage")
        missing_evidence.append("signal lineage linking findings to raw detections")

    has_auth = any("auth" in _finding_text(f) for f in supporting_findings)
    has_token = any("token" in _finding_text(f) or "jwt" in _finding_text(f) for f in supporting_findings)
    has_upload = any("upload" in _finding_text(f) for f in supporting_findings)
    has_retrieval = any("download" in _finding_text(f) or "retriev" in _finding_text(f) for f in supporting_findings)
    has_ssrf = any("ssrf" in _finding_text(f) for f in supporting_findings)
    has_provider = any(any(k in _finding_text(f) for k in ("aws", "gcp", "azure", "metadata")) for f in supporting_findings)
    has_component = any("component" in _finding_text(f) or "version" in _finding_text(f) for f in supporting_findings)

    objective_type = objective.get("objective_type")
    if objective_type in {"admin_access", "authenticated_api_access"} and has_token and not has_auth:
        blockers.append("token_without_auth_endpoint")
        missing_evidence.append("confirmed auth endpoint using discovered token material")
    if objective_type == "admin_access" and has_upload and not has_retrieval:
        blockers.append("upload_without_retrieval_proof")
        missing_evidence.append("evidence of upload retrieval or execution path")
    if objective_type == "cloud_credential_access" and has_ssrf and not has_provider:
        blockers.append("ssrf_without_provider_clue")
        missing_evidence.append("provider-specific metadata clue")
    if objective_type == "source_code_access" and not has_component:
        blockers.append("component_without_version_evidence")
        missing_evidence.append("component or version evidence for prioritization")

    return {
        "blocker_count": len(blockers),
        "reasons": blockers,
        "missing_evidence": missing_evidence,
    }


def _serialize_operator_action(action):
    metadata = action.metadata_json if isinstance(action.metadata_json, dict) else {}
    blocker_summary = action.blocker_summary if isinstance(action.blocker_summary, dict) else {"blocker_count": 0, "reasons": [], "missing_evidence": []}
    return {
        "id": action.id,
        "mission_id": action.mission_id,
        "action_key": action.action_key,
        "related_asset_ids": _to_id_list(action.related_asset_ids),
        "related_target_ids": _to_id_list(action.related_target_ids),
        "related_finding_ids": _to_id_list(action.related_finding_ids),
        "related_signal_ids": _to_id_list(action.related_signal_ids),
        "objective_type": action.objective_type,
        "action_type": action.action_type,
        "title": action.title,
        "description": action.description,
        "rationale": action.rationale,
        "confidence": round(float(action.confidence or 0), 2),
        "attack_priority": action.attack_priority,
        "estimated_value": action.estimated_value,
        "estimated_complexity": action.estimated_complexity,
        "status": _normalize_action_status(action.status),
        "blocker_summary": blocker_summary,
        "required_conditions": action.required_conditions if isinstance(action.required_conditions, list) else [],
        "evidence_summary": action.evidence_summary,
        "metadata": metadata,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "updated_at": action.updated_at.isoformat() if action.updated_at else None,
    }


def _execution_dashboard(objectives, objective_paths, operator_actions, next_steps):
    status_counts = {status: 0 for status in sorted(ACTION_STATUSES)}
    for action in operator_actions:
        status = _normalize_action_status(action.get("status"))
        status_counts[status] = status_counts.get(status, 0) + 1

    blocked_actions = [a for a in operator_actions if _normalize_action_status(a.get("status")) == "blocked"]
    reviewed_or_executed = [a for a in operator_actions if _normalize_action_status(a.get("status")) in {"reviewed", "executed"}]

    most_valuable = sorted(operator_actions, key=lambda a: (a.get("estimated_value") == "high", a.get("attack_priority") == "critical", a.get("confidence", 0)), reverse=True)
    highest_confidence = sorted(operator_actions, key=lambda a: (a.get("confidence", 0), a.get("attack_priority") == "critical"), reverse=True)
    highest_path = sorted(objective_paths, key=lambda p: ((p.get("metadata") or {}).get("exploit_score", 0), p.get("confidence", 0)), reverse=True)

    objective_readiness = {
        objective["objective_type"]: {
            "status": objective["status"],
            "readiness_score": objective["readiness_score"],
            "required_conditions": objective.get("required_conditions", []),
        }
        for objective in objectives
    }

    return {
        "objective_list": [{"objective_type": o["objective_type"], "status": o["status"], "priority": o["priority"]} for o in objectives],
        "top_objective_paths": objective_paths[:5],
        "recommended_actions": operator_actions[:10],
        "blocked_actions": blocked_actions[:10],
        "reviewed_or_executed_actions": reviewed_or_executed[:10],
        "action_counts_by_status": status_counts,
        "mission_readiness_summary": {
            "ready_objectives": len([o for o in objectives if o["status"] == "ready"]),
            "objectives_total": len(objectives),
            "actions_total": len(operator_actions),
            "blocked_actions": len(blocked_actions),
        },
        "objective_readiness_summary": objective_readiness,
        "most_valuable_next_action": most_valuable[0] if most_valuable else None,
        "highest_confidence_next_action": highest_confidence[0] if highest_confidence else None,
        "highest_exploit_score_path": highest_path[0] if highest_path else (objective_paths[0] if objective_paths else None),
        "next_step_candidates": next_steps[:5],
    }


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


def _finding_text(finding):
    return " ".join([
        finding.title or "",
        finding.description or "",
        finding.category or "",
        finding.endpoint or "",
        finding.target or "",
    ]).lower()


def _objective_matches_finding(objective_type, finding):
    rule = OBJECTIVE_RULES.get(objective_type)
    if not rule:
        return False
    category = (finding.category or "").lower()
    if category in rule["categories"]:
        return True
    text = _finding_text(finding)
    return any(keyword in text for keyword in rule["keywords"])


def _parse_objective_entries(mission):
    payload = mission.objectives_json
    if not payload:
        return []

    parsed = []
    if isinstance(payload, list):
        entries = payload
    else:
        entries = [payload]

    for item in entries:
        if isinstance(item, str):
            objective_type = normalize_objective_type(item)
            if objective_type:
                parsed.append({"objective_type": objective_type, "priority": "medium"})
            continue
        if not isinstance(item, dict):
            continue
        objective_type = normalize_objective_type(item.get("objective_type") or item.get("type"))
        if not objective_type:
            continue
        parsed.append({
            "objective_type": objective_type,
            "priority": (item.get("priority") or "medium").lower(),
            "status": (item.get("status") or "draft").lower(),
            "confidence": item.get("confidence") if isinstance(item.get("confidence"), (int, float)) else None,
            "required_conditions": item.get("required_conditions") if isinstance(item.get("required_conditions"), list) else None,
            "recommended_next_steps": item.get("recommended_next_steps") if isinstance(item.get("recommended_next_steps"), list) else None,
        })

    dedup = {}
    for entry in parsed:
        dedup[entry["objective_type"]] = entry
    return [dedup[k] for k in sorted(dedup.keys())]


def _objective_evidence(findings, objective_type):
    supporting = [f for f in findings if _objective_matches_finding(objective_type, f)]
    related_asset_ids = sorted({link.asset_id for f in supporting for link in (f.scan.target.asset_links if f.scan and f.scan.target else [])})
    related_target_ids = sorted({f.scan.target_id for f in supporting if f.scan and f.scan.target_id is not None})
    related_finding_ids = sorted({f.id for f in supporting if f.id is not None})
    related_signal_ids = sorted({sid for f in supporting for sid in ((f.signal_ids or []) if isinstance(f.signal_ids, list) else []) if isinstance(sid, int)})
    return supporting, related_asset_ids, related_target_ids, related_finding_ids, related_signal_ids


def build_objective_statuses(mission, findings):
    entries = _parse_objective_entries(mission)
    configured_types = {entry["objective_type"] for entry in entries}

    # Auto-discover only when evidence exists to avoid speculative objective creation.
    for objective_type in sorted(OBJECTIVE_TYPES):
        supporting, *_ = _objective_evidence(findings, objective_type)
        if supporting and objective_type not in configured_types:
            entries.append({"objective_type": objective_type, "priority": "medium", "status": "derived"})

    objectives = []
    for entry in sorted(entries, key=lambda x: (x.get("priority") or "medium", x["objective_type"])):
        objective_type = entry["objective_type"]
        supporting, related_asset_ids, related_target_ids, related_finding_ids, related_signal_ids = _objective_evidence(findings, objective_type)
        if not supporting and entry.get("status") == "derived":
            continue
        readiness_score = min(100, len(related_finding_ids) * 20 + len(related_asset_ids) * 10)
        confidence = round(min(1.0, 0.25 + len(related_signal_ids) * 0.05 + len(related_asset_ids) * 0.1), 2)
        objectives.append({
            "objective_type": objective_type,
            "priority": entry.get("priority") or "medium",
            "status": "ready" if readiness_score >= 70 else "in_progress" if readiness_score > 0 else (entry.get("status") or "draft"),
            "confidence": entry.get("confidence") if isinstance(entry.get("confidence"), (int, float)) else confidence,
            "required_conditions": entry.get("required_conditions") or OBJECTIVE_RULES[objective_type]["required_conditions"],
            "supporting_assets": related_asset_ids,
            "supporting_findings": related_finding_ids,
            "supporting_signals": related_signal_ids,
            "supporting_targets": related_target_ids,
            "recommended_next_steps": entry.get("recommended_next_steps") or [OBJECTIVE_RULES[objective_type]["recommended_probe"]],
            "readiness_score": readiness_score,
            "field_sources": {
                "supporting_findings": "finding.category/title/description",
                "supporting_signals": "finding.signal_ids",
                "supporting_assets": "asset_target_links",
            },
        })
    return sorted(objectives, key=lambda o: (_priority_weight(o["priority"]) * -1, o["objective_type"]))


def build_objective_next_steps(objectives, findings):
    next_steps = []
    finding_lookup = {f.id: f for f in findings if f.id is not None}
    for objective in objectives:
        objective_findings = [finding_lookup[fid] for fid in objective["supporting_findings"] if fid in finding_lookup]
        if not objective_findings:
            continue
        objective_findings = sorted(objective_findings, key=lambda f: (_severity_weight(f.severity), f.id), reverse=True)
        top = objective_findings[:3]
        combined_score = []
        for finding in top:
            metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
            combined_score.append(metadata.get("exploit_score", 0))
        estimated_value_score = round(sum(combined_score) / max(1, len(combined_score)), 2)
        attack_priority = "critical" if estimated_value_score >= 85 else "high" if estimated_value_score >= 65 else "medium" if estimated_value_score >= 40 else "low"
        related_assets = sorted({link.asset_id for finding in top for link in (finding.scan.target.asset_links if finding.scan and finding.scan.target else [])})
        related_targets = sorted({finding.scan.target_id for finding in top if finding.scan and finding.scan.target_id is not None})
        related_findings = sorted({finding.id for finding in top if finding.id is not None})
        related_signals = sorted({sid for finding in top for sid in ((finding.signal_ids or []) if isinstance(finding.signal_ids, list) else []) if isinstance(sid, int)})
        next_steps.append({
            "objective_type": objective["objective_type"],
            "related_asset_ids": related_assets,
            "related_target_ids": related_targets,
            "related_finding_ids": related_findings,
            "related_signal_ids": related_signals,
            "rationale": f"Evidence for {objective['objective_type']} is concentrated in high-priority findings on related assets/targets.",
            "action_type": "probe_validation",
            "action_priority": attack_priority,
            "estimated_value": "high" if estimated_value_score >= 70 else "medium" if estimated_value_score >= 40 else "low",
            "estimated_complexity": "high" if len(related_assets) > 3 else "medium" if len(related_assets) > 1 else "low",
            "confidence": objective["confidence"],
            "recommended_probe": OBJECTIVE_RULES[objective["objective_type"]]["recommended_probe"],
            "why_priority": {
                "objective_priority": objective["priority"],
                "readiness_score": objective["readiness_score"],
                "supporting_signal_count": len(related_signals),
            },
            "field_sources": {
                "related_finding_ids": "findings.id",
                "related_signal_ids": "findings.signal_ids",
                "action_priority": "finding.metadata.exploit_score + severity",
            },
        })
    return sorted(next_steps, key=lambda s: (_priority_weight(s["action_priority"]), len(s["related_signal_ids"])), reverse=True)


def derive_operator_actions(objectives, findings):
    actions = []
    finding_lookup = {f.id: f for f in findings if f.id is not None}

    for objective in objectives:
        objective_findings = [finding_lookup[fid] for fid in objective.get("supporting_findings", []) if fid in finding_lookup]
        if not objective_findings:
            continue

        blockers = _build_action_blockers(objective, objective_findings)
        objective_guidance = OBJECTIVE_VALIDATION_GUIDANCE.get(
            objective["objective_type"],
            [OBJECTIVE_RULES[objective["objective_type"]]["recommended_probe"]],
        )
        recipes = OBJECTIVE_ACTION_RECIPES.get(
            objective["objective_type"],
            [("probe_validation", OBJECTIVE_RULES[objective["objective_type"]]["recommended_probe"])],
        )

        top_findings = sorted(
            objective_findings,
            key=lambda f: (_severity_weight(f.severity), (f.id or 0)),
            reverse=True,
        )[:3]

        related_asset_ids = sorted({link.asset_id for finding in top_findings for link in (finding.scan.target.asset_links if finding.scan and finding.scan.target else [])})
        related_target_ids = sorted({finding.scan.target_id for finding in top_findings if finding.scan and finding.scan.target_id is not None})
        related_finding_ids = sorted({finding.id for finding in top_findings if finding.id is not None})
        related_signal_ids = sorted({sid for finding in top_findings for sid in ((finding.signal_ids or []) if isinstance(finding.signal_ids, list) else []) if isinstance(sid, int)})

        attack_priority = objective["priority"]
        if blockers["blocker_count"]:
            action_status = "blocked"
        else:
            action_status = "suggested"

        for idx, (action_type, title) in enumerate(recipes):
            evidence_summary = "; ".join([f"finding#{finding.id}: {finding.title}" for finding in top_findings])
            confidence = round(min(1.0, float(objective.get("confidence") or 0) + (0.05 * idx)), 2)
            estimated_complexity = "high" if len(related_assets := related_asset_ids) > 3 else "medium" if len(related_assets) > 1 else "low"
            action = {
                "mission_id": None,
                "related_asset_ids": related_asset_ids,
                "related_target_ids": related_target_ids,
                "related_finding_ids": related_finding_ids,
                "related_signal_ids": related_signal_ids,
                "objective_type": objective["objective_type"],
                "action_type": action_type,
                "title": title,
                "description": objective_guidance[min(idx, len(objective_guidance) - 1)],
                "rationale": f"Supports objective {objective['objective_type']} using evidence-backed findings and linked signal lineage.",
                "confidence": confidence,
                "attack_priority": attack_priority,
                "estimated_value": _value_from_findings(top_findings),
                "estimated_complexity": estimated_complexity,
                "status": action_status,
                "blocker_summary": blockers,
                "required_conditions": objective.get("required_conditions", []),
                "evidence_summary": evidence_summary,
                "metadata": {
                    "field_sources": {
                        "related_finding_ids": "objective.supporting_findings",
                        "related_signal_ids": "objective.supporting_signals",
                        "attack_priority": "mission objective priority",
                        "blocker_summary": "objective + finding evidence checks",
                    },
                    "score_factors": {
                        "severity_hint": _severity_hint(top_findings),
                        "supporting_findings": len(related_finding_ids),
                        "supporting_signals": len(related_signal_ids),
                    },
                    "chain_explanation": f"{len(related_finding_ids)} findings across {len(related_asset_ids)} assets reinforce {objective['objective_type']}",
                    "objective_rationale": objective.get("recommended_next_steps", []),
                    "recommended_precursor_actions": [
                        "collect additional signal lineage" if "no_signal_lineage" in blockers["reasons"] else None,
                        "validate auth endpoint existence" if "token_without_auth_endpoint" in blockers["reasons"] else None,
                        "confirm upload retrieval path" if "upload_without_retrieval_proof" in blockers["reasons"] else None,
                    ],
                },
            }
            action["metadata"]["recommended_precursor_actions"] = [x for x in action["metadata"]["recommended_precursor_actions"] if x]
            action["action_key"] = _action_key(action)
            actions.append(action)

    # deterministic ordering
    return sorted(actions, key=lambda a: (_priority_weight(a["attack_priority"]) * -1, -a["confidence"], a["action_key"]))


def sync_operator_actions(mission_id, derived_actions):
    existing = OperatorAction.query.filter_by(mission_id=mission_id).all()
    existing_by_key = {item.action_key: item for item in existing}

    for action in derived_actions:
        action["mission_id"] = mission_id
        record = existing_by_key.get(action["action_key"])
        if not record:
            record = OperatorAction(mission_id=mission_id, action_key=action["action_key"])
            db.session.add(record)

        preserve_status = _normalize_action_status(record.status if record.status else action.get("status"))
        if preserve_status in {"executed", "skipped", "invalidated", "queued", "reviewed"}:
            effective_status = preserve_status
        elif action.get("blocker_summary", {}).get("blocker_count", 0) > 0:
            effective_status = "blocked"
        else:
            effective_status = "suggested"

        record.related_asset_ids = action.get("related_asset_ids", [])
        record.related_target_ids = action.get("related_target_ids", [])
        record.related_finding_ids = action.get("related_finding_ids", [])
        record.related_signal_ids = action.get("related_signal_ids", [])
        record.objective_type = action["objective_type"]
        record.action_type = action["action_type"]
        record.title = action["title"]
        record.description = action.get("description")
        record.rationale = action.get("rationale")
        record.confidence = float(action.get("confidence") or 0.0)
        record.attack_priority = action.get("attack_priority") or "medium"
        record.estimated_value = action.get("estimated_value") or "medium"
        record.estimated_complexity = action.get("estimated_complexity") or "low"
        record.status = effective_status
        record.blocker_summary = action.get("blocker_summary")
        record.required_conditions = action.get("required_conditions")
        record.evidence_summary = action.get("evidence_summary")
        record.metadata_json = action.get("metadata")

    db.session.flush()
    rows = OperatorAction.query.filter_by(mission_id=mission_id).order_by(OperatorAction.created_at.asc(), OperatorAction.id.asc()).all()
    return [_serialize_operator_action(item) for item in rows]


def update_operator_action_status(mission_id, action_id, next_status):
    action = OperatorAction.query.filter_by(mission_id=mission_id, id=action_id).first()
    if not action:
        return None, "not_found"

    normalized = _normalize_action_status(next_status)
    current = _normalize_action_status(action.status)
    if not is_valid_action_transition(current, normalized):
        return None, "invalid_transition"

    action.status = normalized
    db.session.commit()
    return _serialize_operator_action(action), None


def synthesize_cross_asset_paths(mission_id):
    mission = Mission.query.get(mission_id)
    if not mission:
        return []
    target_ids = [t.id for t in mission.targets]
    latest_ids = _latest_scan_ids_for_targets(target_ids)
    if not latest_ids:
        return []

    findings = Finding.query.filter(Finding.scan_id.in_(latest_ids)).all()
    objective_statuses = build_objective_statuses(mission, findings)
    next_steps = build_objective_next_steps(objective_statuses, findings)

    prep_artifacts = []
    for objective in objective_statuses:
        if len(objective["supporting_assets"]) < 2:
            continue
        blockers = []
        if not objective["supporting_signals"]:
            blockers.append("no_signal_lineage")
        prep_artifacts.append({
            "category": "mission_prep",
            "objective_type": objective["objective_type"],
            "supporting_assets": objective["supporting_assets"],
            "supporting_targets": objective["supporting_targets"],
            "supporting_findings": objective["supporting_findings"],
            "supporting_signals": objective["supporting_signals"],
            "required_conditions": objective["required_conditions"],
            "blockers": blockers,
            "recommended_next_steps": objective["recommended_next_steps"],
            "confidence": objective["confidence"],
            "attack_priority": objective["priority"],
            "chain_explanation": f"Cross-asset evidence supports {objective['objective_type']} preparation.",
        })

    objective_paths = []
    for objective in objective_statuses:
        if len(objective["supporting_assets"]) < 2:
            continue
        objective_paths.append({
            "category": "objective_path",
            "objective_type": objective["objective_type"],
            "title": f"Objective Path: {objective['objective_type']}",
            "severity": "high" if objective["readiness_score"] >= 70 else "medium",
            "confidence": objective["confidence"],
            "rationale": f"{len(objective['supporting_findings'])} findings and {len(objective['supporting_assets'])} assets support this objective.",
            "attack_priority": objective["priority"],
            "related_asset_ids": objective["supporting_assets"],
            "related_target_ids": objective["supporting_targets"],
            "related_finding_ids": objective["supporting_findings"],
            "related_signal_ids": objective["supporting_signals"],
            "field_sources": objective["field_sources"],
        })

    operator_actions = [dict(action, category="operator_action") for action in derive_operator_actions(objective_statuses, findings)]
    combined = objective_paths + prep_artifacts + [dict(step, category="next_step") for step in next_steps] + operator_actions
    return combined


def _mission_coverage(assets, targets, findings, latest_scan_ids, objective_statuses, cross_asset_paths):
    scanned_target_ids = sorted({scan.target_id for scan in Scan.query.filter(Scan.id.in_(latest_scan_ids)).all()}) if latest_scan_ids else []
    scanned_asset_ids = sorted({link.asset_id for target in targets if target.id in scanned_target_ids for link in target.asset_links})
    asset_ids_with_findings = sorted({link.asset_id for finding in findings for link in (finding.scan.target.asset_links if finding.scan and finding.scan.target else [])})

    auth_surfaces = [f for f in findings if _objective_matches_finding("authenticated_api_access", f)]
    api_surfaces = [f for f in findings if (f.category or "") == "api_surface" or "api" in _finding_text(f)]
    admin_surfaces = [f for f in findings if "admin" in _finding_text(f)]
    secrets_detected = [f for f in findings if _objective_matches_finding("sensitive_data_access", f)]

    top_assets = []
    by_asset = defaultdict(list)
    for finding in findings:
        if not finding.scan or not finding.scan.target:
            continue
        for link in finding.scan.target.asset_links:
            by_asset[link.asset_id].append(finding)
    for asset_id, asset_findings in by_asset.items():
        avg_exploit_score = []
        for finding in asset_findings:
            metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
            avg_exploit_score.append(metadata.get("exploit_score", 0))
        top_assets.append({
            "asset_id": asset_id,
            "findings": len(asset_findings),
            "avg_exploit_score": round(sum(avg_exploit_score) / max(1, len(avg_exploit_score)), 2),
        })
    top_assets = sorted(top_assets, key=lambda x: (x["avg_exploit_score"], x["findings"], x["asset_id"]), reverse=True)

    readiness = {
        objective["objective_type"]: {
            "readiness_score": objective["readiness_score"],
            "status": objective["status"],
            "blocker_count": 0 if objective["supporting_signals"] else 1,
        }
        for objective in objective_statuses
    }

    coverage_ratio = round(len(scanned_asset_ids) / max(1, len(assets)), 3)

    return {
        "assets_total": len(assets),
        "targets_total": len(targets),
        "scanned_assets": len(scanned_asset_ids),
        "assets_with_findings": len(asset_ids_with_findings),
        "auth_surfaces_discovered": len(auth_surfaces),
        "api_surfaces_discovered": len(api_surfaces),
        "admin_surfaces_discovered": len(admin_surfaces),
        "secrets_detected": len(secrets_detected),
        "top_attack_chains": [p for p in cross_asset_paths if p.get("category") == "objective_path"][:5],
        "top_objective_paths": [p for p in cross_asset_paths if p.get("category") == "objective_path"][:5],
        "assets_highest_exploit_score": top_assets[:5],
        "coverage_ratio": coverage_ratio,
        "objective_readiness": readiness,
        "exploitability_summary": {
            "high_value_assets": len([a for a in top_assets if a["avg_exploit_score"] >= 65]),
            "critical_objectives": len([o for o in objective_statuses if o["priority"] == "critical"]),
        },
        "attack_surface_distribution": {
            "asset": len(assets),
            "target": len(targets),
            "finding": len(findings),
        },
    }


def _prioritize_mission(objectives, next_steps, findings):
    objective_priority = []
    for objective in objectives:
        score = round(
            (objective["readiness_score"] * 0.4)
            + (_priority_weight(objective["priority"]) * 15)
            + (len(objective["supporting_signals"]) * 2),
            2,
        )
        objective_priority.append({
            "objective_type": objective["objective_type"],
            "objective_priority": score,
            "readiness_score": objective["readiness_score"],
            "blocker_count": 0 if objective["supporting_signals"] else 1,
        })

    mission_priority_score = round(sum(item["objective_priority"] for item in objective_priority) / max(1, len(objective_priority)), 2)
    clustered_findings = defaultdict(list)
    for finding in findings:
        clustered_findings[(finding.category or "uncategorized").lower()].append(finding.id)

    return {
        "mission_priority_score": mission_priority_score,
        "objective_priority": sorted(objective_priority, key=lambda x: x["objective_priority"], reverse=True),
        "next_step_priority": next_steps[:10],
        "finding_clusters": [
            {"category": category, "finding_ids": sorted(ids), "count": len(ids)}
            for category, ids in sorted(clustered_findings.items(), key=lambda item: (-len(item[1]), item[0]))
        ],
    }


def _build_graph_v5(mission, assets, targets, findings, objectives, cross_asset_paths, next_steps, operator_actions):
    nodes = [{"id": f"mission:{mission.id}", "type": "mission", "label": mission.name}]
    edges = []

    for objective in objectives:
        oid = f"objective:{objective['objective_type']}"
        nodes.append({"id": oid, "type": "objective", "label": objective["objective_type"], "metadata": {"readiness_score": objective["readiness_score"]}})
        edges.append({"from": f"mission:{mission.id}", "to": oid, "relation": "contains"})

    for asset in assets:
        aid = f"asset:{asset.id}"
        nodes.append({"id": aid, "type": "asset", "label": asset.label or asset.identifier})
        edges.append({"from": f"mission:{mission.id}", "to": aid, "relation": "contains"})

    for target in targets:
        tid = f"target:{target.id}"
        nodes.append({"id": tid, "type": "target", "label": target.identifier})
        edges.append({"from": f"mission:{mission.id}", "to": tid, "relation": "contains"})
        for link in target.asset_links:
            edges.append({"from": f"asset:{link.asset_id}", "to": tid, "relation": "belongs_to"})

    for finding in findings:
        fid = f"finding:{finding.id}"
        nodes.append({"id": fid, "type": "attack_chain", "label": finding.title})
        if finding.scan and finding.scan.target_id is not None:
            edges.append({"from": f"target:{finding.scan.target_id}", "to": fid, "relation": "leads_to_attack"})

    for index, path in enumerate(cross_asset_paths):
        pid = f"path:{index}:{path.get('category', 'path')}"
        nodes.append({"id": pid, "type": path.get("category", "objective_path"), "label": path.get("title") or path.get("objective_type") or "path"})
        for objective in objectives:
            if objective["objective_type"] == path.get("objective_type"):
                edges.append({"from": f"objective:{objective['objective_type']}", "to": pid, "relation": "supports_objective"})
        for asset_id in path.get("related_asset_ids", path.get("supporting_assets", [])):
            edges.append({"from": f"asset:{asset_id}", "to": pid, "relation": "suggests"})

    for index, step in enumerate(next_steps):
        sid = f"next_step:{index}:{step['objective_type']}"
        nodes.append({"id": sid, "type": "next_step", "label": step["recommended_probe"]})
        edges.append({"from": f"objective:{step['objective_type']}", "to": sid, "relation": "prioritizes"})
        for aid in step["related_asset_ids"]:
            edges.append({"from": sid, "to": f"asset:{aid}", "relation": "depends_on"})

    for action in operator_actions:
        oid = f"operator_action:{action.get('action_key') or action.get('id')}"
        nodes.append({"id": oid, "type": "operator_action", "label": action.get("title") or "operator action"})
        edges.append({"from": f"objective:{action.get('objective_type')}", "to": oid, "relation": "operator_guidance"})
        for aid in action.get("related_asset_ids", []):
            edges.append({"from": oid, "to": f"asset:{aid}", "relation": "depends_on"})

    dedup_nodes = {node["id"]: node for node in nodes}
    dedup_edges = {(edge["from"], edge["to"], edge["relation"]): edge for edge in edges}
    return {
        "nodes": list(dedup_nodes.values()),
        "edges": list(dedup_edges.values()),
        "node_count": len(dedup_nodes),
        "edge_count": len(dedup_edges),
    }


def aggregate_mission_quality_metrics(mission_id, limit=100):
    mission = Mission.query.get_or_404(mission_id)
    targets = Target.query.filter_by(mission_id=mission.id).all()
    target_ids = [t.id for t in targets]
    latest_scan_ids = _latest_scan_ids_for_targets(target_ids)

    findings = Finding.query.filter(Finding.scan_id.in_(latest_scan_ids)).all() if latest_scan_ids else []
    objective_statuses = build_objective_statuses(mission, findings)
    next_steps = build_objective_next_steps(objective_statuses, findings)[:limit]
    objective_paths = [p for p in synthesize_cross_asset_paths(mission.id) if p.get("category") == "objective_path"][:limit]
    derived_actions = derive_operator_actions(objective_statuses, findings)[:limit]

    return build_quality_metrics(
        findings=[_serialize_finding(f) for f in findings],
        operator_actions=derived_actions,
        objectives=objective_statuses,
        objective_paths=objective_paths,
        next_steps=next_steps,
    )


def aggregate_mission_intelligence(mission_id, limit=10):
    mission = Mission.query.get_or_404(mission_id)
    targets = Target.query.filter_by(mission_id=mission.id).all()
    target_ids = [t.id for t in targets]
    latest_scan_ids = _latest_scan_ids_for_targets(target_ids)
    scans = Scan.query.filter(Scan.id.in_(latest_scan_ids)).all() if latest_scan_ids else []

    findings = Finding.query.filter(Finding.scan_id.in_(latest_scan_ids)).all() if latest_scan_ids else []
    top_findings = sorted(
        findings,
        key=lambda f: (_severity_weight(f.severity), f.id or 0),
        reverse=True,
    )[:limit]

    cross_asset_paths = synthesize_cross_asset_paths(mission.id)
    assets = Asset.query.filter_by(mission_id=mission.id).order_by(Asset.created_at.asc()).all()

    objective_statuses = build_objective_statuses(mission, findings)
    next_steps = build_objective_next_steps(objective_statuses, findings)[:limit]
    derived_actions = derive_operator_actions(objective_statuses, findings)
    operator_actions = sync_operator_actions(mission.id, derived_actions)
    coverage = _mission_coverage(assets, targets, findings, latest_scan_ids, objective_statuses, cross_asset_paths)
    prioritization = _prioritize_mission(objective_statuses, next_steps, findings)
    objective_paths = [p for p in cross_asset_paths if p.get("category") == "objective_path"][:limit]
    graph_v5 = _build_graph_v5(mission, assets, targets, findings, objective_statuses, cross_asset_paths, next_steps, operator_actions)
    execution_dashboard = _execution_dashboard(objective_statuses, objective_paths, operator_actions, next_steps)
    validation_guidance = {
        "objective_guidance": {
            objective["objective_type"]: OBJECTIVE_VALIDATION_GUIDANCE.get(
                objective["objective_type"],
                [OBJECTIVE_RULES[objective["objective_type"]]["recommended_probe"]],
            )
            for objective in objective_statuses
        }
    }

    db.session.commit()

    return {
        "mission": {
            "id": mission.id,
            "name": mission.name,
            "description": mission.description,
            "status": normalize_mission_status(mission.status),
            "scope_summary": mission.scope_summary,
            "priority": mission.priority or "medium",
            "tags": mission.tags_json or [],
            "objectives": mission.objectives_json or [],
            "created_at": mission.created_at.isoformat() if mission.created_at else None,
            "updated_at": mission.updated_at.isoformat() if mission.updated_at else None,
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
        "objective_paths": objective_paths,
        "cross_asset_paths": cross_asset_paths,
        "objectives": objective_statuses,
        "next_steps": next_steps,
        "operator_actions": operator_actions[:limit],
        "mission_execution": execution_dashboard,
        "validation_guidance": validation_guidance,
        "mission_coverage": coverage,
        "mission_prioritization": prioritization,
        "quality_metrics": build_quality_metrics(
            findings=[_serialize_finding(f) for f in findings],
            operator_actions=operator_actions,
            objectives=objective_statuses,
            objective_paths=objective_paths,
            next_steps=next_steps,
        ),
        "graph_summary": {
            "node_count": len(scans) + len(assets) + len(targets) + len(findings),
            "edge_count": len(targets) + sum(len(a.target_links) for a in assets),
        },
        "mission_graph_v5": graph_v5,
    }
