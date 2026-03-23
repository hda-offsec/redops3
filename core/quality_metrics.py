from collections import Counter


FINDING_FAMILY_RULES = (
    ("secret_candidates", {"secret", "token", "credential", "api_key", "jwt"}),
    ("upload_retrieval_assessments", {"upload", "file_write", "retrieval", "download"}),
    ("cloud_pivot_candidates", {"cloud", "metadata", "ssrf", "pivot", "iam", "aws", "gcp", "azure"}),
    ("schema_observations", {"schema", "graphql", "object", "type_inference", "api_surface"}),
    ("mutation_candidates", {"mutation", "fuzz", "injection", "deserialization", "prototype"}),
    ("auth_identity_observations", {"auth", "session", "rbac", "access_control"}),
    ("business_logic_heuristics", {"business_logic", "logic", "workflow", "abuse"}),
    ("js_intelligence", {"javascript", "js", "frontend", "route_discovery"}),
)


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def _extract(record, key, default=None):
    if isinstance(record, dict):
        return record.get(key, default)
    return getattr(record, key, default)


def _normalize_finding_record(record):
    metadata = _as_dict(_extract(record, "metadata"))
    if not metadata:
        metadata = _as_dict(_extract(record, "metadata_json"))
    category = str(_extract(record, "category", "") or "").strip().lower()
    title = str(_extract(record, "title", "") or "").strip().lower()
    confidence = str(_extract(record, "confidence", "medium") or "medium").strip().lower()
    signal_ids = _as_list(_extract(record, "signal_ids", []))
    tool = str(_extract(record, "tool_source", "") or _extract(record, "tool", "") or "unknown").strip().lower()
    module = str(_extract(record, "module", "") or "").strip().lower()
    return {
        "category": category,
        "title": title,
        "confidence": confidence,
        "signal_ids": [sid for sid in signal_ids if isinstance(sid, int)],
        "metadata": metadata,
        "tool_source": tool,
        "module": module,
    }


def classify_finding_family(record):
    normalized = _normalize_finding_record(record)
    category = normalized["category"]
    title = normalized["title"]
    text = f"{category} {title}"

    for family, keywords in FINDING_FAMILY_RULES:
        if category in keywords:
            return family
        if any(keyword in text for keyword in keywords):
            return family

    return "findings"


def _sorted_counter(counter):
    return {key: counter[key] for key in sorted(counter.keys())}


def build_quality_metrics(*, findings, operator_actions, objectives, objective_paths, next_steps):
    normalized_findings = [_normalize_finding_record(item) for item in _as_list(findings)]
    action_items = _as_list(operator_actions)
    objective_items = _as_list(objectives)
    path_items = _as_list(objective_paths)
    next_step_items = _as_list(next_steps)

    family_counter = Counter()
    confidence_counter = Counter()
    evidence_confidence_counter = Counter()
    validation_profile_counter = Counter()
    noisy_heuristics_counter = Counter()

    findings_with_signal_lineage = 0
    findings_with_field_sources = 0

    for item in normalized_findings:
        family_counter[classify_finding_family(item)] += 1
        confidence_counter[item["confidence"] or "unknown"] += 1

        if item["signal_ids"]:
            findings_with_signal_lineage += 1

        metadata = item["metadata"]
        field_sources = _as_dict(metadata.get("field_sources"))
        if field_sources:
            findings_with_field_sources += 1

        evidence_confidence = str(metadata.get("evidence_confidence") or metadata.get("confidence") or "unknown").strip().lower()
        evidence_confidence_counter[evidence_confidence] += 1

        profile = metadata.get("validation_profile")
        if isinstance(profile, str) and profile.strip():
            validation_profile_counter[profile.strip().lower()] += 1
        elif isinstance(profile, list):
            for entry in profile:
                if isinstance(entry, str) and entry.strip():
                    validation_profile_counter[entry.strip().lower()] += 1

        if item["confidence"] in {"low", "info", "unknown"}:
            heuristic_key = str(metadata.get("heuristic_family") or item["module"] or item["tool_source"] or "unknown").strip().lower()
            noisy_heuristics_counter[heuristic_key] += 1

    action_status_counter = Counter()
    false_positive_count = 0
    for action in action_items:
        status = str(_extract(action, "status", "suggested") or "suggested").strip().lower()
        action_status_counter[status] += 1
        if status in {"invalidated", "skipped"}:
            false_positive_count += 1

    total_findings = len(normalized_findings)
    total_actions = len(action_items)

    return {
        "artifact_volume": {
            "findings": total_findings,
            "objective_paths": len(path_items),
            "next_steps": len(next_step_items),
            "operator_actions": total_actions,
            "objectives": len(objective_items),
        },
        "signal_vs_actions": {
            "signals_linked_findings": findings_with_signal_lineage,
            "findings_without_signals": max(0, total_findings - findings_with_signal_lineage),
            "operator_actions": total_actions,
        },
        "findings_by_family": _sorted_counter(family_counter),
        "confidence_distribution": _sorted_counter(confidence_counter),
        "evidence_confidence_distribution": _sorted_counter(evidence_confidence_counter),
        "validation_profiles": _sorted_counter(validation_profile_counter),
        "lineage_coverage": {
            "field_sources_present": findings_with_field_sources,
            "field_sources_missing": max(0, total_findings - findings_with_field_sources),
            "signal_lineage_present": findings_with_signal_lineage,
            "signal_lineage_missing": max(0, total_findings - findings_with_signal_lineage),
        },
        "operator_feedback": {
            "status_distribution": _sorted_counter(action_status_counter),
            "false_positive_like_actions": false_positive_count,
            "false_positive_like_ratio": round(false_positive_count / total_actions, 4) if total_actions else 0.0,
        },
        "noisy_heuristics": _sorted_counter(noisy_heuristics_counter),
        "coverage_hints": {
            "objectives_with_paths": len({item.get("objective_type") for item in path_items if isinstance(item, dict) and item.get("objective_type")}),
            "objectives_with_next_steps": len({item.get("objective_type") for item in next_step_items if isinstance(item, dict) and item.get("objective_type")}),
        },
    }
