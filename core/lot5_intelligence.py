import json
import re
from collections import defaultdict
from urllib.parse import urlparse

BUSINESS_TRANSITION_KEYWORDS = {
    "approve", "cancel", "refund", "promote", "publish", "invite", "share",
    "export", "archive", "restore", "revoke", "activate", "deactivate",
}

BUSINESS_SENSITIVE_KEYWORDS = {
    "admin", "support", "impersonate", "role", "permission", "billing", "plan",
    "payout", "invoice", "kyc", "compliance", "ownership",
}

BUSINESS_BULK_KEYWORDS = {"bulk", "batch", "mass", "all", "many"}

IRREVERSIBLE_HINT_KEYWORDS = {"delete", "refund", "cancel", "revoke", "archive"}

STATUS_OWNERSHIP_FIELDS = {
    "status", "state", "owner", "owner_id", "account_id", "tenant_id", "role", "permissions",
}

GRAPHQL_INTROSPECTION_MARKERS = ("__schema", "__type", "IntrospectionQuery")


JSON_BODY_CONTENT_TYPES = {
    "application/json",
    "application/graphql-response+json",
}


def _normalize_path(url_or_path):
    raw = str(url_or_path or "")
    if not raw:
        return ""
    if "://" in raw:
        try:
            return urlparse(raw).path or ""
        except Exception:
            return raw
    return raw


def _path_segments(path):
    return [s for s in str(path or "").strip("/").split("/") if s]


def _generalize_path(path):
    segments = _path_segments(path)
    generalized = []
    for seg in segments:
        if re.fullmatch(r"\d+", seg):
            generalized.append("{id}")
        elif re.fullmatch(r"[0-9a-fA-F-]{8,}", seg):
            generalized.append("{id}")
        else:
            generalized.append(seg.lower())
    return "/" + "/".join(generalized)


def _safe_json_loads(value):
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if not (text.startswith("{") or text.startswith("[")):
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _extract_body_preview(entry, request=True):
    key = "request_body_summary" if request else "response_body_summary"
    body_summary = entry.get(key) if isinstance(entry.get(key), dict) else {}
    preview = body_summary.get("preview")
    return str(preview or "")


def _extract_body_keys_from_preview(preview_text):
    parsed = _safe_json_loads(preview_text)
    if isinstance(parsed, dict):
        return sorted(parsed.keys())
    return []


def analyze_business_logic_heuristics(replay_entries):
    entries = replay_entries if isinstance(replay_entries, list) else []

    clues = []
    candidates = []
    workflow_hints = []
    sensitive_actions = []
    potential_anomalies = []

    family_methods = defaultdict(set)
    family_endpoints = defaultdict(set)
    family_actions = defaultdict(set)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        path = _normalize_path(entry.get("endpoint") or entry.get("url"))
        if not path:
            continue

        method = str(entry.get("method") or "GET").upper()
        segments = [seg.lower() for seg in _path_segments(path)]
        family = _generalize_path(path)
        family_methods[family].add(method)
        family_endpoints[family].add(path)

        status_code = entry.get("status_code")
        content_type = str(entry.get("content_type") or "").lower()
        request_preview = _extract_body_preview(entry, request=True)
        request_keys = _extract_body_keys_from_preview(request_preview)

        transition_hits = sorted({seg for seg in segments if seg in BUSINESS_TRANSITION_KEYWORDS})
        if transition_hits:
            action = transition_hits[0]
            family_actions[family].add(action)
            clues.append({
                "kind": "business_logic_clue",
                "subtype": "state_transition_hint",
                "action": action,
                "endpoint": path,
                "method": method,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route"],
                "rationale": "Route segment matches a business-state transition keyword; no exploit claim.",
            })

        if any(seg in BUSINESS_BULK_KEYWORDS for seg in segments) or any(k.lower() in {"ids", "bulk", "batch"} for k in request_keys):
            clues.append({
                "kind": "business_logic_clue",
                "subtype": "bulk_operation_hint",
                "endpoint": path,
                "method": method,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route", "replay_vault.request_body"],
                "rationale": "Endpoint or body keys indicate potential multi-object operations.",
            })

        sensitive_hits = sorted({seg for seg in segments if seg in BUSINESS_SENSITIVE_KEYWORDS})
        if sensitive_hits:
            sensitive_actions.append({
                "kind": "action_sensible_probable",
                "endpoint": path,
                "method": method,
                "keywords": sensitive_hits,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route"],
                "rationale": "Sensitive/admin-support semantic marker observed in route.",
            })

        if any(seg in IRREVERSIBLE_HINT_KEYWORDS for seg in segments):
            candidates.append({
                "kind": "business_logic_candidate",
                "subtype": "high_impact_or_irreversible_action",
                "endpoint": path,
                "method": method,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route"],
                "rationale": "Route includes action keyword often associated with irreversible impact.",
            })

        observed_high_value_fields = sorted([k for k in request_keys if k.lower() in STATUS_OWNERSHIP_FIELDS])
        if observed_high_value_fields:
            candidates.append({
                "kind": "business_logic_candidate",
                "subtype": "status_or_ownership_field",
                "endpoint": path,
                "method": method,
                "fields": observed_high_value_fields,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.request_body"],
                "rationale": "Request body includes status/ownership fields that may carry business impact.",
            })

        if isinstance(status_code, int) and status_code >= 500 and method in {"POST", "PUT", "PATCH", "DELETE"}:
            potential_anomalies.append({
                "kind": "anomalie_potentielle_non_validee",
                "subtype": "write_path_server_error",
                "endpoint": path,
                "method": method,
                "status_code": status_code,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.response"],
                "rationale": "Server-side error observed on write-like method; triage needed.",
            })

        if method in {"POST", "PUT", "PATCH", "DELETE"} and content_type in JSON_BODY_CONTENT_TYPES and not request_preview:
            potential_anomalies.append({
                "kind": "anomalie_potentielle_non_validee",
                "subtype": "write_without_body_preview",
                "endpoint": path,
                "method": method,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.request_body"],
                "rationale": "Write request captured without structured request body summary.",
            })

    for family, methods in sorted(family_methods.items()):
        has_read = "GET" in methods
        has_write = bool(methods.intersection({"POST", "PUT", "PATCH", "DELETE"}))

        if has_read and not has_write:
            candidates.append({
                "kind": "business_logic_candidate",
                "subtype": "read_write_asymmetry",
                "family": family,
                "methods": sorted(methods),
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route", "replay_vault.method"],
                "rationale": "Only read methods observed in this route family.",
            })

        if has_write and not has_read:
            candidates.append({
                "kind": "business_logic_candidate",
                "subtype": "write_without_read_asymmetry",
                "family": family,
                "methods": sorted(methods),
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route", "replay_vault.method"],
                "rationale": "Write methods observed without corresponding read path in same family.",
            })

        actions = sorted(family_actions.get(family, set()))
        if len(actions) >= 2:
            workflow_hints.append({
                "kind": "business_workflow_hint",
                "family": family,
                "actions": actions,
                "confidence": "low",
                "observation_only": True,
                "sources": ["replay_vault.route"],
                "rationale": "Multiple transition-like actions on same route family suggest multi-step workflow.",
            })

    return {
        "business_logic_clues": clues,
        "business_logic_candidates": candidates,
        "business_workflow_hints": workflow_hints,
        "sensitive_actions_probable": sensitive_actions,
        "potential_anomalies": potential_anomalies,
        "summary": {
            "clue_count": len(clues),
            "candidate_count": len(candidates),
            "workflow_hint_count": len(workflow_hints),
            "sensitive_action_count": len(sensitive_actions),
            "anomaly_count": len(potential_anomalies),
        },
    }


def extract_graphql_observation(replay_artifact):
    entry = replay_artifact if isinstance(replay_artifact, dict) else {}

    path = _normalize_path(entry.get("endpoint") or entry.get("url"))
    method = str(entry.get("method") or "GET").upper()
    content_type = str(entry.get("content_type") or "").lower()

    request_preview = _extract_body_preview(entry, request=True)
    response_preview = _extract_body_preview(entry, request=False)

    request_json = _safe_json_loads(request_preview)
    response_json = _safe_json_loads(response_preview)

    endpoint_probable = "graphql" in path.lower() or "application/graphql" in content_type

    query_text = ""
    operation_name = ""
    operation_type = ""

    if isinstance(request_json, dict):
        query_text = str(request_json.get("query") or "")
        operation_name = str(request_json.get("operationName") or "")
    elif method == "POST" and "query" in request_preview and "{" in request_preview:
        query_text = request_preview

    lower_query = query_text.lower()
    if lower_query.startswith("mutation") or " mutation " in f" {lower_query} ":
        operation_type = "mutation"
    elif lower_query.startswith("query") or " query " in f" {lower_query} ":
        operation_type = "query"

    is_introspection = any(marker.lower() in lower_query for marker in GRAPHQL_INTROSPECTION_MARKERS) or any(
        marker.lower() in response_preview.lower() for marker in GRAPHQL_INTROSPECTION_MARKERS
    )

    exposed_fields = []
    if isinstance(response_json, dict):
        data = response_json.get("data")
        if isinstance(data, dict):
            for top_key in sorted(data.keys()):
                exposed_fields.append(top_key)
                nested = data.get(top_key)
                if isinstance(nested, dict):
                    for child in sorted(list(nested.keys())[:8]):
                        exposed_fields.append(f"{top_key}.{child}")

    return {
        "graphql_endpoint_probable": bool(endpoint_probable or query_text),
        "graphql_operation_observed": bool(query_text),
        "endpoint": path,
        "method": method,
        "operation_name": operation_name or None,
        "operation_type": operation_type or None,
        "introspection_clue": bool(is_introspection),
        "field_exposure_clues": exposed_fields[:24],
        "observation_only": True,
        "rationale": "GraphQL observations are derived from replay request/response structure only.",
    }


def analyze_graphql_surface(replay_entries):
    entries = replay_entries if isinstance(replay_entries, list) else []
    observations = []

    by_endpoint_operation = defaultdict(set)

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        obs = extract_graphql_observation(entry)
        if not obs.get("graphql_endpoint_probable"):
            continue
        observations.append(obs)

        endpoint = obs.get("endpoint") or ""
        op_name = obs.get("operation_name") or f"<{obs.get('operation_type') or 'unknown'}>"
        identity_context = entry.get("identity_context") if isinstance(entry.get("identity_context"), dict) else {}
        identity_key = str(identity_context.get("identity") or identity_context.get("role") or identity_context.get("actor") or "anonymous")
        status_code = entry.get("status_code") if isinstance(entry.get("status_code"), int) else None
        by_endpoint_operation[(endpoint, op_name)].add((identity_key, status_code))

    auth_drift_candidates = []
    for (endpoint, op_name), observed_pairs in sorted(by_endpoint_operation.items()):
        statuses = sorted({p[1] for p in observed_pairs if p[1] is not None})
        identities = sorted({p[0] for p in observed_pairs if p[0]})
        if len(identities) >= 2 and len(statuses) >= 2:
            auth_drift_candidates.append({
                "kind": "auth_drift_candidate_non_valide",
                "endpoint": endpoint,
                "operation_name": op_name,
                "identities": identities,
                "status_codes": statuses,
                "confidence": "low",
                "observation_only": True,
                "rationale": "Different identities observed different status outcomes for same GraphQL operation.",
                "sources": ["replay_vault.identity_context", "replay_vault.status_code"],
            })

    return {
        "graphql_endpoint_probables": [
            {
                "endpoint": obs.get("endpoint"),
                "method": obs.get("method"),
                "observation_only": True,
            }
            for obs in observations
        ],
        "graphql_operations_observed": [
            {
                "endpoint": obs.get("endpoint"),
                "operation_name": obs.get("operation_name"),
                "operation_type": obs.get("operation_type"),
                "observation_only": True,
            }
            for obs in observations
            if obs.get("graphql_operation_observed")
        ],
        "introspection_clues": [
            {
                "endpoint": obs.get("endpoint"),
                "operation_name": obs.get("operation_name"),
                "observation_only": True,
            }
            for obs in observations
            if obs.get("introspection_clue")
        ],
        "field_exposure_clues": [
            {
                "endpoint": obs.get("endpoint"),
                "fields": obs.get("field_exposure_clues") or [],
                "observation_only": True,
            }
            for obs in observations
            if obs.get("field_exposure_clues")
        ],
        "auth_drift_candidates": auth_drift_candidates,
        "summary": {
            "endpoint_count": len([o for o in observations if o.get("graphql_endpoint_probable")]),
            "operation_count": len([o for o in observations if o.get("graphql_operation_observed")]),
            "introspection_count": len([o for o in observations if o.get("introspection_clue")]),
            "auth_drift_candidate_count": len(auth_drift_candidates),
        },
    }


def build_feedback_profile(feedback_rows):
    rows = feedback_rows if isinstance(feedback_rows, list) else []

    family_scores = defaultdict(int)
    subject_scores = defaultdict(int)
    reason_map = defaultdict(list)

    for row in rows:
        item = row if isinstance(row, dict) else {}
        sentiment = int(item.get("sentiment") or 0)
        sentiment = max(-1, min(1, sentiment))

        subject_key = str(item.get("subject_key") or "").strip().lower()
        signal_family = str(item.get("signal_family") or "").strip().lower()
        feedback_type = str(item.get("feedback_type") or "unknown").strip().lower()

        if subject_key:
            subject_scores[subject_key] += sentiment
            reason_map[f"subject:{subject_key}"].append(feedback_type)
        if signal_family:
            family_scores[signal_family] += sentiment
            reason_map[f"family:{signal_family}"].append(feedback_type)

    for key in list(subject_scores.keys()):
        subject_scores[key] = max(-20, min(20, subject_scores[key]))
    for key in list(family_scores.keys()):
        family_scores[key] = max(-20, min(20, family_scores[key]))

    reason_summary = {}
    for key, reasons in reason_map.items():
        counts = defaultdict(int)
        for reason in reasons:
            counts[reason] += 1
        reason_summary[key] = [{"feedback_type": r, "count": counts[r]} for r in sorted(counts.keys())]

    return {
        "subject_scores": dict(sorted(subject_scores.items())),
        "family_scores": dict(sorted(family_scores.items())),
        "reasons": reason_summary,
        "row_count": len(rows),
    }


def apply_feedback_to_operator_actions(actions, feedback_profile):
    action_list = actions if isinstance(actions, list) else []
    profile = feedback_profile if isinstance(feedback_profile, dict) else {}
    subject_scores = profile.get("subject_scores") if isinstance(profile.get("subject_scores"), dict) else {}
    family_scores = profile.get("family_scores") if isinstance(profile.get("family_scores"), dict) else {}

    adjusted = []
    for action in action_list:
        row = dict(action) if isinstance(action, dict) else {}

        action_type_key = str(row.get("action_type") or "").strip().lower()
        objective_key = str(row.get("objective_type") or "").strip().lower()

        delta = 0
        factors = []

        if action_type_key and action_type_key in subject_scores:
            d = int(subject_scores[action_type_key])
            delta += d
            factors.append({"scope": "action_type", "key": action_type_key, "delta": d})

        if objective_key and objective_key in subject_scores:
            d = int(subject_scores[objective_key])
            delta += d
            factors.append({"scope": "objective_type", "key": objective_key, "delta": d})

        family_key = str(row.get("metadata", {}).get("feedback_family") or "").strip().lower() if isinstance(row.get("metadata"), dict) else ""
        if family_key and family_key in family_scores:
            d = int(family_scores[family_key])
            delta += d
            factors.append({"scope": "signal_family", "key": family_key, "delta": d})

        delta = max(-20, min(20, delta))

        base_confidence = float(row.get("confidence") or 0.0)
        adjusted_confidence = max(0.0, min(1.0, round(base_confidence + (delta * 0.01), 2)))

        row["feedback_adjustment"] = {
            "delta": delta,
            "factors": factors,
            "profile_row_count": int(profile.get("row_count") or 0),
            "observation_only": True,
            "rationale": "Local deterministic adjustment from explicit operator feedback.",
        }
        row["confidence_before_feedback"] = round(base_confidence, 2)
        row["confidence"] = adjusted_confidence
        row["feedback_adjusted"] = delta != 0
        adjusted.append(row)

    adjusted.sort(
        key=lambda a: (
            int((a.get("feedback_adjustment") or {}).get("delta") or 0),
            float(a.get("confidence") or 0.0),
            str(a.get("attack_priority") or ""),
            str(a.get("action_key") or ""),
        ),
        reverse=True,
    )
    return adjusted
