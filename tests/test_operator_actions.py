from types import SimpleNamespace

from core.mission_intelligence import (
    derive_operator_actions,
    is_valid_action_transition,
    _execution_dashboard,
)


def _finding(fid, title, severity="medium", category="auth_surface", signal_ids=None, exploit_score=50, asset_ids=None, target_id=1):
    links = [SimpleNamespace(asset_id=a) for a in (asset_ids or [1])]
    target = SimpleNamespace(asset_links=links)
    scan = SimpleNamespace(target=target, target_id=target_id)
    return SimpleNamespace(
        id=fid,
        title=title,
        severity=severity,
        category=category,
        description=title,
        endpoint="/api/test",
        target="example.com",
        signal_ids=signal_ids or [],
        metadata_json={"exploit_score": exploit_score},
        scan=scan,
    )


def test_operator_actions_are_evidence_backed_and_deterministic():
    findings = [
        _finding(1, "Auth token discovered", severity="high", category="jwt_exposure", signal_ids=[101], asset_ids=[1, 2]),
        _finding(2, "Admin route found", severity="high", category="auth_surface", signal_ids=[102], asset_ids=[2]),
    ]
    objectives = [{
        "objective_type": "admin_access",
        "priority": "high",
        "confidence": 0.8,
        "required_conditions": ["validated admin or privileged route"],
        "supporting_findings": [1, 2],
        "supporting_signals": [101, 102],
        "recommended_next_steps": ["Review privileged routes"],
    }]

    actions_a = derive_operator_actions(objectives, findings)
    actions_b = derive_operator_actions(objectives, findings)

    assert actions_a
    assert actions_a == actions_b
    assert all(a["related_finding_ids"] for a in actions_a)
    assert all(a["evidence_summary"] for a in actions_a)


def test_blockers_appear_when_signal_lineage_missing():
    findings = [_finding(3, "Possible SSRF param", category="ssrf", signal_ids=[])]
    objectives = [{
        "objective_type": "cloud_credential_access",
        "priority": "medium",
        "confidence": 0.5,
        "required_conditions": ["cloud reference"],
        "supporting_findings": [3],
        "supporting_signals": [],
        "recommended_next_steps": ["Review metadata routes"],
    }]

    actions = derive_operator_actions(objectives, findings)
    assert actions
    assert any(a["status"] == "blocked" for a in actions)
    assert any(a["blocker_summary"]["blocker_count"] > 0 for a in actions)


def test_action_status_transitions_are_bounded():
    assert is_valid_action_transition("suggested", "reviewed")
    assert is_valid_action_transition("reviewed", "queued")
    assert is_valid_action_transition("queued", "executed")
    assert not is_valid_action_transition("suggested", "executed")


def test_execution_dashboard_aggregation():
    objectives = [{"objective_type": "admin_access", "status": "ready", "priority": "high", "readiness_score": 80, "required_conditions": []}]
    actions = [
        {"title": "Review auth flow", "status": "suggested", "confidence": 0.9, "estimated_value": "high", "attack_priority": "high", "objective_type": "admin_access"},
        {"title": "Inspect admin path", "status": "blocked", "confidence": 0.7, "estimated_value": "medium", "attack_priority": "medium", "objective_type": "admin_access"},
    ]
    objective_paths = [{"objective_type": "admin_access", "confidence": 0.8, "metadata": {"exploit_score": 70}}]
    dashboard = _execution_dashboard(objectives, objective_paths, actions, [])

    assert dashboard["action_counts_by_status"]["suggested"] == 1
    assert dashboard["action_counts_by_status"]["blocked"] == 1
    assert dashboard["most_valuable_next_action"]["title"] == "Review auth flow"


def test_operator_actions_include_required_execution_fields():
    findings = [_finding(9, "Git exposure at /.git", severity="high", category="git_exposure", signal_ids=[301], asset_ids=[5], target_id=7)]
    objectives = [{
        "objective_type": "source_code_access",
        "priority": "high",
        "confidence": 0.7,
        "required_conditions": ["source artifact exposed"],
        "supporting_findings": [9],
        "supporting_signals": [301],
        "recommended_next_steps": ["Inspect exposed source artifacts"],
    }]
    action = derive_operator_actions(objectives, findings)[0]

    for key in (
        "objective_type",
        "action_type",
        "title",
        "description",
        "rationale",
        "attack_priority",
        "estimated_value",
        "estimated_complexity",
        "required_conditions",
        "related_asset_ids",
        "related_target_ids",
        "related_finding_ids",
        "related_signal_ids",
        "evidence_summary",
        "blocker_summary",
        "action_key",
    ):
        assert key in action
