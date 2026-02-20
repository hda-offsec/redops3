from scan_engine.helpers.attack_graph import AttackGraphBuilder


def test_attack_graph_build_resets_state_between_calls():
    builder = AttackGraphBuilder()
    sample = {
        "phases": {
            "recon": {"open_ports": [{"port": 80, "service": "http"}]},
            "enum": {"targets": {"80": ["http://example.com/"]}, "injection_points": {"80": ["q"]}},
            "vuln": {},
        }
    }

    first = builder.build(sample)
    second = builder.build(sample)

    assert len(first["nodes"]) == len(second["nodes"])
    assert len(first["edges"]) == len(second["edges"])
