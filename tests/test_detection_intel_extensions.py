from scan_engine.helpers.passive_intel_engine import PassiveIntelligenceEngine
from scan_engine.helpers.attack_graph import AttackGraphBuilder
from scan_engine.helpers.api_reconstructor import ApiReconstructor
from scan_engine.helpers.vuln_execution_plan import derive_vuln_execution_plan
from scan_engine.orchestrator import ScanOrchestrator
from types import SimpleNamespace


def _sample_results():
    return {
        "target": "example.com",
        "phases": {
            "recon": {"open_ports": [{"port": 443, "service": "https"}]},
            "enum": {
                "targets": {
                    "443": [
                        "https://example.com/swagger",
                        "https://example.com/login",
                        "https://example.com/upload",
                    ]
                },
                "injection_points": {"443": ["__proto__", "redirect_url"]},
                "headers": {
                    "443": {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": "true",
                        "Authorization": "Bearer aaa.bbb.ccc",
                        "Set-Cookie": "jwt=aaa.bbb.ccc",
                    }
                },
                "js_deep_mining": {
                    "discovered_endpoints": ["/api/private/auth"],
                    "findings": [
                        {"source": "/static/app.js", "details": {"secrets": [{"type": "Token", "value": "aaa.bbb.ccc"}]}}
                    ],
                },
            },
            "dirbusting": {"ffuf": {"endpoints": ["https://example.com/api-docs"]}},
            "intel": {"notes": "169.254.169.254 and s3.amazonaws.com token=abc"},
        },
    }


def test_passive_intel_expected_categories_present():
    findings = PassiveIntelligenceEngine.derive_findings(_sample_results(), "example.com")
    categories = {f.get("category") for f in findings}

    assert "api_surface" in categories
    assert "auth_surface" in categories
    assert "prototype_pollution_surface" in categories
    assert "jwt_exposure" in categories
    assert "cors_misconfiguration" in categories
    assert "ssrf_surface" in categories
    assert "metadata_service_exposure" in categories
    assert "cloud_storage_reference" in categories
    assert "token_leakage" in categories


def test_attack_graph_adds_new_surface_nodes_and_edges():
    builder = AttackGraphBuilder()
    graph = builder.build(
        {
            "target": "example.com",
            "findings": [
                {"id_stable": "a1", "title": "Authentication Surface Endpoint Discovered", "category": "auth_surface", "endpoint": "https://example.com/login"},
                {"id_stable": "a2", "title": "API Surface Endpoint Discovered", "category": "api_surface", "endpoint": "https://example.com/swagger"},
                {"id_stable": "a3", "title": "JWT Token Observed", "category": "jwt_exposure", "endpoint": "https://example.com/api"},
                {"id_stable": "a4", "title": "Attack Chain: API Surface + Token Exposure", "category": "attack_chain", "endpoint": "https://example.com/api", "metadata": {"chain": ["api_surface", "token_exposure"]}},
            ],
            "phases": {"recon": {"open_ports": []}, "enum": {}, "vuln": {}},
        }
    )

    node_types = {n.get("type") for n in graph["nodes"]}
    edge_types = {e.get("type") for e in graph["edges"]}

    assert "auth_surface" in node_types
    assert "api_endpoint" in node_types
    assert "token" in node_types
    assert "attack_chain" in node_types

    assert "auth_exposes" in edge_types
    assert "token_authenticates" in edge_types
    assert "depends_on" in edge_types
    assert "leads_to" in edge_types


def test_vuln_execution_plan_enables_adaptive_modules_when_signals_exist():
    plan = derive_vuln_execution_plan(
        {
            "phases": {
                "enum": {
                    "katana": {"443": ["https://example.com/app.js", "https://example.com/graphql"]},
                    "injection_points": {"443": ["https://example.com/search?q=1"]},
                    "api": {"discovered_endpoints": ["https://example.com/api/v1/users"]},
                }
            }
        },
        443,
        profile="quick",
        execution_hints={},
    )

    assert plan["graphql_scanner"]["enabled"] is True
    assert plan["ssrf_expert"]["enabled"] is True
    assert plan["dalfox"]["enabled"] is True
    assert plan["js_vuln_audit"]["enabled"] is True
    assert plan["parameter_miner"]["enabled"] is True
    assert plan["api_fuzzer"]["enabled"] is True


def test_orchestrator_quality_gate_rejects_unproven_critical():
    persisted = []
    orch = ScanOrchestrator(
        scan_id=1,
        target="example.com",
        logger_func=lambda *_args, **_kwargs: None,
        finding_func=lambda **kwargs: persisted.append(kwargs),
        suggestion_func=lambda **_kwargs: None,
        results_func=lambda *_args, **_kwargs: None,
        signal_func=lambda **_kwargs: SimpleNamespace(id=55),
        options={"strict_quality_gates": True},
    )

    orch.add_finding(
        title="Potential RCE",
        description="Generic high-level claim without evidence.",
        severity="critical",
        tool_source="unit",
        confidence="high",
    )

    assert persisted == []
    assert orch.results.get("metrics", {}).get("quality_gate_rejected") == 1


def test_orchestrator_quality_gate_accepts_proven_critical():
    persisted = []
    orch = ScanOrchestrator(
        scan_id=2,
        target="example.com",
        logger_func=lambda *_args, **_kwargs: None,
        finding_func=lambda **kwargs: persisted.append(kwargs),
        suggestion_func=lambda **_kwargs: None,
        results_func=lambda *_args, **_kwargs: None,
        signal_func=lambda **_kwargs: SimpleNamespace(id=77),
        options={"strict_quality_gates": True},
    )

    orch.add_finding(
        title="RCE validated",
        description="Validated with deterministic proof.",
        severity="critical",
        tool_source="unit",
        endpoint="https://example.com/api",
        evidence="Server returned marker REDOPS_POC",
        response="HTTP/1.1 200 OK",
    )

    assert len(persisted) == 1
    assert 77 in (persisted[0].get("signal_ids") or [])
    assert str(persisted[0].get("repro_command", "")).startswith("curl -ik")


def _api_tree_find_node(tree, port, path_parts):
    port_node = next((node for node in tree.get("children", []) if node.get("type") == "port" and node.get("port") == port), None)
    assert port_node is not None
    children = port_node.get("children", [])
    current = None
    for part in path_parts:
        current = next((node for node in children if node.get("name") == part), None)
        assert current is not None
        children = current.get("children", [])
    return current


def test_api_reconstructor_marks_unverified_templated_routes_as_non_clickable():
    results = {
        "target": "example.com",
        "phases": {
            "recon": {"open_ports": [{"port": 443}]},
            "enum": {"api": {"discovered_endpoints": ["/locales/{{lng}}/{{ns}}.json"]}},
        },
    }

    tree = ApiReconstructor.reconstruct(results, findings=[])
    leaf = _api_tree_find_node(tree, 443, ["locales", "{{lng}}", "{{ns}}.json"])

    assert leaf.get("status") is None
    assert leaf.get("status_source") == "unverified"
    assert leaf.get("templated") is True
    assert leaf.get("clickable") is False


def test_api_reconstructor_uses_dirbusting_status_when_present():
    results = {
        "target": "example.com",
        "phases": {
            "recon": {"open_ports": [{"port": 443}]},
            "enum": {"api": {"discovered_endpoints": ["https://example.com/swagger.json"]}},
            "dirbusting": {
                "443": {
                    "ffuf": {
                        "endpoints": [
                            {"url": "https://example.com/swagger.json", "status": 404, "source": "ffuf"}
                        ]
                    }
                }
            },
        },
    }

    tree = ApiReconstructor.reconstruct(results, findings=[])
    leaf = _api_tree_find_node(tree, 443, ["swagger.json"])

    assert leaf.get("status") == 404
    assert str(leaf.get("status_source", "")).startswith("dirbusting")
    assert leaf.get("clickable") is True


def test_api_reconstructor_normalizes_query_for_status_and_findings():
    results = {
        "target": "example.com",
        "phases": {
            "recon": {"open_ports": [{"port": 443}]},
            "enum": {
                "api": {
                    "discovered_endpoints": ["https://example.com/graphql?query=%7Bme%7D"],
                    "endpoints": [{"url": "https://example.com/graphql", "status": "401", "source": "api_discovery"}],
                }
            },
        },
    }
    findings = [
        {
            "id_stable": "finding-graphql",
            "severity": "high",
            "title": "GraphQL auth bypass",
            "endpoint": "https://example.com/graphql?operationName=IntrospectionQuery",
        }
    ]

    tree = ApiReconstructor.reconstruct(results, findings=findings)
    leaf = _api_tree_find_node(tree, 443, ["graphql"])

    assert leaf.get("status") == 401
    assert len(leaf.get("findings") or []) == 1
    assert leaf["findings"][0]["id"] == "finding-graphql"
