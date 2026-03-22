from types import SimpleNamespace

from adapters.detection_adapter import DetectionAdapter


def _db_finding(**overrides):
    payload = {
        "id": 7,
        "id_stable": "stable-db-1",
        "title": "Observed GraphQL Schema Leak",
        "severity": "high",
        "description": "Schema still visible.\nState: OPEN",
        "tool_source": "nuclei",
        "confidence": "medium",
        "request": "GET /graphql HTTP/1.1",
        "response": "HTTP/1.1 200 OK",
        "repro_command": "curl -isk https://example.org/graphql",
        "screenshot_path": "loot/graphql.png",
        "target": "https://example.org/graphql",
        "endpoint": "https://example.org/graphql",
        "parameter": "query",
        "payload": "{__schema{types{name}}}",
        "raw_output": "HTTP/1.1 200 OK\nschema",
        "signal_ids": [3, 2],
        "category": "api",
        "evidence": "Query type returned",
        "reproduction": "Replay the introspection request safely.",
        "module": "graphql_scanner",
        "metadata_json": {"field_sources": {"endpoint": "db"}, "verified": True},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def test_normalize_findings_preserves_db_json_and_synthetic_contract():
    db_findings = [_db_finding()]
    json_results = {
        "phases": {
            "enum": {
                "nuclei": {
                    "findings": [
                        {
                            "title": "",
                            "description": "\x1b[31mReflected XSS on search endpoint\x1b[0m",
                            "severity": "high",
                            "endpoint": "https://example.org/search?q=1",
                            "parameter": "q",
                            "payload": "<svg/onload=alert(1)>",
                            "raw_output": "\x1b[31mHTTP 200 reflected\x1b[0m",
                            "metadata": {"field_sources": {"payload": "json"}},
                        }
                    ]
                },
                "headers": {
                    "443": {
                        "Content-Security-Policy": {"status": "missing"},
                        "X-Frame-Options": {"status": "missing"},
                    }
                },
            }
        }
    }

    findings, stats = DetectionAdapter.normalize_findings(
        db_findings,
        json_results,
        return_stats=True,
    )

    assert len(findings) == 3
    assert stats["db_findings_received"] == 1
    assert stats["json_findings_received"] == 1
    assert stats["findings_exposed"] == 3

    db_entry = next(f for f in findings if f["id_stable"] == "stable-db-1")
    assert db_entry["metadata"]["port_state"] == "open"
    assert db_entry["confidence"] == "high"
    assert db_entry["severity"] == "high"
    assert db_entry["endpoint"] == "https://example.org/graphql"

    json_entry = next(f for f in findings if f["parameter"] == "q")
    assert json_entry["title"] == "Reflected XSS on search endpoint"
    assert "\x1b" not in json_entry["raw_output"]
    assert json_entry["payload"] == "<svg/onload=alert(1)>"
    assert json_entry["metadata"]["field_sources"]["payload"] == "json"

    synthetic_entry = next(f for f in findings if f["tool_source"] == "header_audit")
    assert synthetic_entry["title"] == "Missing Security Headers (port 443)"
    assert synthetic_entry["severity"] == "low"
    assert synthetic_entry["description"] == "Content-Security-Policy\nX-Frame-Options"


def test_normalize_findings_merges_identical_records_and_preserves_lineage():
    stable_id = DetectionAdapter._make_id(
        "nuclei",
        "Shared title",
        endpoint="https://example.org/a",
        parameter="id",
        severity="medium",
    )
    json_results = {
        "phases": {
            "enum": {
                "nuclei": {
                    "findings": [
                        {
                            "id_stable": stable_id,
                            "title": "Shared title",
                            "severity": "medium",
                            "endpoint": "https://example.org/a",
                            "parameter": "id",
                            "raw_output": "first artifact",
                            "evidence": "first evidence",
                            "signal_ids": [1, 2],
                            "metadata": {
                                "field_sources": {"endpoint": "json_a"},
                                "chain": ["enum-a"],
                            },
                        },
                        {
                            "id_stable": stable_id,
                            "title": "Shared title",
                            "severity": "medium",
                            "endpoint": "https://example.org/a",
                            "parameter": "id",
                            "raw_output": "second artifact",
                            "evidence": "second evidence",
                            "signal_ids": [2, 3],
                            "metadata": {
                                "field_sources": {"payload": "json_b"},
                                "chain": ["enum-a", "enum-b"],
                            },
                        },
                        {
                            "title": "Shared title",
                            "severity": "medium",
                            "endpoint": "https://example.org/b",
                            "parameter": "id",
                            "raw_output": "distinct artifact",
                        },
                    ]
                }
            }
        }
    }

    findings, stats = DetectionAdapter.normalize_findings([], json_results, return_stats=True)

    assert len(findings) == 2
    assert stats["dedup_merged"] == 1
    merged = next(f for f in findings if f["endpoint"] == "https://example.org/a")
    distinct = next(f for f in findings if f["endpoint"] == "https://example.org/b")

    assert merged["id_stable"] == stable_id
    assert merged["signal_ids"] == [1, 2, 3]
    assert "first artifact" in merged["raw_output"]
    assert "second artifact" in merged["raw_output"]
    assert "first evidence" in merged["evidence"]
    assert "second evidence" in merged["evidence"]
    assert merged["metadata"]["field_sources"]["endpoint"] == "json_a"
    assert merged["metadata"]["field_sources"]["payload"] == "json_b"
    assert merged["chain_length"] == 2
    assert distinct["id_stable"] != stable_id


def test_normalize_findings_observability_counters_remain_stable_for_rejections_and_filters():
    json_results = {
        "phases": {
            "enum": {
                "bad_payload": "not-a-list",
                "nuclei": {
                    "findings": [
                        {},
                        {
                            "severity": "medium",
                            "endpoint": "https://example.org/empty",
                        },
                    ]
                },
                "derived": {
                    "cortex_recommendations": [
                        {
                            "title": "Virtual Host Brute (port 443)",
                            "reason": "",
                            "confidence": 90,
                            "port": "443",
                        },
                        {
                            "title": "Interesting route follow-up",
                            "reason": "Observed admin route",
                            "confidence": 50,
                            "port": "443",
                        },
                    ]
                },
            },
            "bad_phase": "invalid",
        }
    }

    findings, stats = DetectionAdapter.normalize_findings([], json_results, return_stats=True)

    assert findings == []
    assert stats["findings_received"] == 1
    assert stats["json_findings_received"] == 1
    assert stats["json_items_skipped_empty_dict"] == 1
    assert stats["json_items_skipped_without_content"] == 1
    assert stats["findings_rejected"] == 1
    assert stats["tool_payloads_skipped_non_list"] == 1
    assert stats["phases_skipped_non_mapping"] == 1
    assert stats["cortex_noise_filtered"] == 1
    assert stats["cortex_low_confidence_filtered"] == 1
