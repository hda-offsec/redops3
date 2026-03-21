import unittest
from pathlib import Path
import ast
import re
from datetime import datetime
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.findings_ui_contract import (
    CANONICAL_UI_FIELDS,
    DETAIL_COMMAND_BLOCK_SOURCES,
    DETAIL_CONTRACT_FIELDS,
    DETAIL_EVIDENCE_BLOCK_SOURCES,
    OBSERVED_VERSION_FIELD_SOURCES,
    SEARCH_TEXT_FIELD_SOURCES,
    attach_finding_ui_contract,
    attach_finding_ui_contracts,
    build_finding_detail_contract,
)
from ui.web.views.main import _serialize_db_finding_payload


def _structured_finding():
    return {
        "id": "db-1",
        "id_stable": "stable-1",
        "title": "GraphQL schema leak",
        "severity": "high",
        "confidence": "high",
        "tool_source": "nuclei",
        "tool": "nuclei",
        "source": "nuclei",
        "module": "graphql_scanner",
        "category": "api",
        "description": "Introspection is still reachable on the public GraphQL endpoint.",
        "endpoint": "https://example.org/api/graphql",
        "target": "https://example.org/api/graphql",
        "parameter": "query",
        "raw_output": "HTTP/1.1 200 OK\n{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}",
        "evidence": "Schema introspection returned the Query type.",
        "reproduction": "Validate that introspection stays enabled before blocking public access.",
        "remediation": "Disable introspection on public environments and restrict the endpoint.",
        "request": "GET /api/graphql?query={__schema} HTTP/1.1",
        "response": "HTTP/1.1 200 OK\ncontent-type: application/json",
        "impact": "Public schema exposure accelerates targeted abuse and enumeration.",
        "references": [
            "https://owasp.org/www-project-graphql-security-cheat-sheet/",
        ],
        "screenshot_path": "loot/graphql-proof.png",
        "metadata": {
            "provider": "aws",
            "component": "apigateway",
            "version": "2024.1",
            "versions": ["graphql-js 16.8.1"],
            "port_state": "open",
            "impact_area": "API Gateway",
            "artifacts": [{"header": "x-powered-by", "value": "graphql-js"}],
            "references": [
                "https://graphql.org/learn/security/",
            ],
            "validation": {
                "status": "success",
                "result_state": "confirmed",
                "command": "curl -isk 'https://example.org/api/graphql?query={__schema}'",
                "target": "https://example.org/api/graphql",
                "artifact": "HTTP/1.1 200 OK",
            },
            "reproducibility": {
                "command": "nuclei -u https://example.org/api/graphql",
                "url": "https://fallback.example.org/graphql",
                "request_excerpt": "GET /api/graphql HTTP/1.1",
                "response_excerpt": "HTTP/1.1 200 OK\nx-powered-by: graphql-js",
            },
        },
    }


def _extract_js_array_constant(const_name):
    source = Path("ui/web/static/js/findings_contract.js").read_text()
    match = re.search(rf"const {const_name} = \[(.*?)\];", source, re.DOTALL)
    if not match:
        raise AssertionError(f"Missing JS constant {const_name}")
    return ast.literal_eval(f"[{match.group(1)}]")


class FindingsUiContractTests(unittest.TestCase):
    def test_backend_contract_constants_are_stable(self):
        self.assertEqual(
            CANONICAL_UI_FIELDS,
            (
                "validationStatus",
                "resultState",
                "primaryCommand",
                "primaryUrl",
                "provider",
                "component",
                "version",
                "portState",
                "hasEvidence",
                "isValidated",
                "searchText",
            ),
        )
        self.assertEqual(
            SEARCH_TEXT_FIELD_SOURCES,
            (
                "title",
                "tool_source",
                "tool",
                "source",
                "category",
                "primary_url",
                "target",
                "provider",
                "component",
                "version",
                "validation_status",
                "result_state",
                "validated_token",
                "parameter",
                "port_state",
            ),
        )
        self.assertEqual(
            OBSERVED_VERSION_FIELD_SOURCES,
            (
                "version",
                "metadata.version",
                "metadata.service_version",
                "metadata.detected_version",
                "metadata.component_version",
            ),
        )
        self.assertEqual(
            DETAIL_COMMAND_BLOCK_SOURCES,
            (
                "validation.command",
                "reproducibility.command",
                "repro_command",
            ),
        )
        self.assertEqual(
            DETAIL_EVIDENCE_BLOCK_SOURCES,
            (
                "validation.artifact",
                "request",
                "response",
                "raw_output",
                "evidence",
            ),
        )
        self.assertEqual(
            DETAIL_CONTRACT_FIELDS,
            (
                "summary",
                "technicalContext",
                "commandExecuted",
                "commandBlocks",
                "validationGuidance",
                "target",
                "observedVersions",
                "evidenceBlocks",
                "rawOutput",
                "interpretation",
                "severity",
                "confidence",
                "remediation",
                "references",
                "artifacts",
            ),
        )

    def test_backend_and_frontend_constants_stay_in_sync(self):
        self.assertEqual(tuple(_extract_js_array_constant("CANONICAL_UI_FIELDS")), CANONICAL_UI_FIELDS)
        self.assertEqual(tuple(_extract_js_array_constant("SEARCH_TEXT_FIELD_SOURCES")), SEARCH_TEXT_FIELD_SOURCES)
        self.assertEqual(
            tuple(_extract_js_array_constant("OBSERVED_VERSION_FIELD_SOURCES")),
            OBSERVED_VERSION_FIELD_SOURCES,
        )
        self.assertEqual(
            tuple(_extract_js_array_constant("DETAIL_COMMAND_BLOCK_SOURCES")),
            DETAIL_COMMAND_BLOCK_SOURCES,
        )
        self.assertEqual(
            tuple(_extract_js_array_constant("DETAIL_EVIDENCE_BLOCK_SOURCES")),
            DETAIL_EVIDENCE_BLOCK_SOURCES,
        )
        self.assertEqual(
            tuple(_extract_js_array_constant("DETAIL_CONTRACT_FIELDS")),
            DETAIL_CONTRACT_FIELDS,
        )

    def test_scan_dashboard_uses_shared_findings_contract(self):
        content = Path("ui/web/static/js/scan_dashboard.js").read_text()
        for token in [
            "getFindingsContract()",
            "normalizeFindingRecord(finding)",
            "applyRowDataset(tr, data)",
            "getFindingsContract().applyTableFilters()",
            "deriveAuditJourney",
            "updateAuditJourney",
            "window.goToAuditStage",
            "window.applyTacticalFilter",
        ]:
            self.assertIn(token, content)

    def test_shared_js_contract_exposes_pure_and_dom_namespaces(self):
        content = Path("ui/web/static/js/findings_contract.js").read_text()
        for token in [
            "const contractApi = {",
            "const domApi = {",
            "contract: contractApi",
            "dom: domApi",
            "const CANONICAL_UI_FIELDS = [",
            "const SEARCH_TEXT_FIELD_SOURCES = [",
            "buildFindingSearchTextFields",
            "buildFindingDetailState",
            "buildFindingDetailHtml",
        ]:
            self.assertIn(token, content)

    def test_findings_detail_panel_uses_shared_contract_and_encoded_actions(self):
        content = Path("ui/web/templates/scan_partials/interface/findings.html").read_text()
        for token in [
            "normalizeFindingRecord(finding)",
            "findingsContract.dom.buildFindingDetailHtml(f)",
            "findingsContract.dom.handleCopyButtonClick(event)",
            "panel.innerHTML = findingsContract.dom.buildFindingDetailHtml(f);",
        ]:
            self.assertIn(token, content)

    def test_scannmap_results_uses_shared_findings_detail_renderer(self):
        content = Path("ui/web/templates/scannmap_results.html").read_text()
        for token in [
            "findingsContract.dom.buildFindingDetailHtml(f)",
            "findingsContract.dom.handleCopyButtonClick(event)",
        ]:
            self.assertIn(token, content)

    def test_attach_finding_ui_contract_prefers_structured_command_and_url(self):
        finding = attach_finding_ui_contract(_structured_finding())

        self.assertEqual(
            finding["_ui"]["primaryCommand"],
            "curl -isk 'https://example.org/api/graphql?query={__schema}'",
        )
        self.assertEqual(finding["_ui"]["primaryUrl"], "https://example.org/api/graphql")
        self.assertEqual(finding["_ui"]["validationStatus"], "success")
        self.assertEqual(finding["_ui"]["resultState"], "confirmed")
        self.assertTrue(finding["_ui"]["hasEvidence"])
        self.assertTrue(finding["_ui"]["isValidated"])
        self.assertEqual(
            finding["_ui"]["searchText"],
            "graphql schema leak nuclei api https://example.org/api/graphql aws apigateway 2024.1 success confirmed validated query open",
        )

    def test_build_finding_detail_contract_preserves_rich_evidence_and_context(self):
        detail = build_finding_detail_contract(_structured_finding())

        self.assertEqual(
            detail["commandExecuted"],
            "curl -isk 'https://example.org/api/graphql?query={__schema}'",
        )
        self.assertEqual(detail["target"], "https://example.org/api/graphql")
        self.assertEqual(detail["observedVersions"], ["2024.1", "graphql-js 16.8.1"])
        self.assertEqual(
            [block["key"] for block in detail["commandBlocks"]],
            ["validation_command", "reproducibility_command"],
        )
        self.assertEqual(tuple(detail.keys()), DETAIL_CONTRACT_FIELDS)
        self.assertEqual(
            [block["key"] for block in detail["evidenceBlocks"]],
            ["validation_artifact", "request", "response", "raw_output", "evidence"],
        )
        self.assertEqual(detail["validationGuidance"], "Validate that introspection stays enabled before blocking public access.")
        self.assertEqual(detail["severity"], "high")
        self.assertEqual(detail["confidence"], "high")
        self.assertEqual(detail["remediation"], "Disable introspection on public environments and restrict the endpoint.")
        self.assertEqual(
            detail["references"],
            [
                "https://owasp.org/www-project-graphql-security-cheat-sheet/",
                "https://graphql.org/learn/security/",
            ],
        )
        self.assertEqual(detail["artifacts"][0]["kind"], "image")
        self.assertEqual(detail["artifacts"][0]["value"], "loot/graphql-proof.png")
        self.assertEqual(detail["artifacts"][1]["kind"], "text")

    def test_attach_finding_ui_contract_rejects_narrative_reproduction(self):
        finding = attach_finding_ui_contract(
            {
                "title": "Manual validation note",
                "severity": "medium",
                "tool_source": "manual",
                "category": "review",
                "reproduction": "Open the admin page in a browser and inspect the banner manually.",
                "metadata": {},
            }
        )

        self.assertEqual(finding["_ui"]["primaryCommand"], "")
        self.assertEqual(finding["_ui"]["validationStatus"], "not_run")
        self.assertEqual(finding["_ui"]["resultState"], "observation")
        self.assertFalse(finding["_ui"]["isValidated"])

    def test_attach_finding_ui_contract_accepts_safe_legacy_command(self):
        finding = attach_finding_ui_contract(
            {
                "title": "Legacy curl guidance",
                "tool_source": "legacy",
                "category": "api",
                "reproduction": "curl -isk 'https://example.org/debug?x=<tag>&y=1'",
                "metadata": {},
            }
        )

        self.assertEqual(
            finding["_ui"]["primaryCommand"],
            "curl -isk 'https://example.org/debug?x=<tag>&y=1'",
        )

    def test_detection_table_renders_backend_ui_contract_dataset(self):
        template_root = Path(__file__).resolve().parents[1] / "ui" / "web" / "templates"
        env = Environment(
            loader=FileSystemLoader(str(template_root)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.from_string(
            "{% from 'components/detection_table.html' import detection_table %}{{ detection_table(findings) }}"
        )

        html = template.render(findings=attach_finding_ui_contracts([_structured_finding()]))

        self.assertIn('data-validation-status="success"', html)
        self.assertIn('data-result-state="confirmed"', html)
        self.assertIn(
            'data-content="graphql schema leak nuclei api https://example.org/api/graphql aws apigateway 2024.1 success confirmed validated query open"',
            html,
        )
        self.assertIn("VALIDATED", html)
        self.assertIn('id="findings-empty-state"', html)
        self.assertIn('style="display: none;"', html)
        self.assertNotIn("data-provider=", html)
        self.assertNotIn("data-component=", html)

    def test_serialize_db_finding_payload_preserves_api_contract_fields(self):
        payload = _serialize_db_finding_payload(
            SimpleNamespace(
                id=42,
                scan_id=7,
                id_stable="stable-42",
                severity="high",
                confidence="high",
                title="GraphQL schema leak",
                description="Schema is exposed",
                category="api",
                tool_source="manual",
                tool="manual",
                module="graphql_review",
                target="https://example.org/api/graphql",
                endpoint="https://example.org/api/graphql",
                parameter="query",
                payload="{}",
                evidence="Schema returned",
                raw_output="HTTP/1.1 200 OK",
                reproduction="Review the output carefully",
                repro_command="curl -isk 'https://example.org/api/graphql?query={__schema}'",
                request="GET /api/graphql HTTP/1.1",
                response="HTTP/1.1 200 OK",
                remediation="Disable introspection",
                risk_scorecard={"impact": "Schema disclosure"},
                screenshot_path="loot/graphql-proof.png",
                signal_ids=[9, 7, 9],
                metadata_json={
                    "references": ["https://owasp.org/test"],
                    "impact_area": "API Gateway",
                    "validation": {"status": "success", "artifact": "HTTP/1.1 200 OK"},
                    "provider": "aws",
                },
                created_at=datetime(2026, 3, 21, 12, 0, 0),
            )
        )

        self.assertEqual(payload["tool_source"], "manual")
        self.assertEqual(payload["source"], "manual")
        self.assertEqual(payload["raw_output"], "HTTP/1.1 200 OK")
        self.assertEqual(payload["repro_command"], "curl -isk 'https://example.org/api/graphql?query={__schema}'")
        self.assertEqual(payload["remediation"], "Disable introspection")
        self.assertEqual(payload["references"], ["https://owasp.org/test"])
        self.assertEqual(payload["signal_ids"], [9, 7])
        self.assertEqual(payload["metadata"]["validation"]["command"], "curl -isk 'https://example.org/api/graphql?query={__schema}'")
        self.assertEqual(payload["metadata"]["reproducibility"]["url"], "https://example.org/api/graphql")
        self.assertEqual(payload["created_at"], "2026-03-21T12:00:00")

    def test_detail_evidence_blocks_keep_same_value_when_semantic_keys_differ(self):
        detail = build_finding_detail_contract(
            {
                "title": "HTTP artifact parity",
                "tool_source": "manual",
                "endpoint": "https://example.org/api",
                "metadata": {
                    "validation": {"artifact": "HTTP/1.1 200 OK"},
                    "reproducibility": {
                        "request_excerpt": "GET /api HTTP/1.1",
                        "response_excerpt": "HTTP/1.1 200 OK",
                    },
                },
            }
        )

        response_blocks = [block for block in detail["evidenceBlocks"] if block["key"] in {"validation_artifact", "response"}]
        self.assertEqual([block["key"] for block in response_blocks], ["validation_artifact", "response"])
        self.assertEqual([block["value"] for block in response_blocks], ["HTTP/1.1 200 OK", "HTTP/1.1 200 OK"])

    def test_serialize_db_finding_payload_handles_partial_metadata_and_duplicates(self):
        payload = _serialize_db_finding_payload(
            SimpleNamespace(
                id=43,
                scan_id=8,
                id_stable="stable-43",
                severity="medium",
                confidence="medium",
                title="Partial record",
                description=None,
                category="review",
                tool_source="manual",
                tool="manual",
                module=None,
                target=None,
                endpoint=None,
                parameter=None,
                payload=None,
                evidence=None,
                raw_output=None,
                reproduction=None,
                repro_command=None,
                request=None,
                response=None,
                remediation=None,
                risk_scorecard="not-a-dict",
                screenshot_path=None,
                signal_ids=[5, 5, 3],
                metadata_json={"references": "https://invalid.example/ref"},
                created_at=None,
            )
        )

        self.assertEqual(payload["references"], ["https://invalid.example/ref"])
        self.assertEqual(payload["risk_scorecard"], {})
        self.assertEqual(payload["signal_ids"], [5, 3])
        self.assertRegex(payload["created_at"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(payload["metadata"]["validation"]["command"], "")
        self.assertEqual(payload["metadata"]["reproducibility"]["url"], "")

    def test_audit_journey_component_is_wired_into_main_content(self):
        main_content = Path("ui/web/templates/scan_partials/main_content.html").read_text()
        self.assertIn("{% include 'scan_partials/components/audit_journey.html' %}", main_content)

        component = Path("ui/web/templates/scan_partials/components/audit_journey.html").read_text()
        for token in [
            'id="audit-journey"',
            'id="audit-stage-cadrage"',
            'id="audit-stage-recon"',
            'id="audit-stage-enum"',
            'id="audit-stage-detection"',
            'id="audit-stage-validation"',
            'id="audit-stage-correlation"',
            'id="audit-stage-reporting"',
            'id="audit-stage-closure"',
            'id="audit-gate-total"',
            'id="audit-gate-validated"',
            'id="audit-gate-missing-proof"',
            'id="audit-gate-missing-command"',
            "goToAuditStage('recon')",
            "goToAuditStage('detection')",
            "goToAuditStage('correlation')",
            "goToAuditStage('reporting')",
            'id="audit-journey-current-phase"',
        ]:
            self.assertIn(token, component)


if __name__ == "__main__":
    unittest.main()
