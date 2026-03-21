import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.findings_ui_contract import (
    CANONICAL_UI_FIELDS,
    SEARCH_TEXT_FIELD_SOURCES,
    attach_finding_ui_contract,
    attach_finding_ui_contracts,
)


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
        "category": "api",
        "endpoint": "https://example.org/api/graphql",
        "target": "https://example.org/api/graphql",
        "parameter": "query",
        "metadata": {
            "provider": "aws",
            "component": "apigateway",
            "version": "2024.1",
            "port_state": "open",
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
                "response_excerpt": "HTTP/1.1 200 OK",
            },
        },
    }


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
        ]:
            self.assertIn(token, content)

    def test_findings_detail_panel_uses_shared_contract_and_encoded_actions(self):
        content = Path("ui/web/templates/scan_partials/interface/findings.html").read_text()
        for token in [
            "normalizeFindingRecord(finding)",
            "findingsContract.encodeDataValue(primaryCommand)",
            "Validation Actions",
            "RESULT STATE:",
            "VALIDATED",
            "data-copy-encoded",
            "decodeDataValue(encoded)",
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
        self.assertNotIn("data-provider=", html)
        self.assertNotIn("data-component=", html)

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
