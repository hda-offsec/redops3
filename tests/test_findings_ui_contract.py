import unittest
from pathlib import Path


class FindingsUiContractTests(unittest.TestCase):
    def test_scan_dashboard_uses_structured_mapping_helpers(self):
        content = Path('ui/web/static/js/scan_dashboard.js').read_text()
        for token in [
            'getFindingValidationStatus',
            'getFindingPrimaryCommand',
            'getFindingPrimaryUrl',
            'getFindingResultState',
            'decodeDataValue',
            'hasMeaningfulProof',
            'data-severity',
            'data-content',
            "finding?.metadata?.result_state",
            "findings-port-status-filter",
            'data-validation-status',
            'data-result-state',
            "terms.status || terms.validation || terms.state",
            'deriveAuditJourney',
            'updateAuditJourney',
            'window.goToAuditStage',
            'window.applyTacticalFilter',
        ]:
            self.assertIn(token, content)

    def test_findings_detail_panel_is_evidence_first_sections(self):
        content = Path('ui/web/templates/scan_partials/interface/findings.html').read_text()
        for token in [
            'Section C — Validation',
            'Section D — Reproductibilité',
            'Section E — Preuve',
            'Copy command',
            'VALIDATION:',
            'VERIFIED',
            'encodeURIComponent(primaryCommand)',
            'getFindingReproducibility',
            'data-copy-encoded',
            'decodeDataValue(encoded)',
            'normalizeFindingRecord',
            "row.getAttribute('data-content')",
        ]:
            self.assertIn(token, content)

    def test_detection_table_uses_consistent_dataset_keys(self):
        content = Path('ui/web/templates/components/detection_table.html').read_text()
        self.assertIn('data-sev="{{ f.severity|lower }}"', content)
        self.assertIn('data-severity="{{ f.severity|lower }}"', content)
        self.assertIn('data-content="{{ ((f.title or', content)
        self.assertIn('{% set primary_url = validation.target or reproducibility.url or f.endpoint or f.target %}', content)
        self.assertIn("result_state = (validation.result_state if validation and validation.result_state else (f.result_state or (f.metadata.result_state if f.metadata else '')))", content)
        self.assertIn('{% set has_chain_links = chain.related_findings is defined and chain.related_findings %}', content)
        self.assertIn('No findings match the current view for this engagement.', content)

    def test_audit_journey_component_is_wired_into_main_content(self):
        main_content = Path('ui/web/templates/scan_partials/main_content.html').read_text()
        self.assertIn("{% include 'scan_partials/components/audit_journey.html' %}", main_content)

        component = Path('ui/web/templates/scan_partials/components/audit_journey.html').read_text()
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


if __name__ == '__main__':
    unittest.main()
