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
        ]:
            self.assertIn(token, content)

    def test_detection_table_uses_consistent_dataset_keys(self):
        content = Path('ui/web/templates/components/detection_table.html').read_text()
        self.assertIn('data-sev="{{ f.severity|lower }}"', content)
        self.assertIn('data-severity="{{ f.severity|lower }}"', content)
        self.assertIn('data-content="{{ ((f.title or', content)
        self.assertIn('{% set primary_url = validation.target or reproducibility.url or f.endpoint or f.target %}', content)
        self.assertIn("result_state = (validation.result_state if validation and validation.result_state else f.result_state)", content)


if __name__ == '__main__':
    unittest.main()
