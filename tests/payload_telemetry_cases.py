import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scan_engine.step03_vuln.lfi_assault import LfiAssaultScanner
from scan_engine.step03_vuln.upload_scanner import UploadExpertScanner


class _FakeUploadSession:
    def post(self, url, files=None, timeout=None):
        return SimpleNamespace(status_code=201, text='{"success":true}', headers={})


class _FakeLfiSession:
    def __init__(self):
        self.headers = {}

    def get(self, url, timeout=None, verify=None):
        return SimpleNamespace(
            status_code=200,
            text=url,
            url=url,
            reason="OK",
            headers={},
            request=SimpleNamespace(method="GET", url=url, headers={}, body=None),
        )

    def post(self, url, data=None, timeout=None, verify=None):
        return SimpleNamespace(
            status_code=200,
            text="uid=1000(redops)",
            url=url,
            reason="OK",
            headers={},
            request=SimpleNamespace(method="POST", url=url, headers={}, body=data),
        )


class PayloadTelemetryTests(unittest.TestCase):
    def test_upload_scanner_tracks_planned_attempted_and_succeeded_payloads(self):
        with patch("scan_engine.step03_vuln.upload_scanner.get_session", return_value=_FakeUploadSession()):
            scanner = UploadExpertScanner("example.org")
            findings = scanner.scan_upload_form("https://example.org/upload")

        self.assertEqual(len(findings), 4)
        self.assertEqual(
            scanner.last_telemetry,
            {
                "payloads_planned": 4,
                "payloads_attempted": 4,
                "payloads_skipped": 0,
                "payloads_succeeded": 4,
                "payloads_errored": 0,
            },
        )

    def test_lfi_scanner_tracks_early_exit_as_skipped_payloads(self):
        with patch("scan_engine.step03_vuln.lfi_assault.PayloadMutator.mutate", side_effect=lambda payload, _: [payload]):
            scanner = LfiAssaultScanner(options={})
            scanner.lfi_rules = [
                {
                    "rule_id": "passwd",
                    "payloads": ["/etc/passwd", "/etc/hosts"],
                    "mutations": ["original"],
                    "check_type": "contains",
                    "match_keywords": ["root:x:0:0:"],
                }
            ]
            scanner.rce_bridge_payloads = []
            scanner._check_success = lambda resp, rule, baseline_text="": "passwd" in resp.text

            with patch("scan_engine.step03_vuln.lfi_assault.get_session", return_value=_FakeLfiSession()):
                findings = scanner.scan(
                    "https://example.org/download?file=index",
                    scan_id=1,
                    urls=[],
                    quick=True,
                )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            scanner.last_telemetry,
            {
                "payloads_planned": 2,
                "payloads_attempted": 1,
                "payloads_skipped": 1,
                "payloads_succeeded": 1,
                "payloads_errored": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
