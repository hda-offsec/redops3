from requests import RequestException

from scan_engine.helpers.context_attack_engine import APIIntelligenceEngine, ExploitValidationEngine
from scan_engine.step03_vuln.api_fuzzer import APIFuzzer


class DummyResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8")


class SequenceSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []
        self.headers = {}

    def _next(self):
        if not self._responses:
            raise AssertionError("No more fake responses configured")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._next()

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        return None


def test_api_fuzzer_idor_does_not_flag_identical_object_template(monkeypatch):
    session = SequenceSession(
        [
            DummyResponse(405, "method not allowed"),
            DummyResponse(405, "method not allowed"),
            DummyResponse(200, '{"id": "7", "name": "Same"}'),
            DummyResponse(200, '{"id": "8", "name": "Same"}'),
            DummyResponse(200, '{"id": "6", "name": "Same"}'),
            DummyResponse(200, '{"id": "0", "name": "Same"}'),
            DummyResponse(200, '{"id": "1", "name": "Same"}'),
            DummyResponse(200, '{"id": "9999", "name": "Same"}'),
        ]
    )
    monkeypatch.setattr("scan_engine.step03_vuln.api_fuzzer.get_session", lambda _options=None: session)

    findings = APIFuzzer(options={"api_fuzzer_max_requests": 8}).fuzz_endpoint("https://example.com/api/users/7")

    assert findings == []


def test_api_fuzzer_idor_flags_differential_access(monkeypatch):
    session = SequenceSession(
        [
            DummyResponse(405, "method not allowed"),
            DummyResponse(405, "method not allowed"),
            DummyResponse(403, '{"error": "forbidden"}'),
            DummyResponse(200, '{"id": "8", "email": "user8@example.com", "role": "member"}'),
        ]
    )
    monkeypatch.setattr("scan_engine.step03_vuln.api_fuzzer.get_session", lambda _options=None: session)

    findings = APIFuzzer(options={"api_fuzzer_max_requests": 4}).fuzz_endpoint("https://example.com/api/users/7")

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "Potential IDOR Surface Detected"
    assert finding["tool_source"] == "api_fuzzer"
    assert finding["metadata"]["baseline_status"] == 403
    assert "baseline_403_candidate_200" in finding["metadata"]["differential_reasons"]


def test_api_intelligence_engine_fuzz_surface_idor_uses_differential_validation(monkeypatch):
    session = SequenceSession(
        [
            DummyResponse(200, '{"id":"2","email":"user2@example.com"}'),
            DummyResponse(403, '{"error":"forbidden"}'),
        ]
    )
    monkeypatch.setattr("scan_engine.helpers.context_attack_engine.get_session", lambda _options=None: session)

    findings = APIIntelligenceEngine.fuzz_surface(
        [{"endpoint": "https://example.com/api/orders", "parameters": ["id"]}],
        options={"api_fuzz_max_requests": 2, "timeout": 1},
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "idor"
    assert finding["metadata"]["status_code"] == 200
    assert finding["metadata"]["request_budget_used"] == 2


def test_exploit_validation_engine_confirms_ssrf_with_differential_probe(monkeypatch):
    session = SequenceSession(
        [
            DummyResponse(200, '{"status":"ok"}'),
            DummyResponse(200, "instance-id\ni-1234567890"),
        ]
    )
    monkeypatch.setattr("scan_engine.helpers.context_attack_engine.get_session", lambda _options=None: session)

    findings = ExploitValidationEngine.validate(
        [
            {
                "id_stable": "f-1",
                "title": "Potential SSRF Surface",
                "category": "ssrf",
                "severity": "high",
                "endpoint": "https://example.com/fetch",
            }
        ],
        options={"validation_max_requests": 1, "timeout": 1},
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["title"] == "VERIFIED: Potential SSRF Surface"
    assert finding["metadata"]["verified"] is True
    assert finding["metadata"]["source_id"] == "f-1"


def test_exploit_validation_engine_logs_baseline_errors(monkeypatch):
    session = SequenceSession([RequestException("boom")])
    messages = []
    monkeypatch.setattr("scan_engine.helpers.context_attack_engine.get_session", lambda _options=None: session)

    findings = ExploitValidationEngine.validate(
        [
            {
                "title": "Potential SSRF Surface",
                "category": "ssrf",
                "endpoint": "https://example.com/fetch",
            }
        ],
        options={"validation_max_requests": 2, "timeout": 1},
        logger=lambda message, level: messages.append((level, message)),
    )

    assert findings == []
    assert messages
    assert messages[0][0] == "DEBUG"
    assert "exploit_validation_baseline failed" in messages[0][1]
