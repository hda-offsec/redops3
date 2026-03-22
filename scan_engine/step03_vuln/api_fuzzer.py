import json
import logging
import re
from urllib.parse import urlparse

from requests import RequestException

from scan_engine.helpers.http_client import get_session


LOGGER = logging.getLogger(__name__)


class APIFuzzer:
    """
    Expert Auditor for API logic.
    Focuses on:
    - HTTP Method Fuzzing (PATCH, DELETE, etc.)
    - IDOR Pattern Detection
    - GraphQL Introspection
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-APIFuzzer/1.0", "Content-Type": "application/json"})
        self.max_requests = max(1, int((self.options or {}).get("api_fuzzer_max_requests", 12) or 12))

    @staticmethod
    def _fingerprint_response(response):
        body = str(getattr(response, "text", "") or "").strip().lower()
        normalized = re.sub(r"\b\d+\b", "<num>", body)
        normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", normalized)
        return response.status_code, normalized[:400]

    @staticmethod
    def _looks_like_object_body(body):
        body_low = str(body or "").lower()
        markers = ('"id"', '"user"', '"username"', '"email"', '"account"', '"order"', '"profile"', "{", "[")
        return any(marker in body_low for marker in markers)

    @staticmethod
    def _extract_body_ids(body):
        return set(re.findall(r'(?:"(?:id|user_id|account_id|order_id)"\s*:\s*"?(\d+)"?)', str(body or ""), flags=re.IGNORECASE))

    def _log_error(self, logger, stage, url, exc, **context):
        message = f"API Fuzzer {stage} error on {url}: {exc.__class__.__name__}: {exc}"
        if logger:
            logger(message, "DEBUG")
        LOGGER.debug(message, extra={"stage": stage, "url": url, "context": context}, exc_info=True)

    def fuzz_endpoint(self, url, logger=None):
        findings = []
        if logger: logger(f"📡 API Fuzzer: Auditing logic on {url}...", "INFO")
        request_budget = 0

        # 1. HTTP Method Fuzzing (Verb Tampering) — Safe methods only
        methods = ["OPTIONS", "TRACE"]
        for m in methods:
            if request_budget >= self.max_requests:
                break
            try:
                request_budget += 1
                r = self.session.request(m, url, timeout=3, verify=False)
                # Successful method change might be a problem if it wasn't expected
                if r.status_code in [200, 201, 204]:
                    findings.append({
                        "title": f"API Intelligence: Allowed Method (`{m}`)",
                        "description": f"The endpoint `{url}` allows the `{m}` HTTP method (Status: {r.status_code}). This should be verified for proper access control.",
                        "severity": "info",
                        "tool_source": "api_fuzzer",
                        "url": url,
                        "metadata": {"method": m}
                    })
            except RequestException as exc:
                self._log_error(logger, "method_probe", url, exc, method=m)

        # 2. IDOR Pattern Probing (Bounded differential path-ID analysis)
        id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        if id_match and request_budget < self.max_requests:
            original_id = id_match.group(1)
            baseline = None
            try:
                request_budget += 1
                baseline = self.session.get(url, timeout=3, verify=False)
            except RequestException as exc:
                self._log_error(logger, "idor_baseline", url, exc, original_id=original_id)

            test_ids = []
            for candidate in [str(int(original_id) + 1), str(max(int(original_id) - 1, 0)), "0", "1", "9999"]:
                if candidate != original_id and candidate not in test_ids:
                    test_ids.append(candidate)

            baseline_fp = self._fingerprint_response(baseline) if baseline is not None else None
            baseline_ids = self._extract_body_ids(getattr(baseline, "text", ""))

            for tid in test_ids:
                if request_budget >= self.max_requests:
                    break
                test_url = re.sub(rf"/{re.escape(original_id)}(?=/|$|\?)", f"/{tid}", url, count=1)
                try:
                    request_budget += 1
                    r = self.session.get(test_url, timeout=3, verify=False)
                except RequestException as exc:
                    self._log_error(logger, "idor_probe", test_url, exc, original_id=original_id, candidate_id=tid)
                    continue

                if r.status_code != 200 or not self._looks_like_object_body(r.text):
                    continue

                candidate_fp = self._fingerprint_response(r)
                candidate_ids = self._extract_body_ids(r.text)
                differential_reasons = []

                if baseline is None:
                    differential_reasons.append("missing_baseline")
                else:
                    if baseline.status_code in [401, 403, 404] and r.status_code == 200:
                        differential_reasons.append(f"baseline_{baseline.status_code}_candidate_200")
                    if baseline_fp != candidate_fp:
                        differential_reasons.append("response_fingerprint_changed")
                    if candidate_ids and candidate_ids != baseline_ids:
                        differential_reasons.append("object_identifier_changed")
                    if tid in candidate_ids and original_id not in candidate_ids:
                        differential_reasons.append("candidate_identifier_reflected")

                meaningful_differential = any(
                    reason.startswith("baseline_") or reason == "response_fingerprint_changed"
                    for reason in differential_reasons
                )
                if not meaningful_differential:
                    continue

                findings.append({
                    "title": "Potential IDOR Surface Detected",
                    "description": (
                        f"Differential access was observed for alternative ID `{tid}` at `{test_url}` "
                        f"(original `{original_id}`). Review authorization controls for possible BOLA."
                    ),
                    "severity": "medium",
                    "confidence": "medium",
                    "tool_source": "api_fuzzer",
                    "url": test_url,
                    "metadata": {
                        "original_url": url,
                        "baseline_status": getattr(baseline, "status_code", None),
                        "candidate_status": r.status_code,
                        "differential_reasons": sorted(differential_reasons),
                    },
                })
                break

        # 3. GraphQL Introspection
        if "graphql" in url.lower() and request_budget < self.max_requests:
            introspection_query = {"query": "{__schema{queryType{name}}}"}
            try:
                request_budget += 1
                r = self.session.post(url, json=introspection_query, timeout=5, verify=False)
                if r.status_code == 200 and "__schema" in r.text:
                    if logger: logger(f"🔥 GraphQL Introspection Enabled: {url}", "HIGH")
                    findings.append({
                        "title": "CRITICAL: GraphQL Introspection Enabled",
                        "description": f"The GraphQL endpoint at `{url}` allows introspection. This enables anyone to query the entire schema and underlying data models.",
                        "severity": "high",
                        "confidence": "high",
                        "tool_source": "api_fuzzer",
                        "url": url,
                        "metadata": {"technique": "introspection"}
                    })
            except RequestException as exc:
                self._log_error(logger, "graphql_introspection", url, exc)

        return findings
