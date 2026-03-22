import json
import logging
import re
from urllib.parse import urlparse

from requests import RequestException

from scan_engine.helpers.http_client import get_session


LOGGER = logging.getLogger(__name__)
OBJECT_REFERENCE_KEYS = ("id", "user_id", "account_id", "order_id", "profile_id", "uuid")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
SLUG_WITH_NUMERIC_SUFFIX_PATTERN = re.compile(r"^(?P<prefix>[a-z][a-z0-9_-]*?)(?P<digits>\d{1,12})$", re.IGNORECASE)


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
    def _normalize_text_fingerprint(value):
        normalized = str(value or "").strip().lower()
        normalized = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", "<uuid>", normalized)
        normalized = re.sub(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", "<email>", normalized)
        normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", normalized)
        normalized = re.sub(r"\b\d+\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    @classmethod
    def _normalize_json_value(cls, value):
        if isinstance(value, dict):
            return {str(key): cls._normalize_json_value(value[key]) for key in sorted(value.keys(), key=str)}
        if isinstance(value, list):
            return [cls._normalize_json_value(item) for item in value]
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return "<num>"
        return cls._normalize_text_fingerprint(value)

    @staticmethod
    def _fingerprint_response(response):
        body = str(getattr(response, "text", "") or "").strip().lower()
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            normalized = APIFuzzer._normalize_text_fingerprint(body)
        else:
            normalized = json.dumps(APIFuzzer._normalize_json_value(parsed), sort_keys=True, separators=(",", ":"))
        return response.status_code, normalized[:400]

    @staticmethod
    def _looks_like_object_body(body):
        body_low = str(body or "").lower()
        markers = ('"id"', '"user"', '"username"', '"email"', '"account"', '"order"', '"profile"', "{", "[")
        return any(marker in body_low for marker in markers)

    @staticmethod
    def _extract_body_ids(body):
        matches = set()
        for key in OBJECT_REFERENCE_KEYS:
            pattern = rf'"{re.escape(key)}"\s*:\s*"?(?P<value>[A-Za-z0-9_-]{{1,64}})"?'
            for match in re.finditer(pattern, str(body or ""), flags=re.IGNORECASE):
                value = match.group("value").strip()
                if value:
                    matches.add(value.lower())
        return matches

    @staticmethod
    def _looks_like_object_reference(segment):
        value = str(segment or "").strip()
        if not value or re.fullmatch(r"v\d+", value, flags=re.IGNORECASE):
            return False
        return (
            value.isdigit()
            or bool(UUID_PATTERN.fullmatch(value))
            or bool(HEX_OBJECT_PATTERN.fullmatch(value))
            or bool(SLUG_WITH_NUMERIC_SUFFIX_PATTERN.fullmatch(value))
        )

    @classmethod
    def _extract_path_object_reference(cls, url):
        parsed = urlparse(str(url or ""))
        segments = [segment for segment in parsed.path.split("/") if segment]
        for index in range(len(segments) - 1, -1, -1):
            segment = segments[index]
            if cls._looks_like_object_reference(segment):
                return index, segment
        return None, None

    @staticmethod
    def _mutate_object_reference(reference):
        value = str(reference or "").strip()
        candidates = []

        if value.isdigit():
            original = int(value)
            for candidate in [str(original + 1), str(max(original - 1, 0)), "0", "1", "9999"]:
                if candidate != value and candidate not in candidates:
                    candidates.append(candidate)
            return candidates

        if UUID_PATTERN.fullmatch(value):
            last = value[-1].lower()
            replacement = "1" if last != "1" else "2"
            return [f"{value[:-1]}{replacement}"]

        if HEX_OBJECT_PATTERN.fullmatch(value):
            last = value[-1].lower()
            replacement = "1" if last != "1" else "2"
            return [f"{value[:-1]}{replacement}"]

        slug_match = SLUG_WITH_NUMERIC_SUFFIX_PATTERN.fullmatch(value)
        if slug_match:
            prefix = slug_match.group("prefix")
            digits = slug_match.group("digits")
            original = int(digits)
            width = len(digits)
            for candidate in [original + 1, max(original - 1, 0)]:
                rendered = f"{prefix}{candidate:0{width}d}"
                if rendered != value and rendered not in candidates:
                    candidates.append(rendered)
            return candidates

        return candidates

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

        # 2. IDOR Pattern Probing (Bounded differential path-object analysis)
        ref_index, original_id = self._extract_path_object_reference(url)
        if original_id and request_budget < self.max_requests:
            baseline = None
            try:
                request_budget += 1
                baseline = self.session.get(url, timeout=3, verify=False)
            except RequestException as exc:
                self._log_error(logger, "idor_baseline", url, exc, original_id=original_id)

            parsed = urlparse(url)
            segments = [segment for segment in parsed.path.split("/") if segment]
            test_ids = self._mutate_object_reference(original_id)

            baseline_fp = self._fingerprint_response(baseline) if baseline is not None else None
            baseline_ids = self._extract_body_ids(getattr(baseline, "text", ""))

            for tid in test_ids:
                if request_budget >= self.max_requests:
                    break
                mutated_segments = list(segments)
                mutated_segments[ref_index] = tid
                new_path = "/" + "/".join(mutated_segments)
                test_url = parsed._replace(path=new_path).geturl()
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
                        "object_reference_kind": (
                            "uuid" if UUID_PATTERN.fullmatch(original_id) else
                            "numeric" if original_id.isdigit() else
                            "hex" if HEX_OBJECT_PATTERN.fullmatch(original_id) else
                            "slug_numeric"
                        ),
                        "original_url": url,
                        "baseline_status": getattr(baseline, "status_code", None),
                        "candidate_status": r.status_code,
                        "baseline_object_ids": sorted(baseline_ids),
                        "candidate_object_ids": sorted(candidate_ids),
                        "differential_reasons": sorted(differential_reasons),
                        "request_budget_used": request_budget,
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
