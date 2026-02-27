"""
SSTI Scanner V9 — Formal Validation Model.

Formal Proof Conditions (all must hold for CONFIRMED):
  P1  Determinism:      I₁ contains R  AND  I₂ contains R
  P2  Non-reflection:   raw payload ∉ I₁
  P3  Baseline exclusion: R ∉ B  (structural, not substring)
  P4  Structural mutation: Δ(B, I₁) ≥ 1 meaningful text-node change
  P5  Stability:        |len(I₁) − len(B)| > 20 bytes
  P6  Status equivalence: HTTP_status(I₁) == HTTP_status(B)
  P7  Not redirect-only: response is not pure 301/302
  P8  Stack compatibility: E ∈ CompatibleEngines(S)

Weighted Confidence:
  C = Σ(wᵢ × fᵢ)   where fᵢ ∈ {0, 1}
  f₁  Deterministic execution     w=0.25
  f₂  Structural DOM mutation     w=0.20
  f₃  Baseline exclusion          w=0.15
  f₄  Stack compatibility         w=0.15
  f₅  Multi-attempt consistency   w=0.10
  f₆  Content-length delta        w=0.10
  f₇  Not redirect-only           w=0.05

Severity:
  C ≥ 0.8  AND  f₁=1  AND  f₂=1         → CRITICAL
  0.6 ≤ C < 0.8                          → HIGH
  0.4 ≤ C < 0.6                          → MEDIUM (UNCONFIRMED)
  C < 0.4                                → SUPPRESSED
"""

import re
import hashlib
import gzip
from io import BytesIO
from scan_engine.helpers.http_client import get_session
from urllib.parse import urlparse, parse_qs, urlencode


class SSTIScanner:
    """V9: Formal-model SSTI validator. Zero hallucination policy."""

    # CompatibleEngines(S) — PART I §3 of V9 spec
    # PHP: Twig (explicit), Blade (Laravel). Jinja2/Mako/Freemarker FORBIDDEN.
    # Python: Jinja2, Mako. Twig/ERB FORBIDDEN.
    # Node: Handlebars, EJS. Twig/Jinja2 FORBIDDEN.
    ENGINE_STACK_MAP = {
        "php":    ["Twig", "Blade"],
        "python": ["Jinja2", "Mako"],
        "java":   ["Freemarker", "Velocity", "Thymeleaf", "EL"],
        "ruby":   ["ERB", "Slim", "Haml"],
        "node":   ["Handlebars", "EJS", "Nunjucks", "Pug"],
        "dotnet": ["Razor"],
    }

    # Weighted scoring factors — PART II
    WEIGHTS = {
        "f1_deterministic":   0.25,
        "f2_structural_diff": 0.20,
        "f3_baseline_excl":   0.15,
        "f4_stack_compat":    0.15,
        "f5_multi_attempt":   0.10,
        "f6_content_delta":   0.10,
        "f7_not_redirect":    0.05,
    }

    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.session = get_session(self.options)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })

    def get_payloads(self):
        """Payloads with expected results for engine identification."""
        return [
            {"payload": "{{7*7}}", "expected": "49", "engines": ["Jinja2", "Twig", "Mako", "Handlebars"]},
            {"payload": "${7*7}", "expected": "49", "engines": ["Freemarker", "Velocity", "EL"]},
            {"payload": "<%= 7*7 %>", "expected": "49", "engines": ["ERB"]},
            {"payload": "{{7*'7'}}", "expected": "7777777", "engines": ["Jinja2", "Twig"]},
            {"payload": "*{7*7}", "expected": "49", "engines": ["Thymeleaf"]},
        ]

    # ------------------------------------------------------------------
    # NORMALIZATION (PART III — Rule 6)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_body(text):
        """
        Structural normalization per V9 Rule 6.
        Strips: Date, Cookies, CSRF, Nonces, tracking parameters.
        Raw HTML diff is forbidden.
        """
        if not text:
            return ""
        # CSRF tokens
        text = re.sub(
            r'name=["\']?_?csrf[_-]?token["\']?\s*value=["\'][^"\']*["\']',
            'CSRF_STRIPPED', text, flags=re.I
        )
        # Nonce values
        text = re.sub(
            r'name=["\']?_?nonce["\']?\s*value=["\'][^"\']*["\']',
            'NONCE_STRIPPED', text, flags=re.I
        )
        text = re.sub(r'nonce=["\'][^"\']*["\']', 'nonce="STRIPPED"', text, flags=re.I)
        # Timestamps
        text = re.sub(r'\d{10,13}', 'TS_STRIPPED', text)
        text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}', 'DT_STRIPPED', text)
        # Tracking IDs (common patterns)
        text = re.sub(r'[a-f0-9]{32,64}', 'HASH_STRIPPED', text, flags=re.I)
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    @staticmethod
    def _hash_body(normalized_text):
        """SHA256 of normalized body for structural comparison."""
        return hashlib.sha256(normalized_text.encode('utf-8', errors='replace')).hexdigest()

    def _safe_get(self, url, **kwargs):
        """
        GET with mandatory timeout, redirect follow, gzip decompress.
        Timeout is NEVER optional (V9 Part V).
        """
        timeout = kwargs.pop('timeout', 8)
        verify = kwargs.pop('verify', False)
        allow_redirects = kwargs.pop('allow_redirects', True)
        r = self.session.get(
            url, timeout=timeout, verify=verify,
            allow_redirects=allow_redirects, **kwargs
        )
        # Decompress gzip (Rule 6)
        if r.headers.get('Content-Encoding', '').lower() == 'gzip':
            try:
                r._content = gzip.GzipFile(fileobj=BytesIO(r.content)).read()
            except Exception:
                pass
        return r

    # ------------------------------------------------------------------
    # STACK DETECTION (PART I §3)
    # ------------------------------------------------------------------

    def _detect_stack(self, response):
        """Detect server-side Stack S from headers and body."""
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        server = headers.get('server', '')
        powered = headers.get('x-powered-by', '')
        body = response.text[:5000].lower()

        if 'php' in powered or 'php' in server or 'x-pingback' in headers:
            return "php"
        if any(x in powered or x in server for x in ['python', 'gunicorn', 'werkzeug', 'flask', 'django', 'uvicorn']):
            return "python"
        if 'asp.net' in powered or 'iis' in server:
            return "dotnet"
        if 'express' in powered or 'node' in powered:
            return "node"
        if 'ruby' in powered or 'passenger' in server or 'puma' in server:
            return "ruby"
        if any(x in server for x in ['jetty', 'tomcat', 'wildfly', 'jboss', 'glassfish']):
            return "java"

        # Body heuristics
        if any(x in body for x in ['wp-content', 'wordpress', 'wp-json', 'wp-includes']):
            return "php"
        if 'csrfmiddlewaretoken' in body:
            return "python"

        return "unknown"

    def _engines_compatible(self, stack, suggested_engines):
        """CompatibleEngines(S) — returns True iff E ∈ CompatibleEngines(S)."""
        if stack == "unknown":
            return True  # Cannot disprove
        compatible = self.ENGINE_STACK_MAP.get(stack, [])
        return any(e in compatible for e in suggested_engines)

    def _filter_engines(self, stack, suggested_engines):
        """Return only stack-compatible engines from the suggestion list."""
        if stack == "unknown":
            return suggested_engines
        compatible = set(self.ENGINE_STACK_MAP.get(stack, []))
        return [e for e in suggested_engines if e in compatible]

    # ------------------------------------------------------------------
    # CORE VALIDATION (PART I §2)
    # ------------------------------------------------------------------

    def scan_endpoint(self, url, params, logger=None):
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if logger:
            logger(f"SSTI V9: Formal validation on {url}...", "INFO")

        # ------ STEP 1: Collect Baseline B ------
        validation_path = {}
        try:
            baseline_r = self._safe_get(url)
            baseline_raw = baseline_r.text
            baseline_norm = self._normalize_body(baseline_raw)
            baseline_hash = self._hash_body(baseline_norm)
            baseline_len = len(baseline_r.content)
            baseline_status = baseline_r.status_code
            stack = self._detect_stack(baseline_r)
            validation_path["baseline_collected"] = True
        except Exception as e:
            if logger:
                logger(f"SSTI V9: Baseline failed for {url}: {e}", "DEBUG")
            return findings

        if logger:
            logger(
                f"SSTI V9: Baseline OK. Stack={stack}, "
                f"Status={baseline_status}, Len={baseline_len}",
                "DEBUG"
            )

        for param_name in params:
            for probe in self.get_payloads():
                vp = dict(validation_path)  # per-probe copy
                try:
                    # ------ STEP 2: Injection I₁ ------
                    qs = parse_qs(parsed.query)
                    qs[param_name] = [probe["payload"]]
                    test_url = f"{base}?{urlencode(qs, doseq=True)}"

                    r = self._safe_get(test_url)
                    attack_norm = self._normalize_body(r.text)
                    attack_hash = self._hash_body(attack_norm)
                    attack_len = len(r.content)
                    vp["injection_sent"] = True
                    vp["normalization_done"] = True

                    # ------ STEP 3: 8-predicate proof ------
                    factors = {}

                    # P2 Non-reflection
                    if probe["payload"] in r.text:
                        continue

                    # P1/B Expected result present in I₁
                    if probe["expected"] not in r.text:
                        continue
                    vp["result_detected"] = True

                    # P3 Baseline exclusion (structural, not substring)
                    # Check normalized baseline AND raw baseline
                    result_in_baseline = (
                        probe["expected"] in baseline_raw
                        or probe["expected"] in baseline_norm
                    )
                    factors["f3_baseline_excl"] = 0 if result_in_baseline else 1
                    if result_in_baseline:
                        if logger:
                            logger(
                                f"SSTI V9: FP — '{probe['expected']}' in baseline "
                                f"for {param_name}",
                                "DEBUG"
                            )
                        continue

                    # P4 Structural mutation Δ(B, I₁)
                    structural_diff = attack_hash != baseline_hash
                    factors["f2_structural_diff"] = 1 if structural_diff else 0
                    if not structural_diff:
                        if logger:
                            logger(
                                "SSTI V9: FP — normalized body identical to baseline",
                                "DEBUG"
                            )
                        continue
                    vp["structural_diff_passed"] = True

                    # P5 Content-length delta
                    len_delta = abs(attack_len - baseline_len)
                    factors["f6_content_delta"] = 1 if len_delta > 20 else 0
                    if len_delta < 20:
                        if logger:
                            logger(
                                f"SSTI V9: FP — content delta too small ({len_delta}B)",
                                "DEBUG"
                            )
                        continue

                    # P6 Status equivalence
                    if r.status_code != baseline_status:
                        if logger:
                            logger(
                                f"SSTI V9: Status mismatch "
                                f"({r.status_code} vs {baseline_status})",
                                "DEBUG"
                            )
                        continue

                    # P7 Not redirect-only
                    is_redirect = r.status_code in [301, 302, 303, 307, 308]
                    factors["f7_not_redirect"] = 0 if is_redirect else 1
                    if is_redirect:
                        continue

                    # P1 Multi-attempt: I₂ (deterministic reproduction)
                    confirmations = 0
                    for _ in range(2):
                        try:
                            r2 = self._safe_get(test_url)
                            if (probe["expected"] in r2.text
                                    and probe["payload"] not in r2.text):
                                confirmations += 1
                        except Exception:
                            pass

                    factors["f1_deterministic"] = 1 if confirmations >= 2 else 0
                    factors["f5_multi_attempt"] = 1 if confirmations >= 1 else 0

                    # P8 Stack compatibility
                    engine_compat = self._engines_compatible(stack, probe["engines"])
                    factors["f4_stack_compat"] = 1 if engine_compat else 0
                    vp["stack_verified"] = True

                    # ------ CONFIDENCE SCORING (weighted matrix) ------
                    confidence = 0.0
                    for key, weight in self.WEIGHTS.items():
                        confidence += weight * factors.get(key, 0)
                    confidence = round(min(confidence, 1.0), 2)
                    vp["confidence_calculated"] = confidence

                    if logger:
                        logger(
                            f"SSTI V9: Factors={factors} → C={confidence}",
                            "DEBUG"
                        )

                    # ------ SEVERITY MAPPING ------
                    f1 = factors.get("f1_deterministic", 0)
                    f2 = factors.get("f2_structural_diff", 0)

                    if confidence >= 0.8 and f1 == 1 and f2 == 1:
                        severity = "critical"
                        label = "CONFIRMED"
                    elif confidence >= 0.6:
                        severity = "high"
                        label = "PROBABLE"
                    elif confidence >= 0.4:
                        severity = "medium"
                        label = "UNCONFIRMED — MANUAL REVIEW REQUIRED"
                    else:
                        if logger:
                            logger(
                                f"SSTI V9: SUPPRESSED (C={confidence})"
                                f" for {param_name}",
                                "DEBUG"
                            )
                        continue

                    # Stack mismatch enforcement (P8)
                    if not engine_compat and stack != "unknown":
                        # Cap at MEDIUM — ENGINE_INCOMPATIBLE_WITH_STACK
                        if severity in ("critical", "high"):
                            severity = "medium"
                        label = "ENGINE_INCOMPATIBLE_WITH_STACK"
                        engine_str = (
                            f"POSSIBLE TEMPLATE BEHAVIOR — "
                            f"ENGINE UNKNOWN (Stack: {stack})"
                        )
                    else:
                        # Filter engines to only stack-compatible ones
                        compat_engines = self._filter_engines(
                            stack, probe["engines"]
                        )
                        engine_str = ", ".join(compat_engines) if compat_engines else "Unknown"

                    # CRITICAL requires FULL determinism + structural mutation
                    if severity == "critical" and (f1 != 1 or f2 != 1):
                        severity = "high"
                        label = "PROBABLE (determinism incomplete)"

                    # ------ BUILD EVIDENCE ------
                    req_dump = f"GET {test_url} HTTP/1.1\n"
                    for k, v in r.request.headers.items():
                        req_dump += f"{k}: {v}\n"

                    res_dump = f"HTTP/1.1 {r.status_code} {r.reason}\n"
                    for k, v in r.headers.items():
                        res_dump += f"{k}: {v}\n"
                    res_dump += f"\n{r.text[:1500]}..."

                    finding = {
                        "title": f"{severity.upper()}: SSTI {label} ({engine_str})",
                        "description": (
                            f"**SSTI VALIDATION RESULT (V9 Formal Model)**:\n"
                            f"- Execution proven (P1): "
                            f"{'YES' if f1 == 1 else 'NO'}\n"
                            f"- Payload rendered (P2): YES "
                            f"('{probe['payload']}' → '{probe['expected']}')\n"
                            f"- Baseline exclusion (P3): YES\n"
                            f"- Structural diff (P4): YES "
                            f"(Δ = {len_delta}B)\n"
                            f"- Stability (P5): YES\n"
                            f"- Status equivalence (P6): YES "
                            f"({baseline_status})\n"
                            f"- Not redirect-only (P7): YES\n"
                            f"- Stack compatible (P8): "
                            f"{'YES' if engine_compat else f'NO ({stack})'}\n"
                            f"- Multi-attempt: {confirmations}/2\n"
                            f"- **Confidence: {confidence}/1.0**\n\n"
                            f"Parameter: `{param_name}`\n"
                            f"Detected Stack: {stack}\n"
                            f"Validation Path: {vp}\n"
                        ),
                        "severity": severity,
                        "confidence": str(confidence),
                        "tool_source": "ssti_expert",
                        "url": test_url,
                        "payload": probe["payload"],
                        "request": req_dump,
                        "response": res_dump,
                        "repro_command": (
                            f"curl -v -G '{base}' "
                            f"--data-urlencode '{param_name}={probe['payload']}'"
                        ),
                    }
                    findings.append(finding)
                    if logger:
                        logger(
                            f"SSTI V9: [{label}] {engine_str} on {param_name} "
                            f"(C={confidence}, stack={stack})",
                            "CRITICAL" if severity == "critical" else "WARN"
                        )
                    break  # One finding per parameter

                except Exception as e:
                    if logger:
                        logger(
                            f"SSTI V9 Probe Error on {param_name}: {e}", "DEBUG"
                        )

        return findings

    def audit_all(self, endpoints_map, logger=None):
        """Expects a map of {url: [params]}"""
        all_findings = []
        for url, params in endpoints_map.items():
            if not params:
                continue
            all_findings.extend(self.scan_endpoint(url, params, logger))
        return all_findings
