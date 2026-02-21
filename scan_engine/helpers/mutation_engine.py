import hashlib
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode


class MutationEngine:
    """
    V7 Mutation Engine — Strategy-driven, deterministic, budget-aware.

    Contract fields per variant:
        url, attack_type, mutation_type, mutations, source_seed,
        payload, payload_hash, param_shape, variant_id
    """

    def __init__(self, budget_manager=None, logger=None, options=None):
        self.options = options
        self.budget = budget_manager
        self.log = logger
        self.stats = {"generated": 0, "accepted": 0, "dropped": 0}

        self.STRATEGY_MAP = {
            "xss": self._mutate_xss,
            "lfi": self._mutate_lfi,
            "ssrf": self._mutate_ssrf,
        }

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def generate_variants(self, seed_url, attack_type="generic", strategy=None):
        """
        Returns a list of contract-compliant variant dicts.
        Guarantees at least one variant (fallback).
        Selection is deterministic (sorted by mutation priority, not random).
        """
        self.stats = {"generated": 0, "accepted": 0, "dropped": 0}

        if not seed_url or not isinstance(seed_url, str) or not seed_url.startswith("http"):
            return []

        parsed = urlparse(seed_url)
        query = parse_qs(parsed.query, keep_blank_values=True)

        # Param synthesis for param-less seeds on high-value paths only
        _HV_PATH_KEYWORDS = {"view", "api", "download", "render", "include", "file", "page", "data"}
        path_segments = parsed.path.strip("/").lower().split("/")
        def _seg_matches_keyword(seg):
            """Exact match or keyword at start followed by non-alpha (file_upload OK, viewer NO)."""
            return seg in _HV_PATH_KEYWORDS or any(
                seg.startswith(kw) and (len(seg) == len(kw) or not seg[len(kw)].isalpha())
                for kw in _HV_PATH_KEYWORDS
            )
        if (not query
                and len(path_segments) >= 1
                and path_segments[0]  # blocks root "/"
                and any(_seg_matches_keyword(seg) for seg in path_segments)):
            extra_p = strategy.get("extra_params", []) if strategy else []
            high_value = [
                "id", "file", "path", "url", "redirect", "page",
                "template", "include", "callback", "view", "next", "return",
            ]
            combined_p = list(dict.fromkeys(extra_p + high_value))  # dedup, order-preserving
            seed_entropy = int(hashlib.sha512(seed_url.encode(), usedforsecurity=False).hexdigest()[:8], 16) % 100
            for p in combined_p[:12]:
                query[p] = [f"__seed{seed_entropy}__"]

        # Dispatch
        handler = self.STRATEGY_MAP.get(attack_type)
        variants = []
        if handler:
            variants.extend(handler(parsed, query, seed_url, strategy))
        else:
            variants.append(
                self._build_contract_variant(
                    parsed, query, seed_url, ["original"], "generic", "original"
                )
            )

        # Deterministic selection (throttle) — sorted by mutation priority score
        if strategy and "mutation_budget" in strategy:
            max_mut = strategy["mutation_budget"]
            if len(variants) > max_mut:
                variants = self._deterministic_select(variants, max_mut, seed_url, attack_type)

        # Safety: guarantee ≥1 variant
        if not variants:
            variants.append(
                self._build_contract_variant(
                    parsed, query, seed_url, ["fallback"], attack_type, "original"
                )
            )

        if self.log:
            self.log(
                f"MutationEngine: seed={seed_url[:60]}… attack={attack_type} "
                f"gen={self.stats['generated']} acc={self.stats['accepted']} "
                f"drop={self.stats['dropped']}",
                "DEBUG",
            )

        return variants

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------

    def _mutate_xss(self, parsed, query, seed, strategy=None):
        results = []
        probes = [
            ("xss_probe_minimal", "ROXSS123"),
            ("xss_probe_breakout", '"><ROXSS123'),
            ("xss_probe_svg", "<svg/onload=ROXSS123>"),
            ("xss_js_scheme", "javascript:ROXSS123"),
            ("xss_data_scheme", "data:text/html,ROXSS123"),
        ]

        for param in sorted(query.keys()):
            if self.budget and self.budget.should_throttle("xss"):
                break

            for label, payload in probes:
                # Plain probe  (change #5: lightweight copy)
                m_query = {k: list(v) for k, v in query.items()}
                m_query[param] = [payload]
                v = self._build_contract_variant(
                    parsed, m_query, seed, [label], "xss", label, payload=payload
                )
                if self._can_add(v):
                    results.append(v)

                # Double-encoded
                enc_payload = payload.replace("<", "%253c").replace(">", "%253e")
                m_query2 = {k: list(v) for k, v in query.items()}
                m_query2[param] = [enc_payload]
                v = self._build_contract_variant(
                    parsed, m_query2, seed,
                    [f"{label}_encoded"], "xss", f"{label}_enc", payload=enc_payload,
                )
                if self._can_add(v):
                    results.append(v)

            # Array wrap
            m_query = {k: list(v) for k, v in query.items()}
            val = m_query.pop(param)
            m_query[f"{param}[]"] = val
            v = self._build_contract_variant(
                parsed, m_query, seed,
                ["xss_array_wrap"], "xss", "xss_array_wrap", param_shape="array",
            )
            if self._can_add(v):
                results.append(v)

        # Proto pollution  (change #4: reclassified as "json" attack_type)
        if strategy and strategy.get("enable_json_mutations"):
            for pp in ["__proto__", "constructor", "prototype"]:
                m_query = {k: list(v) for k, v in query.items()}
                payload = '{"polluted":"true"}'
                m_query[pp] = [payload]
                v = self._build_contract_variant(
                    parsed, m_query, seed,
                    ["proto_pollution"], "json", "proto_pollution",
                    payload=payload, param_shape="json",
                )
                if self._can_add(v):
                    results.append(v)

        return results

    def _mutate_lfi(self, parsed, query, seed, strategy=None):
        results = []
        # Scaled traversal depth: 2× path segments, capped at 6
        path_depth = max(1, len(parsed.path.strip("/").split("/")))
        depth_count = min(6, path_depth * 2)
        depths = ["../" * depth_count, "/"]
        files = ["etc/passwd", "windows/win.ini", "proc/self/environ"]

        for param in sorted(query.keys()):
            if self.budget and self.budget.should_throttle("lfi"):
                break

            for d in depths:
                for f in files:
                    payload = f"{d}{f}"
                    m_query = {k: list(v) for k, v in query.items()}
                    m_query[param] = [payload]
                    v = self._build_contract_variant(
                        parsed, m_query, seed,
                        ["lfi_traversal"], "lfi", "lfi_traversal", payload=payload,
                    )
                    if self._can_add(v):
                        results.append(v)

                    # Encoded
                    enc_payload = payload.replace("../", "..%2f").replace("/", "%2f")
                    m_query2 = {k: list(v) for k, v in query.items()}
                    m_query2[param] = [enc_payload]
                    v = self._build_contract_variant(
                        parsed, m_query2, seed,
                        ["lfi_encoded"], "lfi", "lfi_enc", payload=enc_payload,
                    )
                    if self._can_add(v):
                        results.append(v)

            if strategy and strategy.get("enable_lfi"):
                for ext in [".php", ".html", "%00"]:
                    m_query = {k: list(v) for k, v in query.items()}
                    orig = m_query[param][0] if m_query[param] else "index"
                    m_query[param] = [f"{orig}{ext}"]
                    v = self._build_contract_variant(
                        parsed, m_query, seed,
                        ["lfi_suffix"], "lfi", "lfi_suffix", payload=ext,
                    )
                    if self._can_add(v):
                        results.append(v)

        return results

    _SSRF_SENSITIVE_PARAMS = {"url", "redirect", "callback", "dest", "target", "endpoint"}

    def _mutate_ssrf(self, parsed, query, seed, strategy=None):
        results = []
        targets = ["127.0.0.1", "localhost", "0.0.0.0"]
        base_schemes = ["http", "https"]
        exotic_schemes = []

        if strategy and strategy.get("enable_ssrf"):
            targets.append("169.254.169.254")
            exotic_schemes = ["gopher", "dict", "file", "ftp"]

        for param in sorted(query.keys()):
            if self.budget and self.budget.should_throttle("ssrf"):
                break

            # Exotic schemes only for URL-like param names
            param_lower = param.lower().rstrip("[]")
            schemes = base_schemes + (
                exotic_schemes if param_lower in self._SSRF_SENSITIVE_PARAMS else []
            )

            for s in schemes:
                for t in targets:
                    payload = f"{s}://{t}"
                    m_query = {k: list(v) for k, v in query.items()}
                    m_query[param] = [payload]
                    v = self._build_contract_variant(
                        parsed, m_query, seed,
                        [f"ssrf_{s}"], "ssrf", "ssrf_scheme", payload=payload,
                    )
                    if self._can_add(v):
                        results.append(v)

        return results

    # ------------------------------------------------------------------
    # Contract builder  (V7 — deterministic normalisation)
    # ------------------------------------------------------------------

    def _build_contract_variant(self, parsed, query_dict, source_seed,
                                mutations, attack_type, mutation_type,
                                payload=None, param_shape="scalar"):
        """
        Builds a standardised variant dict with a stable, deterministic URL
        and a collision-resistant variant_id / payload_hash.
        """
        # 1. Build deterministic, sorted query string directly from query_dict
        stable_pairs = []
        for k in sorted(query_dict.keys()):
            vals = query_dict[k]
            if isinstance(vals, list):
                for v in sorted(vals):
                    stable_pairs.append((k, v))
            else:
                stable_pairs.append((k, str(vals)))

        sorted_q = urlencode(stable_pairs, doseq=False)

        url = urlunparse((
            parsed.scheme, parsed.netloc,
            parsed.path, "",          # params segment empty
            sorted_q, "",             # fragment stripped
        ))

        # 2. payload_hash — hash includes netloc+path for cross-origin collision resistance
        ph_input = f"{parsed.netloc}|{parsed.path}|{payload}|{sorted_q}"
        payload_hash = hashlib.sha512(ph_input.encode(), usedforsecurity=False).hexdigest()[:8]

        # 3. variant_id — full identity hash
        id_input = f"{url}|{attack_type}|{mutation_type}|{payload_hash}|{param_shape}"
        variant_id = hashlib.sha512(id_input.encode(), usedforsecurity=False).hexdigest()

        return {
            "url": url,
            "method": "GET",
            "attack_type": attack_type,
            "mutation_type": mutation_type,
            "mutations": mutations,
            "source_seed": source_seed,
            "payload": payload,
            "payload_hash": payload_hash,
            "param_shape": param_shape,
            "variant_id": variant_id,
        }

    # ------------------------------------------------------------------
    # Budget gate
    # ------------------------------------------------------------------

    def _can_add(self, v):
        self.stats["generated"] += 1
        if not self.budget:
            self.stats["accepted"] += 1
            return True

        if self.budget.can_add_variant(v):
            self.stats["accepted"] += 1
            return True
        else:
            self.stats["dropped"] += 1
            return False

    # ------------------------------------------------------------------
    # Deterministic selection  (replaces random.sample)
    # ------------------------------------------------------------------

    _MUTATION_PRIORITY = {
        "xss_probe_breakout": 10,
        "xss_probe_svg": 9,
        "xss_probe_minimal": 8,
        "xss_js_scheme": 7,
        "xss_data_scheme": 7,
        "xss_probe_breakout_enc": 6,
        "xss_probe_svg_enc": 5,
        "xss_probe_minimal_enc": 5,
        "xss_js_scheme_enc": 4,
        "xss_data_scheme_enc": 4,
        "xss_array_wrap": 3,
        "proto_pollution": 3,
        "lfi_traversal": 10,
        "lfi_enc": 8,
        "lfi_suffix": 6,
        "ssrf_scheme": 7,
    }

    def _deterministic_select(self, variants, budget, seed_url, attack_type):
        """
        Select top-N variants by mutation priority.
        Ties broken by stable hash so output is reproducible.
        """
        def sort_key(v):
            prio = self._MUTATION_PRIORITY.get(v.get("mutation_type", ""), 1)
            tie = hashlib.sha512(
                f"{seed_url}|{attack_type}|{v['variant_id']}".encode(),
                usedforsecurity=False
            ).hexdigest()
            return (-prio, tie)

        variants.sort(key=sort_key)
        return variants[:budget]
