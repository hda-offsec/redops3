import hashlib
from urllib.parse import urlparse, parse_qs, urlencode


class BudgetManager:
    """
    V7 BudgetManager — Offensive mutation budgeting with structural deduplication.

    Dedup axes (canonical key):
        method | scheme | host | path_normalized | query_value_hash | param_shape | mutation_type | payload_hash

    Budget axes:
        - max_total_variants  : hard global cap
        - max_variants_per_seed : per source_seed cap
        - max_seeds           : cap on unique source_seeds processed
        - soft_threshold      : per mutation_type category throttle
    """

    def __init__(self, max_seeds=500, max_variants_per_seed=30,
                 max_total_variants=2000, config=None):
        self.max_seeds = max_seeds
        self.max_variants_per_seed = max_variants_per_seed
        self.max_total_variants = max_total_variants
        self.soft_threshold = 50

        if config:
            self.max_total_variants = config.get("mutation_budget", self.max_total_variants)
            self.max_variants_per_seed = config.get("max_variants_per_seed", self.max_variants_per_seed)
            self.max_seeds = config.get("max_seeds", self.max_seeds)
            self.soft_threshold = config.get("mutation_soft_threshold", self.soft_threshold)

        # --- internal state ---
        self.total_variants_count = 0
        self.preserved_variants = 0
        self.seen_keys = set()          # canonical key dedup
        self.category_counts = {}       # mutation_type -> int
        self.seed_counts = {}           # seed_hash -> int
        self.seen_seeds = set()         # unique seed_hash set

        # Granular drop counters (change #3)
        self.dropped_duplicate_key = 0
        self.dropped_seed_cap = 0
        self.dropped_soft_throttle = 0
        self.dropped_global_cap = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def can_add_variant(self, variant_dict):
        """
        Decides whether a variant should be kept.
        Checks: global cap, seed cap, category throttle, dedup key.
        Automatically increments all counters on acceptance.
        """
        # 1. Global cap
        if self.total_variants_count >= self.max_total_variants:
            self.dropped_global_cap += 1
            return False

        # 2. Per-seed cap
        seed_hash = self._seed_hash(variant_dict.get("source_seed", ""))
        if seed_hash not in self.seen_seeds:
            if len(self.seen_seeds) >= self.max_seeds:
                self.dropped_seed_cap += 1
                return False
            self.seen_seeds.add(seed_hash)

        seed_count = self.seed_counts.get(seed_hash, 0)
        if seed_count >= self.max_variants_per_seed:
            self.dropped_seed_cap += 1
            return False

        # 3. Category throttle
        m_type = variant_dict.get("mutation_type", "generic")
        if self.should_throttle(m_type):
            self.dropped_soft_throttle += 1
            return False

        # 4. Canonical-key dedup
        key = self.get_canonical_key(
            url=variant_dict.get("url", ""),
            method=variant_dict.get("method", "GET"),
            mutation_type=m_type,
            payload_hash=variant_dict.get("payload_hash"),
            param_shape=variant_dict.get("param_shape"),
        )
        if key in self.seen_keys:
            self.dropped_duplicate_key += 1
            return False

        # --- accept ---
        self.seen_keys.add(key)
        self.total_variants_count += 1
        self.preserved_variants += 1
        self.seed_counts[seed_hash] = seed_count + 1
        self.category_counts[m_type] = self.category_counts.get(m_type, 0) + 1
        return True

    def should_throttle(self, mutation_type):
        """Returns True if a specific mutation category exceeds the soft threshold."""
        return self.category_counts.get(mutation_type, 0) >= self.soft_threshold

    def get_stats(self):
        dropped_total = (
            self.dropped_duplicate_key + self.dropped_seed_cap
            + self.dropped_soft_throttle + self.dropped_global_cap
        )
        return {
            "total": self.total_variants_count,
            "preserved": self.preserved_variants,
            "dropped_total": dropped_total,
            "dropped_duplicate_key": self.dropped_duplicate_key,
            "dropped_seed_cap": self.dropped_seed_cap,
            "dropped_soft_throttle": self.dropped_soft_throttle,
            "dropped_global_cap": self.dropped_global_cap,
            "categories": dict(self.category_counts),
            "seeds_tracked": len(self.seen_seeds),
            "per_seed": dict(self.seed_counts),
            "capacity_reached": self.total_variants_count >= self.max_total_variants,
        }

    # ------------------------------------------------------------------
    # Canonical Key  (V7 — collision-safe)
    # ------------------------------------------------------------------

    @staticmethod
    def get_canonical_key(url, method="GET", mutation_type="generic",
                          payload_hash=None, param_shape=None):
        """
        V7 canonical key.

        Components (all lowered / normalised):
            method | scheme | host | path | query_value_hash | param_shape | mutation_type | payload_hash

        Key differences vs V6:
          - Full normalised path instead of path_depth (no /admin vs /login collision).
          - query_value_hash includes sorted param names AND their values
            so two URLs with same params but different injected values
            are NOT considered duplicates.
          - param_shape is deterministic: sorted key initials A/S.
        """
        try:
            parsed = urlparse(url)
            scheme = (parsed.scheme or "http").lower()
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "/").rstrip("/").lower() or "/"

            query = parse_qs(parsed.query, keep_blank_values=True)
            params_sorted = sorted(query.keys())

            # Deterministic query value hash — includes values
            stable_pairs = []
            for k in params_sorted:
                vals = sorted(query[k])
                for v in vals:
                    stable_pairs.append((k, v))
            
            # Using SHA256 for stronger fingerprinting (V8)
            qv_hash = hashlib.blake2b(
                urlencode(stable_pairs, doseq=False).encode()
            ).hexdigest()[:16]

            # Deterministic param_shape: "A" for array-style, "S" for scalar.
            # If param_shape contains free-form labels (e.g. "array", "json")
            # prefix with "T:" so it never collides with A/S signatures.
            if not param_shape:
                param_shape = "".join(
                    "A" if "[]" in p else "S" for p in params_sorted
                )
            elif any(c not in ("A", "S") for c in param_shape):
                param_shape = f"T:{param_shape}"

            # payload_hash retained for collision safety even though
            # qv_hash already differentiates values — the two hashes
            # cover different dimensions (payload identity vs full query state).
            if not payload_hash:
                payload_hash = "00000000"

            canonical = (
                f"{method}|{scheme}|{host}|{path}"
                f"|{qv_hash}|{param_shape}|{mutation_type}|{payload_hash}"
            )
            return hashlib.blake2b(canonical.encode()).hexdigest()
        except Exception:
            return hashlib.blake2b(url.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _seed_hash(source_seed):
        """Stable hash for a source seed URL."""
        raw = str(source_seed).strip()
        return hashlib.blake2b(raw.encode()).hexdigest()[:16]
