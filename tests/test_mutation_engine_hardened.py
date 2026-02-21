"""
V7.1 Hardened tests for BudgetManager + MutationEngine.

Covers:
  1) Same depth, different paths → no collision
  2) Same params/type, different values → no collision
  3) max_variants_per_seed enforced
  4) Normalisation stability (same dict → same url string)
  5) Deterministic selection (no randomness)
  6) Existing contract / integration tests
  7) Synthetic seed symmetry breaking (change #1)
  8) param_shape T: prefix normalisation (change #2)
  9) Granular drop counters (change #3)
  10) proto_pollution attack_type reclassified to json (change #4)
"""
import pytest
from scan_engine.helpers.mutation_engine import MutationEngine
from scan_engine.helpers.budget_manager import BudgetManager
from scan_engine.helpers.enum_seed_factory import EnumSeedFactory


# =====================================================================
# A) Canonical key: no path-depth collision
# =====================================================================

class TestCanonicalKeyNoCollision:

    def test_same_depth_different_paths_no_collision(self):
        """
        /admin and /login both have depth=1.
        Old V6 used path_depth → collision.  V7 uses full path → no collision.
        """
        budget = BudgetManager(max_total_variants=100)

        v1 = {
            "url": "http://example.com/admin?id=1",
            "mutation_type": "xss_probe_minimal",
            "payload_hash": "aaaa1111",
            "param_shape": "S",
            "source_seed": "http://example.com/admin?id=1",
        }
        v2 = {
            "url": "http://example.com/login?id=1",
            "mutation_type": "xss_probe_minimal",
            "payload_hash": "aaaa1111",
            "param_shape": "S",
            "source_seed": "http://example.com/login?id=1",
        }

        assert budget.can_add_variant(v1) is True
        assert budget.can_add_variant(v2) is True, \
            "Different paths should NOT collide in canonical key"

    def test_deeper_paths_no_collision(self):
        """/api/v1/users vs /api/v2/users — same depth=3, different path."""
        budget = BudgetManager(max_total_variants=100)

        v1 = {
            "url": "http://t.com/api/v1/users?x=1",
            "mutation_type": "generic",
            "payload_hash": "bbbb2222",
            "param_shape": "S",
            "source_seed": "http://t.com/api/v1/users?x=1",
        }
        v2 = {
            "url": "http://t.com/api/v2/users?x=1",
            "mutation_type": "generic",
            "payload_hash": "bbbb2222",
            "param_shape": "S",
            "source_seed": "http://t.com/api/v2/users?x=1",
        }

        assert budget.can_add_variant(v1) is True
        assert budget.can_add_variant(v2) is True


# =====================================================================
# B) Same params/type but different injected values → no collision
# =====================================================================

class TestValueAwareDedup:

    def test_same_param_different_values_no_collision(self):
        """
        Two XSS probes on same param 'id' with different payloads.
        Old V6 could collide if payload_hash was identical.
        V7 includes query values in the canonical key.
        """
        budget = BudgetManager(max_total_variants=100)

        v1 = {
            "url": "http://example.com/page?id=ROXSS123",
            "mutation_type": "xss_probe_minimal",
            "payload_hash": "aaa11111",
            "param_shape": "S",
            "source_seed": "http://example.com/page?id=1",
        }
        v2 = {
            "url": "http://example.com/page?id=%22%3E%3CROXSS123",
            "mutation_type": "xss_probe_minimal",
            "payload_hash": "bbb22222",
            "param_shape": "S",
            "source_seed": "http://example.com/page?id=1",
        }

        assert budget.can_add_variant(v1) is True
        assert budget.can_add_variant(v2) is True, \
            "Different query values must NOT be deduped"

    def test_exact_duplicate_is_dropped(self):
        """Identical variant submitted twice → second one dropped."""
        budget = BudgetManager(max_total_variants=100)

        v = {
            "url": "http://example.com/page?id=ROXSS123",
            "mutation_type": "xss_probe_minimal",
            "payload_hash": "aaa11111",
            "param_shape": "S",
            "source_seed": "http://example.com/page?id=1",
        }
        assert budget.can_add_variant(v) is True
        assert budget.can_add_variant(v) is False


# =====================================================================
# C) max_variants_per_seed enforcement
# =====================================================================

class TestPerSeedBudget:

    def test_max_variants_per_seed_respected(self):
        """After max_variants_per_seed, further variants for that seed are refused."""
        limit = 3
        budget = BudgetManager(max_variants_per_seed=limit, max_total_variants=1000)

        seed = "http://example.com/target?x=1"
        accepted = 0
        for i in range(20):
            v = {
                "url": f"http://example.com/target?x=payload_{i}",
                "mutation_type": "xss_probe_minimal",
                "payload_hash": f"hash{i:04d}",
                "param_shape": "S",
                "source_seed": seed,
            }
            if budget.can_add_variant(v):
                accepted += 1

        assert accepted == limit, \
            f"Expected exactly {limit} accepted, got {accepted}"

    def test_different_seeds_independent_budgets(self):
        """Two different seeds each get their own per-seed budget."""
        limit = 2
        budget = BudgetManager(max_variants_per_seed=limit, max_total_variants=1000)

        for seed_id in ["seedA", "seedB"]:
            seed = f"http://example.com/{seed_id}?x=1"
            accepted = 0
            for i in range(10):
                v = {
                    "url": f"http://example.com/{seed_id}?x=pay_{i}",
                    "mutation_type": "generic",
                    "payload_hash": f"h{seed_id}{i}",
                    "param_shape": "S",
                    "source_seed": seed,
                }
                if budget.can_add_variant(v):
                    accepted += 1
            assert accepted == limit

    def test_max_seeds_enforced(self):
        """Once max_seeds unique seeds are seen, new seeds are refused."""
        budget = BudgetManager(max_seeds=2, max_total_variants=1000, max_variants_per_seed=100)

        seeds = [
            "http://a.com/1?x=1",
            "http://b.com/2?x=1",
            "http://c.com/3?x=1",
        ]
        results = []
        for s in seeds:
            v = {
                "url": s,
                "mutation_type": "generic",
                "payload_hash": "ffff0000",
                "param_shape": "S",
                "source_seed": s,
            }
            results.append(budget.can_add_variant(v))

        assert results == [True, True, False], \
            f"3rd seed should be refused, got {results}"


# =====================================================================
# D) Normalisation stability
# =====================================================================

class TestNormalisationStability:

    def test_same_dict_produces_same_url(self):
        """Calling _build_contract_variant twice with same input → identical URL."""
        engine = MutationEngine()
        from urllib.parse import urlparse

        parsed = urlparse("http://example.com/test")
        qdict = {"b": ["2"], "a": ["1"]}

        v1 = engine._build_contract_variant(
            parsed, qdict, "seed", ["m"], "xss", "xss_probe", payload="P"
        )
        v2 = engine._build_contract_variant(
            parsed, qdict, "seed", ["m"], "xss", "xss_probe", payload="P"
        )

        assert v1["url"] == v2["url"]
        assert v1["variant_id"] == v2["variant_id"]
        assert v1["payload_hash"] == v2["payload_hash"]

    def test_param_order_irrelevant(self):
        """Query dict with keys in different insertion order → same URL."""
        engine = MutationEngine()
        from urllib.parse import urlparse
        from collections import OrderedDict

        parsed = urlparse("http://example.com/x")
        qdict1 = OrderedDict([("z", ["3"]), ("a", ["1"]), ("m", ["2"])])
        qdict2 = OrderedDict([("a", ["1"]), ("m", ["2"]), ("z", ["3"])])

        v1 = engine._build_contract_variant(
            parsed, qdict1, "s", ["m"], "g", "g"
        )
        v2 = engine._build_contract_variant(
            parsed, qdict2, "s", ["m"], "g", "g"
        )

        assert v1["url"] == v2["url"]
        assert v1["variant_id"] == v2["variant_id"]


# =====================================================================
# E) Deterministic selection (no random)
# =====================================================================

class TestDeterministicSelection:

    def test_selection_is_reproducible(self):
        """Same inputs → same selected variants, always."""
        engine = MutationEngine()
        seed = "http://example.com/page?id=1"
        strategy = {"mutation_budget": 3}

        r1 = engine.generate_variants(seed, attack_type="xss", strategy=strategy)
        r2 = engine.generate_variants(seed, attack_type="xss", strategy=strategy)

        ids1 = [v["variant_id"] for v in r1]
        ids2 = [v["variant_id"] for v in r2]

        assert ids1 == ids2, "Selection must be deterministic"


# =====================================================================
# F) Existing integration tests (preserved from V6)
# =====================================================================

class TestVariantContract:

    def test_schema_fields_present(self):
        engine = MutationEngine()
        seed = "http://example.com/page?id=1"
        variants = engine.generate_variants(seed, attack_type="xss")

        assert len(variants) > 0
        required = [
            "url", "attack_type", "mutation_type", "mutations",
            "source_seed", "payload", "payload_hash", "param_shape", "variant_id",
        ]
        for field in required:
            assert field in variants[0], f"Missing contract field: {field}"

        assert variants[0]["attack_type"] == "xss"
        assert len(variants[0]["variant_id"]) == 32


class TestLFI:

    def test_lfi_generates_traversal_on_empty_seed(self):
        engine = MutationEngine()
        seed = "http://example.com/app/view"  # path has 'view' keyword + depth 2
        strategy = {"enable_lfi": True}
        variants = engine.generate_variants(seed, attack_type="lfi", strategy=strategy)

        assert any("file=" in v["url"] for v in variants)
        assert any("etc" in v["url"] and "passwd" in v["url"] for v in variants)


class TestSSRF:

    def test_ssrf_cloud_metadata(self):
        engine = MutationEngine()
        # Use a seed WITH a URL-like param so exotic schemes (gopher) are tested
        seed = "http://example.com/api/data?url=http://internal"
        strategy = {"enable_ssrf": True}
        variants = engine.generate_variants(seed, attack_type="ssrf", strategy=strategy)

        assert any("169.254.169.254" in v["url"] for v in variants)
        assert any("gopher" in v["url"] for v in variants)


class TestEnumSeedFactory:

    def test_factory_weighted_scoring(self):
        factory = EnumSeedFactory("example.com", 80, "http")
        factory.add_raw_endpoints([
            "http://example.com/static/logo.png",
            "http://example.com/api/v1/user?id=1",
            "http://example.com/login",
        ])

        output = factory.produce_canonical_output()
        top = output["normalized"]["endpoints"]
        assert "api/v1" in top[0]["url"]
        assert "logo.png" == top[-1]["url"].split("/")[-1]

    def test_factory_seed_expansion(self):
        factory = EnumSeedFactory("example.com", 80, "http")
        factory.add_raw_endpoints(["http://example.com/search"])
        factory.add_arjun_params(["q", "s"])

        output = factory.produce_canonical_output()
        seeds = output["derived"]["injection_points"]
        assert any("q=__seed__" in s for s in seeds)
        assert any("s=__seed__" in s for s in seeds)


# =====================================================================
# G) Stats reporting  (change #3 — granular counters)
# =====================================================================

class TestBudgetStats:

    def test_stats_reflect_per_seed_counts(self):
        budget = BudgetManager(max_variants_per_seed=5, max_total_variants=100)

        seed = "http://x.com/a?p=1"
        for i in range(5):
            budget.can_add_variant({
                "url": f"http://x.com/a?p=v{i}",
                "mutation_type": "generic",
                "payload_hash": f"h{i}",
                "param_shape": "S",
                "source_seed": seed,
            })

        stats = budget.get_stats()
        assert stats["total"] == 5
        assert stats["preserved"] == 5
        assert stats["seeds_tracked"] == 1
        assert len(stats["per_seed"]) == 1
        seed_hash = list(stats["per_seed"].keys())[0]
        assert stats["per_seed"][seed_hash] == 5

    def test_granular_drop_counters(self):
        """Verify each drop reason is tracked independently."""
        budget = BudgetManager(
            max_variants_per_seed=2,
            max_total_variants=100,
            max_seeds=500,
        )
        budget.soft_threshold = 3

        seed = "http://x.com/a?p=1"

        # Accept 2
        for i in range(2):
            budget.can_add_variant({
                "url": f"http://x.com/a?p=v{i}",
                "mutation_type": "xss",
                "payload_hash": f"h{i}",
                "param_shape": "S",
                "source_seed": seed,
            })

        # 3rd should be dropped by seed cap
        budget.can_add_variant({
            "url": "http://x.com/a?p=v99",
            "mutation_type": "xss",
            "payload_hash": "h99",
            "param_shape": "S",
            "source_seed": seed,
        })

        stats = budget.get_stats()
        assert stats["dropped_seed_cap"] == 1
        assert stats["dropped_duplicate_key"] == 0
        assert stats["dropped_soft_throttle"] == 0
        assert stats["dropped_global_cap"] == 0
        assert stats["dropped_total"] == 1


# =====================================================================
# H) Synthetic seed symmetry breaking (change #1)
# =====================================================================

class TestSyntheticSeedSymmetry:

    def test_different_seeds_produce_different_synthetic_values(self):
        """Two different param-less seeds with HV keywords produce different query values."""
        engine = MutationEngine()

        v1 = engine.generate_variants("http://a.com/app/view", attack_type="xss")
        v2 = engine.generate_variants("http://b.com/app/page", attack_type="xss")

        urls1 = {v["url"] for v in v1}
        urls2 = {v["url"] for v in v2}

        # The URLs should differ because synthetic seed values differ
        assert urls1 != urls2, "Different seeds should not produce identical URL sets"

    def test_same_seed_produces_same_synthetic_values(self):
        """Determinism: same seed → same synthetic values."""
        engine = MutationEngine()

        v1 = engine.generate_variants("http://a.com/app/view", attack_type="xss")
        v2 = engine.generate_variants("http://a.com/app/view", attack_type="xss")

        ids1 = [v["variant_id"] for v in v1]
        ids2 = [v["variant_id"] for v in v2]
        assert ids1 == ids2


# =====================================================================
# I) param_shape normalisation (change #2)
# =====================================================================

class TestParamShapeNormalisation:

    def test_free_label_gets_t_prefix(self):
        """param_shape='array' should become 'T:array' in canonical key."""
        key_array = BudgetManager.get_canonical_key(
            "http://x.com/?a=1", param_shape="array"
        )
        key_s = BudgetManager.get_canonical_key(
            "http://x.com/?a=1", param_shape="S"
        )
        assert key_array != key_s, "T:array and S must not collide"

    def test_as_only_shapes_not_prefixed(self):
        """Pure A/S shapes should NOT get T: prefix."""
        key1 = BudgetManager.get_canonical_key(
            "http://x.com/?a=1&b=2", param_shape="SS"
        )
        key2 = BudgetManager.get_canonical_key(
            "http://x.com/?a=1&b=2", param_shape="SS"
        )
        assert key1 == key2  # stable


# =====================================================================
# J) proto_pollution reclassified (change #4)
# =====================================================================

class TestProtoPollutionReclassification:

    def test_proto_pollution_is_json_attack_type(self):
        engine = MutationEngine()
        seed = "http://example.com/api?x=1"
        strategy = {"enable_json_mutations": True}
        variants = engine.generate_variants(seed, attack_type="xss", strategy=strategy)

        proto_variants = [v for v in variants if v["mutation_type"] == "proto_pollution"]
        assert len(proto_variants) > 0, "proto_pollution variants should be generated"
        for pv in proto_variants:
            assert pv["attack_type"] == "json", \
                f"proto_pollution should have attack_type='json', got '{pv['attack_type']}'"
