import pytest
from scan_engine.helpers.mutation_engine import MutationEngine
from scan_engine.helpers.budget_manager import BudgetManager

def test_mutation_schema_v6():
    me = MutationEngine()
    seed = "http://example.com/api?id=1"
    variants = me.generate_variants(seed, "xss")
    
    assert len(variants) > 0
    v = variants[0]
    # Check V6 Contract
    expected_fields = [
        "url", "attack_type", "mutation_type", "mutations", 
        "source_seed", "payload", "payload_hash", "param_shape", "variant_id"
    ]
    for field in expected_fields:
        assert field in v
    
    assert v["source_seed"] == seed
    assert "id=1" in v["url"] or "ROXSS123" in v["url"]

def test_xss_probes_distinct_ids():
    me = MutationEngine()
    seed = "http://example.com/search?q=test"
    variants = me.generate_variants(seed, "xss")
    
    # Filter by mutation type
    minimal = [v for v in variants if v["mutation_type"] == "xss_probe_minimal"]
    svg = [v for v in variants if v["mutation_type"] == "xss_probe_svg"]
    
    assert len(minimal) == 1
    assert len(svg) == 1
    # Different mutation types + payloads must have different IDs
    assert minimal[0]["variant_id"] != svg[0]["variant_id"]
    assert "ROXSS123" in minimal[0]["url"]
    assert "onload" in svg[0]["url"]

def test_budget_deduplication_payload_sensitivity():
    # Budget Manager with limited capacity
    budget = BudgetManager(max_total_variants=100)
    me = MutationEngine(budget_manager=budget)
    
    seed = "http://example.com/api?id=1"
    
    # 1. First Pass: XSS
    variants_xss = me.generate_variants(seed, "xss")
    # All should be accepted initially
    assert me.stats["accepted"] > 0
    
    # 2. Second Pass: Same seed, same attack (should be dropped because seen_keys track them)
    me.generate_variants(seed, "xss")
    assert me.stats["dropped"] > 0
    
    # 3. Different attack type (LFI) on same URL
    me.generate_variants(seed, "lfi")
    # Should accept some because attack_type differs in variant_id and canonical_key
    assert me.stats["accepted"] > 0

def test_lfi_fallback_generic_params():
    strategy = {"enable_lfi": True}
    me = MutationEngine()
    
    # URL with no known LFI keywords, only 'id'
    seed = "http://example.com/view?id=123"
    variants = me.generate_variants(seed, "lfi", strategy=strategy)
    
    # Should have attempted LFI on 'id' because it's in high-value fallbacks
    traversals = [v for v in variants if v["mutation_type"] == "lfi_traversal"]
    assert len(traversals) > 0
    assert "/etc/passwd" in traversals[0]["url"]

def test_ssrf_fallback_and_metadata():
    strategy = {"enable_ssrf": True}
    me = MutationEngine()
    
    # Seed with no query
    seed = "http://internal-api.local/v1"
    variants = me.generate_variants(seed, "ssrf", strategy=strategy)
    
    # Should have injected common params (id, url, etc.)
    # and generated variants for 169.254.169.254 if strategy enabled
    metadata = [v for v in variants if "169.254.169.254" in v["url"]]
    assert len(metadata) > 0
    assert metadata[0]["mutation_type"] == "ssrf_scheme"

def test_empty_query_fallback():
    me = MutationEngine()
    seed = "http://example.com/path"
    variants = me.generate_variants(seed, "xss")
    
    # Should have at least the original or injected seed
    assert len(variants) >= 1
    assert "ROX_SEED" in variants[0]["url"] or "example.com/path" in variants[0]["url"]

def test_url_building_integrity():
    me = MutationEngine()
    seed = "https://user:pass@example.com:8443/api/v1?q=1#frag"
    variants = me.generate_variants(seed, "xss")
    
    v = variants[0]
    parsed = urlparse(v["url"])
    assert parsed.scheme == "https"
    assert parsed.netloc == "user:pass@example.com:8443"
    assert parsed.path == "/api/v1"
    assert parsed.fragment == "frag"
