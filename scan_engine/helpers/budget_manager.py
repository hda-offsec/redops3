import hashlib
from urllib.parse import urlparse, urlunparse

class BudgetManager:
    def __init__(self, max_seeds=500, max_variants_per_seed=10, max_total_variants=2000):
        self.max_seeds = max_seeds
        self.max_variants_per_seed = max_variants_per_seed
        self.max_total_variants = max_total_variants
        self.total_variants_count = 0
        self.dropped_duplicates = 0
        self.preserved_variants = 0
        self.seen_keys = set()

    def can_add_variant(self, url, mutation_type="generic"):
        if self.total_variants_count >= self.max_total_variants:
            return False
            
        key = self.get_canonical_key(url, mutation_type=mutation_type)
        if key in self.seen_keys:
            self.dropped_duplicates += 1
            return False
            
        self.seen_keys.add(key)
        self.preserved_variants += 1
        return True

    def track_variant(self):
        self.total_variants_count += 1

    @staticmethod
    def get_canonical_key(url, method="GET", mutation_type="generic"):
        """
        Generates a robust canonical key for an endpoint + mutation shape + type.
        Includes: host, path, param names, param structure, scheme, and mutation type.
        """
        try:
            parsed = urlparse(url)
            host = parsed.hostname.lower() if parsed.hostname else ""
            path = parsed.path.lower()
            if path.endswith("/"): path = path[:-1]
            
            # Extract param names and "shape" (is it an array p[] ?)
            from urllib.parse import parse_qs
            query = parse_qs(parsed.query)
            params_sorted = sorted(query.keys())
            param_shape = "".join(["A" if "[]" in p else "S" for p in params_sorted])
            
            # Payload hash (short) to differentiate different payloads on same param structure
            payload_str = str(sorted(query.items()))
            payload_hash = hashlib.md5(payload_str.encode()).hexdigest()[:8]
            
            # Canonical string: method + scheme + host + path + sorted_params + shape + type + hash
            canonical = f"{method}{parsed.scheme}{host}{path}{','.join(params_sorted)}{param_shape}{mutation_type}{payload_hash}"
            return hashlib.md5(canonical.encode()).hexdigest()
        except:
            return hashlib.md5(url.encode()).hexdigest()


