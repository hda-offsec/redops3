import hashlib
from urllib.parse import urlparse, urlunparse

class BudgetManager:
    def __init__(self, max_seeds=500, max_variants_per_seed=10, max_total_variants=2000):
        self.max_seeds = max_seeds
        self.max_variants_per_seed = max_variants_per_seed
        self.max_total_variants = max_total_variants
        self.total_variants_count = 0

    def can_add_variant(self):
        return self.total_variants_count < self.max_total_variants

    def track_variant(self):
        self.total_variants_count += 1

    @staticmethod
    def get_canonical_key(url, method="GET"):
        """
        Generates a robust canonical key for an endpoint + mutation shape.
        Includes: host, path, param names, param structure (array/scalar), and scheme.
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
            
            # Canonical string
            # key = method + scheme + host + path + sorted_params + shape
            canonical = f"{method}{parsed.scheme}{host}{path}{','.join(params_sorted)}{param_shape}"
            return hashlib.md5(canonical.encode()).hexdigest()
        except:
            return hashlib.md5(url.encode()).hexdigest()

