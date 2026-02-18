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
    def get_canonical_key(url):
        """Generates a canonical key for an endpoint to avoid duplication."""
        try:
            parsed = urlparse(url)
            # Normalize: lower host, strip port if default, strip fragments/params for base key
            host = parsed.hostname.lower() if parsed.hostname else ""
            path = parsed.path.lower()
            if path.endswith("/"): path = path[:-1]
            
            # Canonical string: scheme + host + path
            canonical = f"{parsed.scheme}://{host}{path}"
            return hashlib.md5(canonical.encode()).hexdigest()
        except:
            return hashlib.md5(url.encode()).hexdigest()
