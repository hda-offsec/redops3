import re
from urllib.parse import urlparse

class DiscoveryAccumulator:
    """
    Expert utility to unify all discovery intelligence from various scan phases
    and modules into a single, high-fidelity discovery pool.
    Ensures 'Entropy Persistence' across the pipeline.
    """

    @staticmethod
    def _safe_pool_update(pool, data):
        """Safely adds items to the pool set, handling both strings and dictionaries."""
        if not data:
            return
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    pool.add(item)
                elif isinstance(item, dict):
                    # Try common keys for URL/Path
                    url = item.get('url') or item.get('endpoint') or item.get('target') or item.get('path')
                    if url and isinstance(url, str):
                        pool.add(url)
        elif isinstance(data, str):
            pool.add(data)

    @staticmethod
    def gather(results, port, target, proto="http"):
        """
        Gathers EVERY possible URL and parameter from the entire results tree.
        """
        pool = set()
        base_url = f"{proto}://{target}:{port}"
        
        # 1. ENUM PHASE
        enum = results.get('phases', {}).get('enum', {})
        
        # Katana
        DiscoveryAccumulator._safe_pool_update(pool, enum.get('katana', {}).get(str(port), []))
        
        # API / Kiterunner
        DiscoveryAccumulator._safe_pool_update(pool, enum.get('api', {}).get(str(port), []))
        DiscoveryAccumulator._safe_pool_update(pool, enum.get('api', {}).get('discovered_endpoints', []))
        
        # Arjun / Normalized
        normalized = enum.get('normalized', {}).get(str(port), [])
        if isinstance(normalized, dict):
            DiscoveryAccumulator._safe_pool_update(pool, normalized.get('endpoints', []))
        else:
            DiscoveryAccumulator._safe_pool_update(pool, normalized)
        
        DiscoveryAccumulator._safe_pool_update(pool, enum.get('targets', {}).get(str(port), []))
        
        # JS Deep Mining
        js_mining = enum.get('derived', {}).get('js_expert_mining', {}).get(str(port), {})
        if isinstance(js_mining, dict):
            DiscoveryAccumulator._safe_pool_update(pool, js_mining.get('discovered_endpoints', []))
            
        # Surface Expansion (Heuristics)
        expansion = enum.get('derived', {}).get('surface_expansion', {}).get('per_port', {}).get(str(port), {})
        if isinstance(expansion, dict):
            DiscoveryAccumulator._safe_pool_update(pool, expansion.get('derived_endpoints', []))

        # Execution hints synthesized from Cortex targeting
        per_port_hints = enum.get('derived', {}).get('execution_hints', {}).get('per_port', {}).get(str(port), {})
        if isinstance(per_port_hints, dict):
            for hint_bucket in per_port_hints.values():
                if isinstance(hint_bucket, dict):
                    DiscoveryAccumulator._safe_pool_update(pool, hint_bucket.get('seed_priority', []))
                    DiscoveryAccumulator._safe_pool_update(pool, hint_bucket.get('protected_urls', []))
                    DiscoveryAccumulator._safe_pool_update(pool, hint_bucket.get('hpp_urls', []))
                    DiscoveryAccumulator._safe_pool_update(pool, hint_bucket.get('mass_assignment_urls', []))

        # 2. VULN PHASE (Early discovery modules)
        vuln = results.get('phases', {}).get('vuln', {})
        
        # Git / Backups / GraphQL / etc.
        for mod in ['git', 'backups', 'graphql', 'api_expert', 'js_vulns', 'api_shadow']:
            data = vuln.get(mod, [])
            if isinstance(data, (list, dict)):
                if isinstance(data, dict):
                    # Handle per-port storage
                    DiscoveryAccumulator._safe_pool_update(pool, data.get(str(port), []))
                else:
                    DiscoveryAccumulator._safe_pool_update(pool, data)

        surface_mapping = vuln.get('surface_mapping', {}).get(str(port), {})
        if isinstance(surface_mapping, dict):
            for items in surface_mapping.get('tree', {}).values():
                DiscoveryAccumulator._safe_pool_update(pool, items)

        # 3. Dirbusting
        dirb = results.get('phases', {}).get('dirbusting', {}).get(str(port), {})
        if isinstance(dirb, dict):
            for tool in ['ffuf', 'gobuster', 'dirsearch']:
                t_data = dirb.get(tool, {})
                if isinstance(t_data, dict):
                    DiscoveryAccumulator._safe_pool_update(pool, t_data.get('endpoints', []))

        # 4. Findings themselves
        findings = results.get('findings', [])
        for f in findings:
            ep = f.get('endpoint')
            if ep and isinstance(ep, str):
                pool.add(ep)

        # --- NORMALIZATION & FILTERING ---
        clean_pool = set()
        for url in pool:
            if not isinstance(url, str): continue
            url = url.strip()
            if not url or url.startswith('javascript:'): continue
            
            # Root normalization
            if url.startswith('/'):
                url = f"{base_url}{url}"
            elif not url.startswith('http'):
                url = f"{base_url}/{url}"
            
            # Scope check
            try:
                parsed = urlparse(url)
                if parsed.hostname and target in parsed.hostname:
                    clean_pool.add(url)
            except Exception:
                pass
                
        return list(clean_pool)

