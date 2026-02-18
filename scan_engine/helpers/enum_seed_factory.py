import json
import shlex
import os
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from scan_engine.helpers.budget_manager import BudgetManager

class EnumSeedFactory:
    def __init__(self, target, port, protocol):
        self.target = target
        self.port = str(port)
        self.protocol = protocol
        self.raw_endpoints = []
        self.arjun_params = []
        self.dynamic_extensions = ['.php', '.jsp', '.asp', '.aspx', '.cfm', '.py', '.rb', '.pl', '.cgi', '.do', '.action']
        self.static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.ico', '.pdf', '.docx', '.txt', '.xml']
        self.high_value_params = ["id", "q", "s", "search", "page", "file", "path", "url", "redirect", "next", "view", "cmd", "exec", "dir", "action", "mode", "cb", "callback"]
        self.budget = BudgetManager(max_seeds=500, max_total_variants=1500)
    

    def add_raw_endpoints(self, endpoints, source="unknown"):
        """Adds endpoints from various tools. Handles list of strings or list of dicts."""
        if not endpoints:
            return
            
        for ep in endpoints:
            if isinstance(ep, str):
                self.raw_endpoints.append({"url": ep, "source": source, "confidence": 50})
            elif isinstance(ep, dict):
                url = ep.get("url") or ep.get("endpoint")
                if url:
                    self.raw_endpoints.append({
                        "url": url,
                        "source": source,
                        "confidence": ep.get("confidence", 50),
                        "status": ep.get("status")
                    })

    def add_arjun_params(self, params):
        """Adds parameters discovered by Arjun."""
        if params:
            self.arjun_params.extend(params)
            # Deduplicate
            self.arjun_params = list(dict.fromkeys(self.arjun_params))

    def normalize(self):
        """Clean and deduplicate all raw endpoints using canonical keys."""
        seen_keys = set()
        normalized = []
        
        for ep in self.raw_endpoints:
            url = ep["url"].strip()
            if not url:
                continue
            
            # Simple validation & reconstruction
            parsed = urlparse(url)
            if not parsed.netloc:
                if url.startswith("/"):
                    url = f"{self.protocol}://{self.target}:{self.port}{url}"
                else:
                    url = f"{self.protocol}://{self.target}:{self.port}/{url}"
            
            # Generate CANONICAL KEY
            key = BudgetManager.get_canonical_key(url)
            if key in seen_keys:
                continue
            
            seen_keys.add(key)
            ep["canonical_key"] = key
            normalized.append(ep)
            
        return normalized

    def prioritize(self, normalized_eps):
        """Score and rank endpoints with CONTEXTUAL intelligence."""
        scored = []
        
        # 1. Identify high-value namespaces (path prefixes)
        high_value_namespaces = ['/api', '/admin', '/v1', '/v2', '/auth', '/manage', '/config', '/dev']
        namespace_hits = {ns: 0 for ns in high_value_namespaces}
        
        for ep in normalized_eps:
            path = urlparse(ep["url"]).path.lower()
            for ns in high_value_namespaces:
                if path.startswith(ns):
                    namespace_hits[ns] += 1

        # 2. Score each endpoint
        for ep in normalized_eps:
            url = ep["url"]
            url_lower = url.lower()
            path_lower = urlparse(url).path.lower()
            score = 10 # Base
            
            # Contextual Bonus: if in a high-value namespace
            for ns, count in namespace_hits.items():
                if path_lower.startswith(ns) and count > 0:
                    score += 20
            
            # Dynamic markers
            if "?" in url and "=" in url:
                score += 50
            
            if any(ext in url_lower for ext in self.dynamic_extensions):
                score += 30
                
            if any(kw in url_lower for kw in ['admin', 'login', 'upload', 'search', 'view', 'api', 'v1', 'v2', 'debug']):
                score += 20
                
            # Heuristic High Value Params
            if any(f"{p}=" in url_lower for p in self.high_value_params):
                score += 40

            # Arjun Params presence
            for p in self.arjun_params:
                if f"{p}=" in url_lower:
                    score += 25

            # Penalize static
            if any(ext in url_lower for ext in self.static_extensions):
                score -= 70 # Aggressive penalty
                
            scored.append((score, ep))
            
        scored.sort(key=lambda x: x[0], reverse=True)
        return [x[1] for x in scored]

    def expand_seeds(self, prioritized_eps):
        """The core factory logic: normalizes, expands, and propagates."""
        seeds = []
        
        # 1. Collect all usable parameters (Arjun + Heuristics)
        # We use Arjun as high confidence, and a subset of heuristics as fallback/propagation
        primary_params = self.arjun_params if self.arjun_params else self.high_value_params[:8]
        
        # 2. Process prioritized endpoints
        for ep in prioritized_eps[:500]: # Capacity high for engine
            url = ep["url"]
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            # CASE A: URL already has parameters
            if query:
                # Keep original
                seeds.append(url)
                # Inject payload into existing params
                for param in query:
                    # We create a new query where only ONE param is injected at a time? 
                    # For vulnerability scanning, Dalfox handles it if we give the URL.
                    # But for LFI/SSRF we might want explicit seeds.
                    pass
            
            # CASE B: Dynamic path without parameters
            # Propagate parameters to likely-dynamic paths
            path_lower = parsed.path.lower()
            is_dynamic = any(ext in path_lower for ext in self.dynamic_extensions) or not "." in path_lower.split("/")[-1]
            
            if is_dynamic:
                # Propagate top params
                for p in primary_params[:10]:
                    # Create seeds like /page.php?id=ROXSS123
                    new_query = urlencode({p: "ROXSS123"})
                    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                    seeds.append(new_url)

        # fallback if nothing generated
        if not seeds:
            base_url = f"{self.protocol}://{self.target}:{self.port}/"
            for p in primary_params[:10]:
                seeds.append(f"{base_url}?{p}=ROXSS123")

        # Final deduplication
        return list(dict.fromkeys(seeds))

    def produce_canonical_output(self):
        """Run the full factory and return the structured dict."""
        normalized_all = self.normalize()
        prioritized = self.prioritize(normalized_all)
        seeds = self.expand_seeds(prioritized)
        
        return {
            "normalized": {
                "endpoints": prioritized[:500], # Top 500 for engine
                "count": len(prioritized)
            },
            "derived": {
                "targets": [ep["url"] for ep in prioritized[:100]], # Top 100 for UI consumption as high-value
                "injection_points": seeds[:1000], # High volume for scanners
                "seed_stats": {
                    "raw": len(self.raw_endpoints),
                    "normalized": len(prioritized),
                    "seeds": len(seeds),
                    "arjun_hit": len(self.arjun_params) > 0
                }
            }
        }
