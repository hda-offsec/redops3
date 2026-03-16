from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import hashlib
from scan_engine.helpers.budget_manager import BudgetManager

def normalize_endpoint(url: str) -> str:
    """V6 Normalization: OSCP-grade endpoint sanitization."""
    if not url: return ""
    try:
        parsed = urlparse(url)
        # 1. Normalize scheme and netloc
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        netloc = parsed.netloc.lower()
        # 2. Strip fragments and normalize path
        path = parsed.path.replace("//", "/")
        if not path: path = "/"
        # 3. Canonicalize query order
        query_dict = parse_qs(parsed.query)
        sorted_query = urlencode(sorted(query_dict.items()), doseq=True)
        return urlunparse((scheme, netloc, path, "", sorted_query, ""))
    except Exception:
        return url.strip()

class EnumSeedFactory:
    def __init__(self, target, port, protocol, config=None, options=None):
        self.options = options
        self.target = target
        self.port = str(port)
        self.protocol = protocol
        self.raw_endpoints = []
        self.arjun_params = []
        self.config = config or {}
        
        self.high_risk_params = ["id", "file", "url", "redirect", "callback", "path", "template", "include"]
        self.dynamic_exts = ['.php', '.jsp', '.asp', '.aspx', '.cfm', '.py', '.rb', '.pl', '.cgi']
        self.static_exts = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ico', '.pdf']

        # --- SCOPE ENFORCEMENT ---
        # Extract the root domain for scope filtering (e.g. "iffen.fr" from "www.iffen.fr")
        parts = self.target.lower().split('.')
        if len(parts) >= 2:
            self.root_domain = '.'.join(parts[-2:])  # e.g. "iffen.fr"
        else:
            self.root_domain = self.target.lower()

    def _is_in_scope(self, url):
        """Check if a URL belongs to the target domain (prevents cross-domain leakage via redirects)."""
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            return hostname.endswith(self.root_domain)
        except Exception:
            return False

    def add_raw_endpoints(self, endpoints, source="unknown"):
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url")
            if url and self._is_in_scope(url):
                self.raw_endpoints.append({"url": url, "source": source})

    def add_arjun_params(self, params):
        if params:
            self.arjun_params = list(set(self.arjun_params + params))

    def produce_canonical_output(self):
        """Pipeline Phase 1 & 2: Normalize -> Prioritize -> Synthesize."""
        # 1. Normalize
        normalized_eps = []
        seen = set()
        for raw in self.raw_endpoints:
            norm_url = normalize_endpoint(raw["url"])
            if norm_url and norm_url not in seen:
                seen.add(norm_url)
                normalized_eps.append({"url": norm_url, "source": raw["source"]})

        # 2. Prioritize (Weighted Scoring)
        scored = []
        for ep in normalized_eps:
            url = ep["url"]
            parsed = urlparse(url)
            path = parsed.path.lower()
            score = 10 # Base
            
            # Weighted scoring logic
            if parsed.query: score += 70  # Dynamic param present
            if any(p in url.lower() for p in self.high_risk_params): score += 40
            if any(api in path for api in ["/api/", "/v1/", "/rest/"]): score += 20
            if ".json" in path or "json" in url.lower(): score += 15
            if any(ext in path for ext in self.static_exts): score -= 60
            
            scored.append((score, ep))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        limit = self.config.get("enum_limit", 100)
        top_eps = [x[1] for x in scored[:limit]]

        # 3. Synthesis (Phase 2 Injection Point Generation)
        seeds = []
        seed_meta = {}
        
        # Classification patterns
        framework_params = {"redirect_to", "reauth", "wp_lang", "ver", "lang", "utm_source", "utm_medium", "utm_campaign", "s"}
        # 's' is the search param, while others are less 'injectable' but valid surface.
        
        for ep in top_eps:
            url = ep["url"]
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Determine if it's a static asset
            is_static = any(path.endswith(ext) for ext in self.static_exts)
            
            if parsed.query:
                query_params = parse_qs(parsed.query)
                param_names = set(query_params.keys())
                
                # Classify based on path and params
                classification = "candidate_injection_surface"
                if is_static:
                    classification = "parameterized_asset"
                elif param_names.issubset(framework_params):
                    # Special case for 's' (Search) - it's a real surface even if it's framework
                    if "s" in param_names:
                        classification = "candidate_injection_surface"
                    else:
                        classification = "legitimate_framework_parameter"
                
                # V12: Only include as 'seed' if it's not a pure static asset with no high-risk params
                include_as_seed = True
                if classification == "parameterized_asset":
                    # Check if it has any high-risk params (e.g. ?url=...)
                    if not any(p in param_names for p in self.high_risk_params):
                        include_as_seed = False
                
                if include_as_seed:
                    seeds.append(url)
                    seed_meta[url] = {
                        "source": ep["source"],
                        "dynamic": True,
                        "classification": classification,
                        "params": list(param_names),
                        "score": 100 if classification == "candidate_injection_surface" else 30
                    }
            elif self.arjun_params and not is_static:
                # ELSE IF Arjun params exist and not static
                for p in self.arjun_params[:10]:
                    new_url = f"{url}?{p}=__seed__" if "?" not in url else f"{url}&{p}=__seed__"
                    seeds.append(new_url)
                    seed_meta[new_url] = {
                        "source": f"arjun:{ep['source']}",
                        "dynamic": True,
                        "classification": "candidate_injection_surface",
                        "params": [p],
                        "score": 80
                    }
            else:
                pass

        return {
            "normalized": {"endpoints": top_eps, "count": len(top_eps)},
            "derived": {
                "targets": [ep["url"] for ep in top_eps],
                "injection_points": seeds,
                "seed_meta": seed_meta,
                "seed_stats": {"raw": len(self.raw_endpoints), "normalized": len(normalized_eps), "seeds": len(seeds)}
            }
        }

