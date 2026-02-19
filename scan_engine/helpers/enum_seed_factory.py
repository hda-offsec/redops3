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
    def __init__(self, target, port, protocol, config=None):
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
        
        for ep in top_eps:
            url = ep["url"]
            parsed = urlparse(url)
            
            if parsed.query:
                # IF endpoint has params: keep structure
                seeds.append(url)
                seed_meta[url] = {"source": ep["source"], "dynamic": True, "score": 100}
            elif self.arjun_params:
                # ELSE IF Arjun params exist: synthesize seeds
                for p in self.arjun_params[:10]:
                    new_url = f"{url}?{p}=__seed__" if "?" not in url else f"{url}&{p}=__seed__"
                    seeds.append(new_url)
                    seed_meta[new_url] = {"source": f"arjun:{ep['source']}", "dynamic": True, "score": 80}
            else:
                # ELSE: DO NOT generate empty seeds (except original as target)
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

