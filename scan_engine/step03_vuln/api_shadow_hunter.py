from scan_engine.helpers.http_client import get_session
from urllib.parse import urljoin

class APIShadowHunter:
    """
    Expert Auditor for Shadow APIs and Undocumented Endpoints.
    Searches for exposed documentation files (Swagger/OpenAPI) and 
    compares them with active endpoints.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-ShadowHunter/1.0"})
        # Common locations for API documentation
        self.doc_paths = [
            "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/index.html",
            "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml",
            "/api/docs", "/api/swagger-ui", "/docs/api-docs"
        ]

    def scan_endpoints(self, base_url, logger=None):
        findings = []
        if logger: logger(f"Shadow Hunter: Searching for exposed API documentation at {base_url}...", "INFO")

        for path in self.doc_paths:
            try:
                url = urljoin(base_url, path)
                resp = self.session.get(url, timeout=5)
                
                if resp.status_code == 200:
                    # Validate content
                    content = resp.text.lower()
                    if any(k in content for k in ["swagger", "openapi", "paths", "definitions", "\"info\""]):
                        findings.append({
                            "title": "Exposed API Documentation (Shadow Hunter)",
                            "description": f"Found exposed API documentation at {url}. This reveals the entire internal API structure, parameters, and potentially undocumented/debug endpoints.",
                            "severity": "high",
                            "tool_source": "api_shadow_hunter",
                            "url": url,
                            "raw_loot": resp.text[:1000]
                        })
                        if logger: logger(f"HIGH: Exposed API Docs found at {url}", "SUCCESS")
                        
                        # Active: Extract endpoints from the doc
                        extracted = self._extract_endpoints(resp.text, url, logger)
                        if extracted:
                            findings.append({
                                "title": "API Surface Expansion (Shadow Hunter)",
                                "description": f"Extracted {len(extracted)} undocumented endpoints from the exposed documentation. These should be audited for authentication bypass.",
                                "severity": "info",
                                "tool_source": "api_shadow_hunter",
                                "url": url,
                                "endpoints_count": len(extracted)
                            })
                        break # Found a valid one
            except Exception:
                pass
        return findings

    def _extract_endpoints(self, doc_text, source_url, logger):
        # Very simple extraction for JSON based Swagger/OpenAPI
        import re
        try:
            # Match JSON keys that look like paths: "/api/user"
            paths = re.findall(r'\"(/[a-zA-Z0-9_\-\/\{\}]+)\"', doc_text)
            unique_paths = list(set([p for p in paths if p.startswith('/') and len(p) > 1]))
            return unique_paths
        except Exception:
            return []
