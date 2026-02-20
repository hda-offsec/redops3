import re
from typing import List
from scan_engine.surface.router_parser import RouterParser
from scan_engine.surface.route_model import RouteModel

class ArchitectureDetector:
    """
    Scans HTTP traffic and responses for architectural leaks.
    Identifies patterns suggesting backend structure exposure.
    """
    
    def __init__(self):
        self.parser = RouterParser()
        
        # Signatures of architectural leaks
        self.signatures = {
            "js_router": re.compile(r'path\s*:\s*["\']/[^"\']+["\']|component\s*:\s*[a-zA-Z0-9]+Router'),
            "json_api_map": re.compile(r'\{["\']endpoints["\']\s*:|["\']routes["\']\s*:|["\']api_v\d+["\']'),
            "openapi_spec": re.compile(r'["\']openapi["\']\s*:\s*["\']\d+\.\d+\.\d+["\']|["\']swagger["\']\s*:\s*["\']2\.0["\']'),
            "graphql_schema": re.compile(r'__schema|__type|IntrospectionQuery')
        }

    def detect_in_response(self, url: str, content: str, content_type: str) -> List[RouteModel]:
        """Analyzes a single HTTP response for architecture leaks."""
        routes = []
        
        # 1. Detect Signature
        found_signatures = []
        for name, pattern in self.signatures.items():
            if pattern.search(content):
                found_signatures.append(name)
        
        if not found_signatures:
            return []

        # 2. Extract based on type
        if "js" in content_type.lower() or url.endswith('.js'):
             routes.extend(self.parser.parse_js_routes(content, source=f"js_leak:{url}"))
        
        elif "json" in content_type.lower() or url.endswith('.json'):
            try:
                import json
                data = json.loads(content)
                routes.extend(self.parser.parse_api_manifest(data, source=f"json_leak:{url}"))
            except Exception:
                pass

        # 3. Tag source
        for r in routes:
            r.metadata["discovery_method"] = "architecture_leak"
            r.metadata["leak_type"] = ",".join(found_signatures)
            
        return routes
