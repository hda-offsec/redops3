import re
import json
from typing import List
from scan_engine.surface.route_model import RouteModel

class RouterParser:
    """
    Expert Module: Parses architectural leaks to reconstruct backend routing.
    Stack-agnostic: Handles generic patterns found in JS bundles and JSON manifests.
    """
    
    def __init__(self, options=None):
        self.options = options
        # Generic patterns for routes and variables
        # Matches: /api/v1/user/{id}, /users/:id, /order/<int:id>
        self.path_var_pattern = re.compile(r'\{([a-zA-Z0-9_-]+)\}|:([a-zA-Z0-9_-]+)|<([a-zA-Z0-9_-]+)>')
        
    def parse_js_routes(self, content: str, source: str) -> List[RouteModel]:
        routes = []
        
        # 1. Generic Route Objects in JS
        # Matches patterns like: { path: '/admin', component: ... } or .route('/order/:id')
        patterns = [
            r'path\s*:\s*["\'](/\/[^"\']+)["\']',
            r'\.route\(["\'](/\/[^"\']+)["\']',
            r'url\s*:\s*["\'](/\/[^"\']+)["\']',
            r'endpoint\s*:\s*["\'](/\/[^"\']+)["\']'
        ]
        
        for p in patterns:
            matches = re.finditer(p, content)
            for m in matches:
                path = m.group(1)
                if self._is_valid_path(path):
                    routes.append(self._create_model(path, source))

        # 2. JSON-like structures in JS (e.g., large route maps)
        # We look for arrays or objects containing "path" keys
        json_matches = re.finditer(r'\{[^{}]*path\s*:\s*["\'](/\/[^"\']+)["\'][^{}]*\}', content)
        for m in json_matches:
            path_match = re.search(r'path\s*:\s*["\'](/\/[^"\']+)["\']', m.group(0))
            if path_match:
                path = path_match.group(1)
                model = self._create_model(path, source)
                # Try to extract methods if present in the same block
                methods_match = re.search(r'methods?\s*:\s*\[([^\]]+)\]', m.group(0))
                if methods_match:
                    model.methods = [method.strip().strip('"\'').upper() for method in methods_match.group(1).split(',')]
                routes.append(model)

        return self._deduplicate(routes)

    def parse_api_manifest(self, data: dict, source: str) -> List[RouteModel]:
        """Parses structured JSON manifests (Swagger, OpenAPI, custom API maps)."""
        routes = []
        
        # OpenAPI / Swagger
        if "paths" in data:
            for path, methods in data["paths"].items():
                model = self._create_model(path, source)
                model.methods = [m.upper() for m in methods.keys() if m.lower() in ['get', 'post', 'put', 'delete', 'patch']]
                routes.append(model)
        
        # Generic List of endpoints
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str) and item.startswith('/'):
                    routes.append(self._create_model(item, source))
                elif isinstance(item, dict) and "path" in item:
                    routes.append(self._create_model(item["path"], source))

        return self._deduplicate(routes)

    def _create_model(self, path: str, source: str) -> RouteModel:
        # Extract variables from path
        vars = []
        for match in self.path_var_pattern.finditer(path):
            var = match.group(1) or match.group(2) or match.group(3)
            if var: vars.append(var)
            
        return RouteModel(
            path=path,
            variables=vars,
            source=source,
            methods=["GET"] # Default
        )

    def _is_valid_path(self, path: str) -> bool:
        # Avoid false positives like protocol slashes if not careful
        if path.startswith('//') and not path.startswith('///'):
            return False
        return len(path) > 1 and path.startswith('/')

    def _deduplicate(self, routes: List[RouteModel]) -> List[RouteModel]:
        seen = set()
        unique = []
        for r in routes:
            if r.path not in seen:
                seen.add(r.path)
                unique.append(r)
        return unique
