from scan_engine.helpers.http_client import get_session
from typing import List, Dict
from scan_engine.surface.route_model import RouteModel

class PassiveBackendValidator:
    """
    Confirms backend reach via passive behavioral observation.
    No active exploitation, no state modification.
    """
    
    def __init__(self, target_host: str, options=None):
        self.options = options
        self.target_host = target_host
        self.session = get_session(options if 'options' in locals() else (self.options if hasattr(self, 'options') else None))
        self.session.headers.update({"User-Agent": "RedOps3-SurfaceValidator/1.0"})

    def validate_route(self, route: RouteModel, port: int, protocol="http") -> bool:
        """
        Tests if the backend actually responds to the discovered route pattern.
        Uses variation analysis (e.g. invalid IDs) to confirm backend logic engagement.
        """
        if not route.variables:
            return self._test_static_reach(route, port, protocol)

        # For dynamic routes, we try two different instances that should trigger backend validation
        # e.g. /users/invalid-uuid vs /users/999999
        base_url = f"{protocol}://{self.target_host}:{port}"
        path = route.path
        
        # Heuristic: Replace variables with something that triggers 400/404/422 from BACKEND
        # If we see 422 Unprocessable Entity or 500 with a backend stack trace (passive), it's confirmed.
        
        # Sample test with generic 'invalid' value
        test_path = path
        for var in route.variables:
            test_path = test_path.replace(f"{{{var}}}", "redops_passive_test")
            test_path = test_path.replace(f":{var}", "redops_passive_test")
            test_path = test_path.replace(f"<{var}>", "redops_passive_test")
            
        try:
            resp = self.session.get(f"{base_url}{test_path}", timeout=5, verify=False)
            
            # Backend engagement indicators:
            # 1. Specific status codes (400, 422, 500)
            # 2. Response headers (X-Powered-By, Server-Timing, specific backend cookies)
            # 3. Content-Type (application/json even on error)
            
            engagement_markers = [
                resp.status_code in [400, 422, 500, 405],
                "application/json" in resp.headers.get("Content-Type", "").lower(),
                any(h in resp.headers for h in ["X-Powered-By", "X-Runtime", "X-Backend-Server"])
            ]
            
            if any(engagement_markers):
                route.risk_tags.append("backend_lookup_confirmed")
                return True
                
        except Exception:
            pass
            
        return False

    def _test_static_reach(self, route: RouteModel, port: int, protocol="http") -> bool:
        url = f"{protocol}://{self.target_host}:{port}{route.path}"
        try:
            # Try with a non-existent method to see if backend handles it
            resp = self.session.options(url, timeout=5, verify=False)
            if resp.status_code != 404:
                route.risk_tags.append("backend_lookup_confirmed")
                return True
        except Exception:
            pass
        return False
