from typing import List, Dict
from scan_engine.surface.route_model import RouteModel

class SurfaceVisualizer:
    """
    Formates discovered surface data for RedOps3 UI components.
    Ensures compatibility with the "Backend Surface Exposure" section.
    """
    
    @staticmethod
    def format_for_ui(routes: List[RouteModel]) -> Dict:
        # Group by first path segment for tree view
        tree = {}
        for r in routes:
            parts = [p for p in r.path.split('/') if p]
            root = parts[0] if parts else "/"
            if root not in tree:
                tree[root] = []
            
            tree[root].append({
                "path": r.path,
                "methods": r.methods,
                "variables": r.variables,
                "risks": r.risk_tags,
                "source": r.source,
                "score": SurfaceVisualizer._calculate_score(r)
            })
            
        return {
            "summary": {
                "total_endpoints": len(routes),
                "mutation_points": len([r for r in routes if "mutation_surface" in r.risk_tags]),
                "high_risk_points": len([r for r in routes if SurfaceVisualizer._calculate_score(r) > 70])
            },
            "tree": tree
        }

    @staticmethod
    def _calculate_score(route: RouteModel) -> int:
        score = 10
        if "mutation_surface" in route.risk_tags: score += 40
        if "object_lookup" in route.risk_tags: score += 30
        if "admin_surface" in route.risk_tags: score += 50
        if "backend_lookup_confirmed" in route.risk_tags: score += 10
        if "weak_validation" in route.risk_tags: score += 20
        
        return min(score, 100)
