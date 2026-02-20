from typing import List
from scan_engine.surface.route_model import RouteModel

class RiskClassifier:
    """
    Classifies backend surface area based on path patterns and methods.
    Strictly passive classification.
    """
    
    def classify(self, route: RouteModel):
        tags = []
        path = route.path.lower()
        
        # 1. Mutation Surface
        if any(m in route.methods for m in ["POST", "PUT", "PATCH", "DELETE"]):
            tags.append("mutation_surface")
        if any(keyword in path for keyword in ["create", "update", "delete", "remove", "edit", "save"]):
            tags.append("mutation_surface")

        # 2. Object Lookup (High value for IDOR/BOLA)
        if any(v in ["id", "uuid", "uid", "pk"] for v in [var.lower() for var in route.variables]):
            tags.append("object_lookup")
        if any(keyword in path for keyword in ["/user/", "/account/", "/profile/", "/order/", "/invoice/"]):
             if route.variables:
                 tags.append("object_lookup")

        # 3. Geo/Location Data
        if any(keyword in path for keyword in ["geo", "location", "coords", "proximity", "map", "nearby"]):
            tags.append("geo_endpoint")

        # 4. Stateful Objects
        if any(keyword in path for keyword in ["favorite", "bookmark", "cart", "wishlist", "bundle"]):
            tags.append("stateful_object")

        # 5. Administrative Surface
        if any(keyword in path for keyword in ["admin", "root", "console", "config", "settings", "manage"]):
            tags.append("admin_surface")

        # 6. Weak Validation Patterns
        # Detection of broad regex patterns in routes (e.g. {path:*})
        for constraint in route.constraints.values():
            if "[^/]" in constraint or ".*" in constraint:
                tags.append("weak_validation")

        route.risk_tags = list(set(tags))
        return route

    def batch_classify(self, routes: List[RouteModel]) -> List[RouteModel]:
        for r in routes:
            self.classify(r)
        return routes
