from typing import List, Dict
from scan_engine.surface.route_model import RouteModel

class AttackSurfaceBuilder:
    """
    Transforms discovered routes into RedOps3 Attack Graph nodes and edges.
    """
    
    def __init__(self, port: int, options=None):
        self.options = options
        self.port = port
        self.service_id = f"service:{port}"
        
    def build_nodes(self, routes: List[RouteModel]) -> Dict:
        nodes = []
        edges = []
        
        # Group routes by base path to create a hierarchical view if needed
        # But here we focus on individual dynamic endpoints as requested
        
        for route in routes:
            # 1. Create Route Node
            node_type = self._determine_node_type(route)
            node_id = f"surface:{self.port}:{route.path}"
            
            node_data = route.to_dict()
            node_data["tag"] = "discovered_from_architecture"
            
            nodes.append({
                "type": node_type,
                "id": node_id,
                "data": node_data
            })
            
            # 2. Relation: Service -> Route
            edges.append({
                "from": self.service_id,
                "to": node_id,
                "type": "exposes_surface"
            })
            
            # 3. Create Risk Nodes for high-risk tags
            for tag in route.risk_tags:
                if tag in ["mutation_surface", "object_lookup", "admin_surface"]:
                    risk_id = f"risk:{self.port}:{tag}"
                    # Risk nodes are usually global per port/type in RedOps3
                    # But we link the specific route to it
                    self._ensure_risk_node(nodes, tag, risk_id)
                    edges.append({
                        "from": node_id,
                        "to": risk_id,
                        "type": "contributes_to_risk"
                    })

        return {"nodes": nodes, "edges": edges}

    def _determine_node_type(self, route: RouteModel) -> str:
        if "object_lookup" in route.risk_tags:
            return "object_lookup_endpoint"
        if "mutation_surface" in route.risk_tags:
            return "mutation_surface"
        if "geo_endpoint" in route.risk_tags:
            return "geo_endpoint"
        if "admin_surface" in route.risk_tags:
            return "admin_surface"
        if route.variables:
            return "dynamic_route"
        return "backend_endpoint"

    def _ensure_risk_node(self, nodes: List[Dict], tag: str, risk_id: str):
        if not any(n["id"] == risk_id for n in nodes):
            nodes.append({
                "type": "risk_surface",
                "id": risk_id,
                "data": {"category": tag, "description": f"Aggregated risk for {tag}"}
            })
