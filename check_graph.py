from core.extensions import db
from app import create_app
app = create_app()

from core.models import KnowledgeNode, KnowledgeEdge

with app.app_context():
    nodes = KnowledgeNode.query.filter_by(scan_id=6).count()
    edges = KnowledgeEdge.query.filter_by(scan_id=6).count()
    print(f"Scan 6: {nodes} nodes, {edges} edges")

    if nodes > 0:
        print("\nNodes sample:")
        for n in KnowledgeNode.query.filter_by(scan_id=6).limit(5).all():
            print(f"  - [{n.type}] {n.label} (ID: {n.node_id})")
    
    if edges > 0:
        print("\nEdges sample:")
        for e in KnowledgeEdge.query.filter_by(scan_id=6).limit(5).all():
            print(f"  - {e.source_node} --[{e.relationship}]--> {e.target_node}")
