from app import create_app
from core.models import Scan, KnowledgeNode, KnowledgeEdge

app = create_app()
with app.app_context():
    print("--- SCANS ---")
    scans = Scan.query.all()
    for s in scans:
        findings_count = len(s.findings)
        print(f"ID: {s.id}, Target: {s.target}, Status: {s.status}, Findings: {findings_count}")
    
    print("\n--- GRAPH DATA COUNT ---")
    nodes_count = KnowledgeNode.query.count()
    edges_count = KnowledgeEdge.query.count()
    print(f"Total Nodes: {nodes_count}")
    print(f"Total Edges: {edges_count}")

    if nodes_count > 0:
        print("\nNodes scan_id distribution:")
        from sqlalchemy import func
        from core.extensions import db
        counts = db.session.query(KnowledgeNode.scan_id, func.count(KnowledgeNode.id)).group_by(KnowledgeNode.scan_id).all()
        for sid, count in counts:
            print(f"  Scan ID {sid}: {count} nodes")
