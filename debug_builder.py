import json
from scan_engine.helpers.attack_graph import AttackGraphBuilder

with open("data/results/scan_1.json", "r") as f:
    results = json.load(f)

builder = AttackGraphBuilder()
graph_data = builder.build(results)
print(f"Nodes count: {len(graph_data['nodes'])}")
print(f"Edges count: {len(graph_data['edges'])}")

if not graph_data['nodes']:
    print("\nDebug Phases:")
    print(json.dumps(results.get("phases", {}).get("recon", {}), indent=2))
