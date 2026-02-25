# UI Data Integrity & Extension Guide (RedOps3)

## The RedOps3 "Attack Intelligence Interface"
The UI revolves around a strict **Mission-Centric Layout** designed to present the highest impact evidence efficiently without "hallucinating" data.

### Strict Anti-Hallucination Policy
- **No computed logic in templates:** If the backend model or dictionary doesn't provide a count/score, do not invent one in Jinja or JS. Show "N/A".
- **Evidence-backed Detections:** Findings displayed in Tab 3 ("FindingsVault") rely strictly on DB-persisted `request`, `response`, and `repro_command`.
- **Graph Inferences:** Tab 4 ("Attack Graph") explicitly alerts the user that edges (relationships) are *visually inferred* unless the backend explicitly stores a true Directed Acyclic Graph (DAG). Do not draw connections invisibly without a disclaimer.

### Expanding the UI
If you need to add a new Scanner or UI visualization, follow these constraints:
1. **Never alter the backend execution:** The pipeline (`enum.py`, `vuln.py`, Celestia Tasks) should remain totally ignorant of UI updates.
2. **Update the `results` JSON contract:** Provide your scanner's parsed JSON output into `results_store.py`.
3. **Map it to Attack Surface (Tab 2):** Add it to the Javascript extraction logic in `scan_partials/interface/attack_surface.html` using the Unified Schema (`type: asset|endpoint|param|leak`, `value: str`, `source: scanner_name`, `raw: object`).
4. **Findings Lifecycle:** New findings mapped in the DB (`Finding` model) automatically appear in Tab 3 ("Findings"). Ensure you provide a Human Readable `title` and populate `tool_source` properly.

### Tabs Structure
1. `mission_overview.html` - Executive dashboard and target health.
2. `attack_surface.html` - Unified data explorer (JS Driven).
3. `findings.html` - Safe listing of findings with interactive Detail Drawers.
4. `attack_graph.html` - Vis.js powered relationship explorer.
5. `report_builder.html` - API gateway to trigger PDF creation.
6. `under_the_hood.html` - Logs, Engine State, and Integrity validations.
