## Findings data flow guardrails

Critical runtime/reporting paths currently rely on the same normalized finding shape flowing through four layers:

1. `scan_engine/helpers/finding_schema.py::normalize_finding_shape`
   - Canonicalizes severity/confidence/result state.
   - Preserves additive lineage in `metadata.field_sources`, `signal_ids`, `score_factors`, and reproducibility/validation blocks.
2. `ui/web/static/js/findings_contract.js` and `ui/web/static/js/scan_dashboard.js`
   - Recompute `_ui` display helpers from the normalized finding without mutating the stored payload.
   - Runtime ingestion should ignore malformed array entries rather than crashing live updates.
3. `core/mission_intelligence.py`
   - Serializes findings for mission payloads.
   - Derives objective actions only from explicit supporting findings or deterministic category matches.
   - Derives cross-asset paths only when shared lineage exists across multiple findings.
4. `core/quality_metrics.py`
   - Measures both `metadata.field_sources` coverage and `signal_ids` lineage coverage without removing existing keys.

When changing one layer, verify the others still agree on:

- `tool` / `tool_source` / `module`
- `result_state` and validation status
- reproducibility command/URL selection
- `signal_ids` and `metadata.field_sources` preservation
- deterministic ordering for derived mission payloads and metrics
