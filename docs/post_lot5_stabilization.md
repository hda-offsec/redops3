# Post-Lot5 Stabilization & Industrialization (Phase 1)

This phase is intentionally additive and focuses on stability/operability, not new offensive feature lots.

## Added internal quality metrics

`core/quality_metrics.py` provides deterministic metrics used by mission intelligence:

- `artifact_volume`: totals for findings/objective paths/next steps/operator actions/objectives.
- `signal_vs_actions`: linked findings versus orphan findings plus action volume.
- `findings_by_family`: coarse family mapping (secrets, upload/retrieval, cloud pivots, schema observations, mutation candidates, auth identity observations, business logic heuristics, JS intelligence).
- `confidence_distribution` and `evidence_confidence_distribution`.
- `validation_profiles`: distribution from finding metadata.
- `lineage_coverage`: presence of `metadata.field_sources`.
- `operator_feedback`: status distribution and false-positive-like ratio (`invalidated` + `skipped`).
- `noisy_heuristics`: low-confidence heuristic families/modules/tools.
- `coverage_hints`: objective coverage from paths and next steps.

## API / payload integration

- Mission intelligence payload now includes `quality_metrics` (additive key).
- New lightweight endpoint:
  - `GET /api/missions/<mission_id>/quality-metrics`

## Compatibility notes

- No existing keys removed from mission intelligence payload.
- No destructive DB migration introduced.
- Metric computations are deterministic and side-effect free.
