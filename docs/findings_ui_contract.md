# Findings UI Contract

`core/findings_ui_contract.py` and `ui/web/static/js/findings_contract.js` are mirrored implementations of the same Findings UI contract.

## Canonical `_ui` fields

The backend and frontend must keep this exact field set aligned:

- `validationStatus`
- `resultState`
- `primaryCommand`
- `primaryUrl`
- `provider`
- `component`
- `version`
- `portState`
- `hasEvidence`
- `isValidated`
- `searchText`

## Invariants

- Primary command priority:
  `metadata.validation.command` -> `metadata.reproducibility.command` -> `repro_command` -> controlled legacy `reproduction` only when explicitly command-like.
- Primary URL priority:
  `metadata.validation.target` -> `metadata.reproducibility.url` -> `endpoint` -> `target`.
- `isValidated` is true when `validationStatus == "success"` or `resultState in {"validation", "confirmed"}`.
- `searchText` is a stable, lowercase, deduplicated token list built in this order:
  `title`, `tool_source`, `tool`, `source`, `category`, `primary_url`, `target`, `provider`, `component`, `version`, `validation_status`, `result_state`, `validated_token`, `parameter`, `port_state`.

## JS split

- `RedOpsFindings.contract`: pure normalization, canonicalization, search, and matching helpers.
- `RedOpsFindings.dom`: DOM adapters for row datasets and table filter UI.
- The legacy flat exports remain available for compatibility with existing templates and dashboard code.
- Historical root helpers kept stable: `RedOpsFindings.normalizeFindingRecord(...)`, `RedOpsFindings.applyTableFilters(...)`, `RedOpsFindings.applyRowDataset(...)`.

## Detail And Reporting Contract

- `build_finding_detail_contract(...)` and `RedOpsFindings.contract.buildFindingDetailState(...)` mirror the richer findings detail semantics used by the drawer and reporting exports.
- The shared detail model preserves, when present: operational summary, technical context, target, observed versions, command blocks, validation guidance, evidence blocks, interpretation, remediation, references, and artifacts.
- The canonical detail field order is fixed by `DETAIL_CONTRACT_FIELDS` / `detailStateFields`; backend and frontend must keep that list aligned.
- Block deduplication is semantic, not value-only: two blocks with different `key` values must both survive even when their serialized payload is identical.
- `prepare_report_findings(...)` must keep using that shared detail contract so HTML/PDF exports do not become poorer than the interactive drawer.
- `evidenceBlocks` remains the canonical ordered collection for proof-oriented rendering, including the `raw_output` block when present. `rawOutput` stays as a convenience mirror for direct access and must not diverge from that underlying raw output content.
- Exported API endpoint rows must default to `Unverified` when no real status is available. They must not fall back to synthetic `200`.
