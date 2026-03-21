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
