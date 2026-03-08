# AGENTS.md — RedOps3 Stabilization Guardrails

## Scope & architecture (real repo)
- Flask app entrypoint: `app.py` (`create_app`, runtime SQLite additive migrations).
- Core data models: `core/models.py` (`findings`, `signals`, `replay_vault_entries`, `auth_identity_maps`, `operator_actions`, mission entities).
- Mission intelligence and operator action synthesis: `core/mission_intelligence.py`.
- Canonical finding normalization and lineage metadata: `scan_engine/helpers/finding_schema.py`.
- Replay/auth identity normalization and diffing: `core/replay_vault.py`.
- Web/API routes: `ui/web/views/main.py`.

## Post-Lot5 additive rules
1. **No destructive migration**: SQLite runtime changes must remain `ADD COLUMN`/`CREATE TABLE IF NOT EXISTS`/`CREATE INDEX IF NOT EXISTS` only.
2. **No contract break**: existing JSON keys must remain backward compatible; additive keys only.
3. **Determinism first**: no random ordering in payloads; sort keys/lists when aggregating metrics.
4. **Lineage preservation**: do not drop/overwrite `metadata.field_sources`, `score_factors`, `signal_ids`, `provenance`.
5. **Observation vs actionability**:
   - Observation: replay/auth/schema/object facts without exploit claim.
   - Correlation/heuristic: inferred relationships and probable paths.
   - Validation: explicit safe-check guidance/profile.
   - Confidence/priority: scoring outputs, not proof of exploitability.

## Testing expectations
- Prefer targeted unit tests for:
  - finding/replay serialization contracts,
  - deterministic outputs,
  - additive mission/metrics payloads,
  - empty/malformed input handling.
- Report validation honestly (what ran vs not run).

## Codex change style
- Keep changes localized and additive.
- Do not run broad speculative refactors.
- If expected component is missing, document the gap and adapt instead of inventing files/routes/models.
- PR summaries must list executed commands and concrete limits.
