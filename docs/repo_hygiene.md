# RedOps3 Repository Hygiene & Historical Purge

This document outlines the procedures for maintaining a clean repository and purging sensitive data from the Git history. RedOps3 is an offensive security tool, and its operation generates logs, screenshots, and scan results that must **never** be committed to the repository.

## 1. Automated Hygiene

The project now includes a hardened `scan_engine/helpers/http_client.py`. 
- **Rule**: All network requests *must* use `http_client.request()` or `get_session()`.
- **Direct use of `requests` is prohibited** and is checked via automated tests.
- **Timeouts** are mandatory for all requests.

## 2. Sensitive Artifacts

The following patterns are ignored by `.gitignore` and must be purged if they ever leak into the history:
- `nohup.out`, `*.out`, `*.log`, `*.tmp`
- `data/*.sqlite*` (Local Databases)
- `data/results/`, `data/reports/`, `data/loot/`
- `ui/web/static/screenshots/`
- `walkthrough_*.md`

## 3. Historical Purge Procedure (Action Required)

If sensitive data or logs were accidentally committed in the past, follow this procedure to rewrite the history.

### Prerequisites
Install `git-filter-repo` (recommended):
```bash
pip install git-filter-repo
```

### Steps to Purge
Execute these commands from the repository root:

1. **Dry Run (Recommended)**:
   Verify what will be removed.
   
2. **Execute Purge**:
   This command removes common artifacts and logs from the entire history.

```bash
git filter-repo --invert-paths \
  --path nohup.out \
  --path-glob '*.out' \
  --path-glob '*.log' \
  --path-glob '*.tmp' \
  --path-glob 'data/*.db' \
  --path-glob 'data/*.sqlite*' \
  --path data/results/ \
  --path data/reports/ \
  --path data/loot/ \
  --path ui/web/static/screenshots/ \
  --path-glob 'walkthrough_*.md'
```

3. **Force Push**:
   **Warning**: This rewrites history. All contributors must re-clone the repository.
```bash
git push origin main --force
```

4. **Aggressive Garbage Collection**:
```bash
git gc --prune=now --aggressive
```

## 4. Verification

To ensure no sensitive paths remain in the history:
```bash
git log --name-only --all | grep -E "nohup\.out|data/results|screenshots"
```

To check for direct `requests` imports:
```bash
pytest tests/test_repo_hygiene.py
```
