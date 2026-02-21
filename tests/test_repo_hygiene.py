import os
import pytest
import re

# forbidden file paths (relative to project root)
FORBIDDEN_PATHS = [
    "nohup.out",
    "data/celery.log",
    "data/app.log",
]

# forbidden patterns in the tree
FORBIDDEN_GLOBS = [
    r".*\.out$",
    r".*\.tmp$",
    r"walkthrough_.*\.md$"
]

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCAN_ENGINE_DIR = os.path.join(PROJECT_ROOT, "scan_engine")

def test_forbidden_files_not_present():
    """Checks that no forbidden files (logs, outputs) are in the working tree."""
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Skip some directories
        if any(x in root for x in [".git", "venv", "__pycache__", ".pytest_cache"]):
            continue
            
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, PROJECT_ROOT)
            
            # 1. Check direct forbidden paths
            assert rel_path not in FORBIDDEN_PATHS, f"Forbidden file found: {rel_path}"
            
            # 2. Check glob patterns
            for pattern in FORBIDDEN_GLOBS:
                if re.match(pattern, file):
                    # Exception for docs/repo_hygiene.md or legitimate files if any
                    if file == "repo_hygiene.md": continue
                    assert False, f"Forbidden file pattern match: {rel_path} (matches {pattern})"

def test_no_direct_requests_use_in_scan_engine():
    """
    Ensures that scan_engine modules do not import requests directly,
    forcing the use of our hardened http_client.
    """
    for root, dirs, files in os.walk(SCAN_ENGINE_DIR):
        for file in files:
            if file.endswith(".py") and file != "http_client.py":
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    content = f.read()
                    
                # 1. Check for standard imports
                assert "import requests" not in content, f"Direct 'import requests' found in {file}. Use http_client instead."
                
                # 2. Check for functional calls if they use from requests import ...
                # We specifically look for requests.<method>(
                forbidden_calls = ["requests.get(", "requests.post(", "requests.put(", "requests.delete(", "requests.head(", "requests.options(", "requests.request("]
                for call in forbidden_calls:
                    assert call not in content, f"Direct functional call '{call}' found in {file}. Use http_client instead."

def test_all_requests_have_timeout_in_http_client_use():
    """
    Scans the codebase for http_client use and ensures timeouts are either 
    managed by the wrapper or explicitly passed.
    Note: Our http_client.request wrapper imposes a default timeout if None.
    """
    # This test is more about ensuring the wrapper is used correctly
    # or that any remaining session usage has timeouts.
    for root, dirs, files in os.walk(SCAN_ENGINE_DIR):
        for file in files:
            if file.endswith(".py") and file != "http_client.py":
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    lines = f.readlines()
                
                for i, line in enumerate(lines):
                    # If using a session directly (self.session.get), it must have timeout=
                    if ".session." in line and "(" in line and any(m in line for m in [".get", ".post", ".put", ".delete"]):
                        if "timeout=" not in line:
                            # Check subsequent lines if the call is multiline
                            call_context = "".join(lines[i:i+3])
                            assert "timeout=" in call_context, f"Missing timeout in session call at {file}:{i+1}"

def test_data_directory_structure_only():
    """Checks that data/ results, reports, and loot are empty in the repo."""
    for subdir in ["results", "reports", "loot", "snapshots"]:
        path = os.path.join(PROJECT_ROOT, "data", subdir)
        if os.path.exists(path):
            files = os.listdir(path)
            # Ignore hidden files like .gitkeep
            files = [f for f in files if not f.startswith(".")]
            assert not files, f"Data directory {subdir} should be empty in the repository, found: {files}"
