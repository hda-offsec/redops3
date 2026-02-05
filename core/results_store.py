import json
import os
from datetime import datetime

# Simple JSON-based results store to keep things persistent but simple
# In a larger app, this would be purely fully relational DB

RESULTS_DIR = "data/results"

def save_results(scan_id, data):
    filename = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def load_results(scan_id):
    filename = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return None
