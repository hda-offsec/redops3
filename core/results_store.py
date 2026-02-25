import json
import os
import threading
from datetime import datetime

# Simple JSON-based results store to keep things persistent but simple
# In a larger app, this would be purely fully relational DB

RESULTS_DIR = "data/results"
_results_locks = {}
_locks_lock = threading.Lock()

def get_scan_lock(scan_id):
    with _locks_lock:
        if scan_id not in _results_locks:
            _results_locks[scan_id] = threading.Lock()
        return _results_locks[scan_id]

def deep_merge(dict1, dict2):
    """Recursively merges dict2 into dict1 NON-DESTRUCTIVELY."""
    for key, value in dict2.items():
        if key in dict1:
            if isinstance(dict1[key], dict) and isinstance(value, dict):
                deep_merge(dict1[key], value)
            elif isinstance(dict1[key], list) and isinstance(value, list):
                if value:
                    for item in value:
                        if item not in dict1[key]:
                            dict1[key].append(item)
            else:
                if not value and dict1[key] and type(value) == type(dict1[key]):
                    continue
                dict1[key] = value
        else:
            dict1[key] = value
    return dict1

def save_results(scan_id, data, overwrite=False):
    lock = get_scan_lock(scan_id)
    with lock:
        if not os.path.exists(RESULTS_DIR):
            os.makedirs(RESULTS_DIR)
            
        filename = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
        
        # Load existing data to merge if not overwriting
        current_data = {}
        if not overwrite and os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    current_data = json.load(f)
            except Exception:
                current_data = {}

        # Merge new data into current (or just use new data if overwriting)
        if overwrite:
            updated_data = data
        else:
            updated_data = deep_merge(current_data, data)
        
        temp_filename = f"{filename}.{threading.get_ident()}.tmp"
        try:
            # Atomic write: write to temp file first, then rename
            with open(temp_filename, 'w') as f:
                json.dump(updated_data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            
            # Atomic rename (overwrites existing file)
            os.replace(temp_filename, filename)
            return updated_data
            # print(f"[DEBUG] Results saved for Scan #{scan_id} ({'overwritten' if overwrite else 'merged'})")
        except Exception as e:
            print(f"[ERROR] Failed to save results for Scan #{scan_id}: {e}")
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

def load_results(scan_id):
    lock = get_scan_lock(scan_id)
    with lock:
        filename = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                print(f"[WARN] Corrupted JSON for Scan #{scan_id}: {e}. Returning empty structure.")
                return {"scan_id": scan_id, "status": "running", "phases": {}}
            except Exception as e:
                print(f"[ERROR] Failed to load results for Scan #{scan_id}: {e}")
                return None
        return None

def delete_results(scan_id):
    lock = get_scan_lock(scan_id)
    with lock:
        filename = os.path.join(RESULTS_DIR, f"scan_{scan_id}.json")
        if os.path.exists(filename):
            try:
                os.remove(filename)
                print(f"[DEBUG] Deleted results for Scan #{scan_id}")
                return True
            except Exception as e:
                print(f"[ERROR] Failed to delete results for Scan #{scan_id}: {e}")
        return False
