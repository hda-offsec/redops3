import json
import os


def _results_dir():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "results"))
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def results_path(scan_id):
    return os.path.join(_results_dir(), f"scan_{scan_id}.json")


def save_results(scan_id, data):
    path = results_path(scan_id)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=True)
    return path


def load_results(scan_id):
    path = results_path(scan_id)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
