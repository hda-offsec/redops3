import json
import os

# Define paths relative to the project root
# This file is in core/, so project root is ../
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_FILE = os.path.join(BASE_DIR, "data", "kb", "red_team_kb.json")
TIPS_FILE = os.path.join(BASE_DIR, "data", "kb", "general_tips.json")


def load_json_data(filepath, default=None):
    """
    Loads JSON data from a file.
    Returns default value if file is missing or invalid.
    """
    if default is None:
        default = {}
    try:
        if not os.path.exists(filepath):
            # Only print if file is genuinely missing to avoid noise
            # But for KB, it's critical, so maybe print is good.
            print(f"Warning: KB file not found at {filepath}")
            return default

        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading KB file {filepath}: {e}")
        return default


RED_TEAM_KB = load_json_data(KB_FILE, {})
GENERAL_TIPS = load_json_data(TIPS_FILE, [])
