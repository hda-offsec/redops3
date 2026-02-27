import os
import sys
import json
from flask import Flask

# Add project root to sys.path
project_root = "/home/doomer/Bureau/redops3"
sys.path.append(project_root)

# Mock Flask app for context
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

from core.reporting import generate_scan_report, load_results
from adapters.detection_adapter import DetectionAdapter

class MockScan:
    def __init__(self, target_id):
        from datetime import datetime
        self.target = type('Target', (), {'identifier': target_id})()
        self.status = "finished"
        self.id = 4
        self.notes = "Debug scan notes"
        self.start_time = datetime.now()
        self.scan_type = "full"

def debug_pdf_repro():
    scan_id = 4
    results = load_results(scan_id)
    scan = MockScan("rvz-location.fr")
    
    # Mimic main.py normalized findings (list of dicts)
    # We'll create some dummy findings to test the loops
    db_findings = [] # Empty mock for simplicity, normalize_findings will pull from JSON if available
    
    normalized_findings = DetectionAdapter.normalize_findings(db_findings, results)
    
    print(f"Total findings: {len(normalized_findings)}")
    print(f"Sample finding type: {type(normalized_findings[0]) if normalized_findings else 'None'}")
    
    try:
        filename = generate_scan_report(scan_id, scan, normalized_findings)
        print(f"Report generated: {filename}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"FAIL: {e}")

if __name__ == "__main__":
    with app.app_context():
        debug_pdf_repro()
