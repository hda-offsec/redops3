import sys
import os
from datetime import datetime

# Ensure project root is in path
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

from app import create_app
from core.extensions import db, socketio
from core.models import Finding

def emit_test_finding(scan_id):
    app = create_app()
    with app.app_context():
        title = f"Live Test Finding - {datetime.now().strftime('%H:%M:%S')}"
        finding = Finding(
            scan_id=scan_id,
            severity='high',
            confidence='high',
            title=title,
            tool_source='manual_test',
            module='manual_test',
            category='live_update_test',
            description='This finding was emitted via a test script to verify UI live updates.',
            endpoint='http://test.local/live',
            id_stable=f"test_live_{datetime.now().timestamp()}"
        )
        db.session.add(finding)
        db.session.commit()
        
        socketio.emit('new_finding', {
            'scan_id': scan_id,
            'id': finding.id,
            'id_stable': finding.id_stable,
            'severity': 'high',
            'confidence': 'high',
            'title': title,
            'description': finding.description,
            'tool': 'manual_test',
            'module': 'manual_test',
            'category': 'live_update_test',
            'endpoint': finding.endpoint,
            'created_at': datetime.now().isoformat()
        }, room=f"scan_{scan_id}")
        
        print(f"Emitted high finding to scan_{scan_id}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        emit_test_finding(int(sys.argv[1]))
    else:
        print("Usage: python emit_test_finding.py <scan_id>")
