from core.celery_app import celery
from core.extensions import db
from core.models import Scan, ScanLog, Finding, Suggestion
from scan_engine.orchestrator import ScanOrchestrator
from core.results_store import save_results
from datetime import datetime
import logging

# This is needed to access models and DB within Celery workers
from app import create_app
app = create_app()

@celery.task(bind=True, name='redops.run_scan')
def run_scan_task(self, scan_id, target_identifier, scan_type):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return "Scan not found"
        
        scan.status = 'running'
        db.session.commit()
        
        def _log_and_emit(scan_id, msg, level="INFO"):
            log = ScanLog(scan_id=scan_id, message=msg, level=level)
            db.session.add(log)
            db.session.commit()
            # Note: SocketIO emit from worker requires a message queue like Redis
            # We will implement this in the next step
            print(f"[{level}] Scan {scan_id}: {msg}")

        def add_finding_cb(**kwargs):
            finding = Finding(
                scan_id=scan_id,
                severity=kwargs.get('severity', 'info'),
                title=kwargs.get('title', 'Untitled Finding'),
                description=kwargs.get('description'),
                tool_source=kwargs.get('tool_source', 'orchestrator'),
                screenshot_path=kwargs.get('screenshot_path')
            )
            db.session.add(finding)
            db.session.commit()

        def add_suggestion_cb(**kwargs):
            if 'scan_id' not in kwargs: kwargs['scan_id'] = scan_id
            s = Suggestion(**kwargs)
            db.session.add(s)
            db.session.commit()

        def results_update_cb(scan_id, data):
            save_results(scan_id, data)

        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            target=target_identifier,
            logger_func=lambda msg, lvl: _log_and_emit(scan_id, msg, lvl),
            finding_func=add_finding_cb,
            suggestion_func=add_suggestion_cb,
            results_func=results_update_cb
        )
        
        try:
            success = orchestrator.run_pipeline(profile=scan_type)
            scan.status = 'completed' if success else 'failed'
        except Exception as e:
            _log_and_emit(scan_id, f"Pipeline Error: {str(e)}", "ERROR")
            scan.status = 'failed'
        
        scan.end_time = datetime.utcnow()
        db.session.commit()
        return scan.status
