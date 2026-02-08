from core.celery_app import celery
from core.extensions import db
from core.models import Scan, ScanLog, Finding, Suggestion
from scan_engine.orchestrator import ScanOrchestrator
from core.results_store import save_results
from datetime import datetime
from flask import current_app
import logging

@celery.task(bind=True, name='redops.run_scan')
def run_scan_task(self, scan_id, target_identifier, scan_type):
    # We import create_app inside the task to avoid circular import at module level
    # But even better, we use the app context if we are running in the same process
    # For Celery workers, we need to ensure an app context exists
    from app import create_app
    flask_app = create_app()
    
    with flask_app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return "Scan not found"
        
        scan.status = 'running'
        db.session.commit()
        
        def _log_and_emit(scan_id, msg, level="INFO"):
            try:
                from core.extensions import socketio
                log = ScanLog(scan_id=scan_id, message=msg, level=level)
                db.session.add(log)
                db.session.commit()
                
                # Emit to Socket.IO (Room: scan_<id>)
                socketio.emit('new_log', {
                    'scan_id': scan_id,
                    'message': msg,
                    'level': level,
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }, room=f"scan_{scan_id}")
            except Exception as e:
                db.session.rollback()
                print(f"Log/Emit Error: {e}")
            print(f"[{level}] Scan {scan_id}: {msg}")

        def add_finding_cb(**kwargs):
            try:
                from core.extensions import socketio
                severity = kwargs.get('severity', 'info')
                title = kwargs.get('title', 'Untitled Finding')
                
                finding = Finding(
                    scan_id=scan_id,
                    severity=severity,
                    title=title,
                    description=kwargs.get('description'),
                    tool_source=kwargs.get('tool_source', 'orchestrator'),
                    screenshot_path=kwargs.get('screenshot_path')
                )
                db.session.add(finding)
                db.session.commit()

                # Emit to specific scan room for UI updates
                socketio.emit('new_finding', {
                    'scan_id': scan_id,
                    'finding': {
                        'severity': severity,
                        'title': title,
                        'description': kwargs.get('description'),
                        'screenshot_path': kwargs.get('screenshot_path')
                    }
                }, room=f"scan_{scan_id}")

                # Global Alert for Critical Issues from the worker
                if severity.lower() == 'critical':
                    socketio.emit('global_notification', {
                        'title': '🚨 CRITICAL VULNERABILITY',
                        'message': f'{title} found on scan #{scan_id}',
                        'severity': 'critical'
                    })
            except Exception as e:
                db.session.rollback()
                print(f"Finding Save/Emit Error: {e}")

        def add_suggestion_cb(**kwargs):
            try:
                if 'scan_id' not in kwargs: kwargs['scan_id'] = scan_id
                s = Suggestion(**kwargs)
                db.session.add(s)
                db.session.commit()

                # Emit to specific scan room
                from core.extensions import socketio
                socketio.emit('new_suggestion', {
                    'scan_id': scan_id,
                    'suggestion': {
                        'tool_name': kwargs.get('tool_name'),
                        'command_suggestion': kwargs.get('command_suggestion'),
                        'reason': kwargs.get('reason')
                    }
                }, room=f"scan_{scan_id}")
            except Exception as e:
                db.session.rollback()
                print(f"Suggestion Save Error: {e}")

        def results_update_cb(scan_id, data, **kwargs):
            save_results(scan_id, data, **kwargs)
            try:
                from core.extensions import socketio
                
                # If progress is in data, emit specifically for progress handlers
                if "progress" in data:
                    socketio.emit("progress_update", {
                        "scan_id": scan_id,
                        "percent": data["progress"]["percent"],
                        "current_phase": data["progress"]["current_phase"]
                    }, room=f"scan_{scan_id}")

                socketio.emit('results_update', {
                    'scan_id': scan_id,
                    'results': data
                }, room=f"scan_{scan_id}")
            except Exception as e:
                print(f"Results Emit Error: {e}")

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
