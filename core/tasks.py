from core.celery_app import celery
from core.extensions import db
from core.models import Scan, ScanLog, Finding, Suggestion, Loot, Target
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
        
        # Concurrency protection
        if scan.status == 'running':
            print(f"[WARN] Scan {scan_id} is already marked as running. Skipping redundant execution.")
            return "Scan already running"
        
        scan.status = 'running'
        db.session.commit()
        scan.status = 'running'
        db.session.commit()
        
        # --- CLEANUP STALE DATA (Smart Mode) ---
        try:
            print(f"DEBUG: Running SMART cleanup for scan_id={scan_id} target={scan.target.identifier}...")
            
            # WIPE Logs and Suggestions to ensure clean timeline
            num_logs = ScanLog.query.filter_by(scan_id=scan_id).delete()
            num_suggestions = Suggestion.query.filter_by(scan_id=scan_id).delete()
            
            # SMART FILTER Findings
            findings_to_delete = []
            for f in Finding.query.filter_by(scan_id=scan_id).all():
                # If target strictly not in title/desc, mark for deletion
                # (Simple heuristic; can be improved if target has alias)
                if scan.target.identifier not in f.title and (not f.description or scan.target.identifier not in f.description):
                    findings_to_delete.append(f.id)
            
            if findings_to_delete:
                Finding.query.filter(Finding.id.in_(findings_to_delete)).delete(synchronize_session=False)

            # SMART FILTER Loot
            loot_to_delete = []
            for l in Loot.query.filter_by(scan_id=scan_id).all():
                # Keep if content or context mentions target
                content_match = scan.target.identifier in l.content
                context_match = l.context and scan.target.identifier in l.context
                if not (content_match or context_match):
                    loot_to_delete.append(l.id)
            
            if loot_to_delete:
                Loot.query.filter(Loot.id.in_(loot_to_delete)).delete(synchronize_session=False)

            db.session.commit()
            print(f"DEBUG: Cleanup Report - Logs: {num_logs}, Sugg: {num_suggestions}, Findings: {len(findings_to_delete)}, Loot: {len(loot_to_delete)}")
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: Failed to cleanup stale data: {e}")
        # --------------------------

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

                # Emit to specific scan room for UI updates (Flattened format for JS)
                socketio.emit('new_finding', {
                    'scan_id': scan_id,
                    'severity': severity,
                    'title': title,
                    'description': kwargs.get('description'),
                    'tool': kwargs.get('tool_source', 'orchestrator'),
                    'screenshot_path': kwargs.get('screenshot_path')
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

        def add_loot_cb(loot_type, content, context=None):
            try:
                from core.models import Loot
                from core.extensions import socketio
                
                # We need the mission_id from the target
                scan_obj = Scan.query.get(scan_id)
                mission_id = scan_obj.target.mission_id if scan_obj.target else None
                
                loot = Loot(
                    mission_id=mission_id,
                    scan_id=scan_id,
                    type=loot_type,
                    content=content,
                    context=context
                )
                db.session.add(loot)
                db.session.commit()
                
                if socketio:
                    socketio.emit("new_loot", {
                        "scan_id": scan_id,
                        "type": loot_type,
                        "content": content[:50] + "..." if len(content) > 50 else content,
                        "context": context
                    }, room=f"scan_{scan_id}")
                return loot
            except Exception as e:
                db.session.rollback()
                print(f"Loot Save Error: {e}")
                return None

        def add_suggestion_cb(**kwargs):
            try:
                from core.extensions import socketio
                if 'scan_id' not in kwargs: kwargs['scan_id'] = scan_id
                s = Suggestion(**kwargs)
                db.session.add(s)
                db.session.commit()

                # Emit to specific scan room for UI updates (Flattened format for JS)
                socketio.emit('new_suggestion', {
                    'scan_id': scan_id,
                    'tool_name': kwargs.get('tool_name'),
                    'command': kwargs.get('command_suggestion'),
                    'reason': kwargs.get('reason')
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

        def recurse_scan_cb(subdomains, parent_scan_id, current_depth, max_depth):
            if current_depth >= max_depth:
                _log_and_emit(parent_scan_id, f"Max recursion depth ({max_depth}) reached. Stopping recursion.", "WARN")
                return

            _log_and_emit(parent_scan_id, f"Recursion: Processing {len(subdomains)} subdomains for depth {current_depth + 1}...", "INFO")
            
            try:
                # Get Parent Scan Context
                parent_scan = Scan.query.get(parent_scan_id)
                if not parent_scan: return

                mission_id = parent_scan.target.mission_id
                
                triggered_count = 0
                for sub in subdomains:
                    # Clean/Validate subdomain string if needed
                    sub = sub.strip()
                    if not sub: continue

                    # Check/Create Target
                    target = Target.query.filter_by(identifier=sub, mission_id=mission_id).first()
                    if not target:
                        target = Target(identifier=sub, mission_id=mission_id)
                        db.session.add(target)
                        db.session.commit()
                    
                    # Create Child Scan
                    # Inherit options but Increment depth
                    new_options = scan_options.copy()
                    new_options['current_recursion_depth'] = current_depth + 1
                    
                    new_scan = Scan(
                        target_id=target.id,
                        scan_type=parent_scan.scan_type,
                        status='pending',
                        params=json.dumps(new_options),
                        parent_scan_id=parent_scan_id
                    )
                    db.session.add(new_scan)
                    db.session.commit()
                    
                    # Trigger Celery Task
                    # Use self.delay() to queue the task
                    self.delay(new_scan.id, sub, parent_scan.scan_type)
                    triggered_count += 1
                
                _log_and_emit(parent_scan_id, f"Recursion: Triggered {triggered_count} child scans.", "SUCCESS")
            
            except Exception as e:
                db.session.rollback()
                _log_and_emit(parent_scan_id, f"Recursion Error: {e}", "ERROR")

        import json
        scan_options = json.loads(scan.params) if scan.params else {}

        print(f"DEBUG TASK: scan_id={scan_id} db_target={scan.target.identifier} arg_target={target_identifier}")

        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            target=scan.target.identifier, # Force use of DB source of truth
            logger_func=lambda msg, lvl: _log_and_emit(scan_id, msg, lvl),
            finding_func=add_finding_cb,
            suggestion_func=add_suggestion_cb,
            results_func=results_update_cb,
            loot_func=add_loot_cb,
            recursion_func=recurse_scan_cb,
            options=scan_options
        )
        
        try:
            # Force use of DB source of truth for scan_type as well
            scan_profile = scan.scan_type # Cache this
            success = orchestrator.run_pipeline(profile=scan_profile)
            
            # Re-fetch scan logic to avoid ObjectDeletedError / Stale Session
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'completed' if success else 'failed'
                scan.end_time = datetime.utcnow()
                db.session.commit()
        except Exception as e:
            _log_and_emit(scan_id, f"Pipeline Error: {str(e)}", "ERROR")
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'failed'
                db.session.commit()
        
        return "Scan Finished"
