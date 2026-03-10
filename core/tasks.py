import sys
import os

# Ensure the project root is always in sys.path, even when Celery is launched
# via nohup or from a different working directory.
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from core.celery_app import celery
from core.extensions import db
from core.models import Scan, ScanLog, Finding, Suggestion, Loot, Target, Signal
from scan_engine.orchestrator import ScanOrchestrator
from core.results_store import save_results
from datetime import datetime
from flask import current_app
import logging

logger = logging.getLogger(__name__)

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
            
            # Preserve findings/signals for detection entropy control (immutable history).
            findings_to_delete = []

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

        def add_signal_cb(**kwargs):
            try:
                signal = Signal(
                    scan_id=scan_id,
                    tool=kwargs.get("tool", "orchestrator"),
                    module=kwargs.get("module"),
                    type=kwargs.get("type", "finding"),
                    target=kwargs.get("target"),
                    endpoint=kwargs.get("endpoint"),
                    parameter=kwargs.get("parameter"),
                    payload=kwargs.get("payload"),
                    status_code=kwargs.get("status_code") if isinstance(kwargs.get("status_code"), int) else None,
                    response_headers_json=kwargs.get("response_headers") if isinstance(kwargs.get("response_headers"), dict) else None,
                    response_evidence=kwargs.get("response_evidence"),
                    raw_output=kwargs.get("raw_output"),
                    metadata_json=kwargs.get("metadata") if isinstance(kwargs.get("metadata"), dict) else {"raw_metadata": kwargs.get("metadata")} if kwargs.get("metadata") else None
                )
                db.session.add(signal)
                db.session.commit()
                return signal
            except Exception as e:
                db.session.rollback()
                print(f"Signal Save Error: {e}")
                return None

        def add_finding_cb(**kwargs):
            try:
                from core.extensions import socketio
                from core.utils import sanitize_evidence, cap_text
                import json
                
                severity = kwargs.get('severity', 'info')
                title = kwargs.get('title', 'Untitled Finding')
                
                # P0 Hardening: Sanitize and Cap Evidence
                raw_request = kwargs.get('request')
                raw_response = kwargs.get('response')
                raw_repro = kwargs.get('repro_command')

                cleaned_request = cap_text(sanitize_evidence(raw_request))
                cleaned_response = cap_text(sanitize_evidence(raw_response))
                cleaned_repro = cap_text(sanitize_evidence(raw_repro))
                cleaned_reproduction = cap_text(sanitize_evidence(kwargs.get('reproduction') or cleaned_repro))

                evidence_value = kwargs.get('evidence')
                if isinstance(evidence_value, (dict, list)):
                    evidence_value = cap_text(sanitize_evidence(json.dumps(evidence_value, default=str)))
                elif isinstance(evidence_value, str):
                    evidence_value = cap_text(sanitize_evidence(evidence_value))
                else:
                    evidence_value = cap_text(sanitize_evidence(kwargs.get('description')))

                id_stable = kwargs.get('id_stable')
                if not id_stable:
                    import hashlib
                    from urllib.parse import urlparse
                    
                    endpoint_seed = str(kwargs.get('endpoint') or kwargs.get('target') or kwargs.get('url') or '')
                    try:
                        parsed = urlparse(endpoint_seed)
                        # Normalize Host: ignore standard ports and scheme
                        host = parsed.hostname or parsed.netloc.split(':')[0]
                        endpoint_norm = f"{host}{parsed.path}?{parsed.query}"
                    except Exception:
                        endpoint_norm = endpoint_seed

                    id_str = "|".join([
                        str(title),
                        str(endpoint_norm),
                        str(kwargs.get('parameter') or kwargs.get('param') or ''),
                        str(kwargs.get('payload') or kwargs.get('poison') or ''),
                        str(kwargs.get('severity', 'info')),
                        str(kwargs.get('tool_source', kwargs.get('tool', 'orchestrator'))),
                    ])
                    id_stable = hashlib.sha256(id_str.encode()).hexdigest()

                # Deduplication Check: avoid duplicate findings in the same scan
                existing = Finding.query.filter_by(scan_id=scan_id, id_stable=id_stable).first()
                if existing:
                    # Update potentially mission-critical fields if the new finding is on HTTPS while old was HTTP
                    current_url = kwargs.get('target') or kwargs.get('url') or ""
                    if current_url.startswith('https://') and not str(existing.target).startswith('https://'):
                        existing.target = current_url
                        existing.endpoint = kwargs.get('endpoint') or current_url
                        db.session.commit()
                    return

                finding = Finding(
                    scan_id=scan_id,
                    severity=severity,
                    confidence=kwargs.get('confidence', 'medium'),
                    signal_ids=kwargs.get('signal_ids') if isinstance(kwargs.get('signal_ids'), list) else None,
                    target=kwargs.get('target') or kwargs.get('url'),
                    tool=kwargs.get('tool') or kwargs.get('tool_source', 'orchestrator'),
                    module=kwargs.get('module') or kwargs.get('tool_source', 'orchestrator'),
                    category=kwargs.get('category'),
                    id_stable=id_stable,
                    title=title,
                    description=kwargs.get('description'),
                    tool_source=kwargs.get('tool_source', 'orchestrator'),
                    endpoint=kwargs.get('endpoint') or kwargs.get('target') or kwargs.get('url'),
                    parameter=kwargs.get('parameter') or kwargs.get('param'),
                    payload=kwargs.get('payload') or kwargs.get('poison'),
                    evidence=evidence_value,
                    reproduction=cleaned_reproduction,
                    raw_output=cap_text(sanitize_evidence(kwargs.get('raw_output') or kwargs.get('response'))),
                    metadata_json=kwargs.get('metadata') if isinstance(kwargs.get('metadata'), dict) else None,
                    screenshot_path=kwargs.get('screenshot_path'),
                    request=cleaned_request,
                    response=cleaned_response,
                    repro_command=cleaned_repro
                )
                db.session.add(finding)
                db.session.commit()

                # Emit to specific scan room for UI updates (Flattened format for JS)
                socketio.emit('new_finding', {
                    'scan_id': scan_id,
                    'id': finding.id,
                    'id_stable': finding.id_stable,
                    'severity': severity,
                    'confidence': kwargs.get('confidence', 'medium'),
                    'title': title,
                    'description': kwargs.get('description'),
                    'tool': kwargs.get('tool_source', 'orchestrator'),
                    'module': kwargs.get('module') or kwargs.get('tool_source', 'orchestrator'),
                    'category': kwargs.get('category'),
                    'target': kwargs.get('target') or kwargs.get('url'),
                    'endpoint': kwargs.get('endpoint') or kwargs.get('target') or kwargs.get('url'),
                    'parameter': kwargs.get('parameter') or kwargs.get('param'),
                    'payload': kwargs.get('payload') or kwargs.get('poison'),
                    'evidence': evidence_value,
                    'reproduction': cleaned_reproduction,
                    'screenshot_path': kwargs.get('screenshot_path'),
                    'signal_ids': kwargs.get('signal_ids', []),
                    'request': cleaned_request,
                    'response': cleaned_response,
                    'repro_command': cleaned_repro
                }, room=f"scan_{scan_id}")

                logger.info(
                    "finding_created",
                    extra={
                        "scanner_name": kwargs.get('tool_source', 'orchestrator'),
                        "target": kwargs.get('target') or kwargs.get('url') or target_identifier,
                        "finding_type": kwargs.get('category', 'general'),
                        "severity": severity,
                        "confidence": kwargs.get('confidence', 'medium')
                    }
                )

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
            full_data = save_results(scan_id, data, **kwargs) or data
            try:
                from core.extensions import socketio
                
                # If progress is in data, emit specifically for progress handlers
                if "progress" in data:
                    progress_data = data["progress"]
                    if isinstance(progress_data, dict):
                        percent = progress_data.get("percent", 0)
                        phase = progress_data.get("current_phase", "Processing")
                    else:
                        percent = progress_data
                        phase = "Executing Tasks"
                        
                    socketio.emit("progress_update", {
                        "scan_id": scan_id,
                        "percent": percent,
                        "current_phase": phase
                    }, room=f"scan_{scan_id}")

                socketio.emit('results_update', {
                    'scan_id': scan_id,
                    'results': full_data
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

        def persist_graph_cb(nodes, edges):
            try:
                from core.models import KnowledgeEdge, KnowledgeNode
                from core.extensions import socketio
                
                # Clear existing graph data for this scan to avoid duplicates
                KnowledgeEdge.query.filter_by(scan_id=scan_id).delete()
                KnowledgeNode.query.filter_by(scan_id=scan_id).delete()
                
                for node in nodes:
                    kn = KnowledgeNode(
                        scan_id=scan_id,
                        node_id=node.get('id'),
                        type=node.get('type'),
                        label=node.get('label'),
                        metadata_json=node.get('data')
                    )
                    db.session.add(kn)
                
                for edge in edges:
                    ke = KnowledgeEdge(
                        scan_id=scan_id,
                        source_node=edge.get('from'),
                        target_node=edge.get('to'),
                        relationship=edge.get('type'),
                        metadata_json=edge.get('data')
                    )
                    db.session.add(ke)
                
                db.session.commit()
                _log_and_emit(scan_id, f"Attack graph synchronized: {len(nodes)} nodes, {len(edges)} edges persisted.", "SUCCESS")
                
                # Notify UI to refresh graph
                if socketio:
                    socketio.emit("graph_updated", {"scan_id": scan_id}, room=f"scan_{scan_id}")
            except Exception as e:
                print(f"[ERROR] Failed to persist graph in task: {e}")
                db.session.rollback()

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
            graph_func=persist_graph_cb,
            recursion_func=recurse_scan_cb,
            options=scan_options,
            signal_func=add_signal_cb
        )
        
        try:
            # Force use of DB source of truth for scan_type as well
            scan_profile = scan.scan_type # Cache this
            success = orchestrator.run_pipeline(profile=scan_profile)

            all_synth_findings = []
            try:
                from scan_engine.helpers.passive_intel_engine import PassiveIntelligenceEngine
                passive_findings = PassiveIntelligenceEngine.derive_findings(orchestrator.results, scan.target.identifier)
                for pf in passive_findings:
                    add_finding_cb(**pf)
                all_synth_findings.extend(passive_findings)
                if passive_findings:
                    _log_and_emit(scan_id, f"Passive intelligence synthesized {len(passive_findings)} findings from existing telemetry.", "INFO")
            except Exception as p_err:
                _log_and_emit(scan_id, f"Passive intelligence skipped: {p_err}", "WARN")

            try:
                from scan_engine.helpers.context_attack_engine import APIIntelligenceEngine
                api_findings, api_inventory = APIIntelligenceEngine.derive_surface(orchestrator.results, scan.target.identifier)
                for af in api_findings:
                    add_finding_cb(**af)
                all_synth_findings.extend(api_findings)
                if api_findings:
                    _log_and_emit(scan_id, f"API intelligence discovered {len(api_findings)} API surface findings.", "INFO")

                api_fuzz_findings = APIIntelligenceEngine.fuzz_surface(api_inventory, options=scan_options)
                for ff in api_fuzz_findings:
                    add_finding_cb(**ff)
                all_synth_findings.extend(api_fuzz_findings)
                if api_fuzz_findings:
                    _log_and_emit(scan_id, f"API fuzzing generated {len(api_fuzz_findings)} high-signal findings.", "INFO")
            except Exception as api_err:
                _log_and_emit(scan_id, f"API intelligence/fuzzing skipped: {api_err}", "WARN")

            try:
                from scan_engine.helpers.context_attack_engine import ExploitValidationEngine
                # Fetch all findings in DB so far to subject them to rigorous validation
                db_findings_list = Finding.query.filter_by(scan_id=scan_id).all()
                validation_candidates = []
                for f in db_findings_list:
                    validation_candidates.append({
                        "id_stable": f.id_stable,
                        "title": f.title,
                        "category": f.category,
                        "severity": f.severity,
                        "endpoint": f.endpoint,
                        "target": f.target,
                        "confidence": f.confidence
                    })
                
                # Merge with synthetic findings
                validation_candidates.extend(all_synth_findings)
                
                validation_findings = ExploitValidationEngine.validate(validation_candidates, options=scan_options)
                for vf in validation_findings:
                    add_finding_cb(**vf)
                if validation_findings:
                    _log_and_emit(scan_id, f"Rigorous Validation: Confirmed & badge-pinned {len(validation_findings)} findings via differential audit.", "SUCCESS")
            except Exception as val_err:
                _log_and_emit(scan_id, f"Exploit validation skipped: {val_err}", "WARN")

            try:
                from core.analysis import run_signal_correlation, run_cortex_attack_reasoning
                run_signal_correlation(scan_id, add_finding_cb)
                cortex_created = run_cortex_attack_reasoning(scan_id, add_finding_cb)
                if cortex_created:
                    _log_and_emit(scan_id, f"Cortex reasoning generated {cortex_created} attack path findings.", "INFO")
            except Exception as corr_e:
                _log_and_emit(scan_id, f"Signal correlation/Cortex reasoning skipped: {corr_e}", "WARN")

            try:
                from core.analysis import apply_risk_scores
                from scan_engine.helpers.attack_graph import AttackGraphBuilder

                graph_builder = AttackGraphBuilder(options=scan_options)
                risk_graph_payload = dict(orchestrator.results or {})
                db_findings = Finding.query.filter_by(scan_id=scan_id).all()
                risk_graph_payload["findings"] = [
                    {
                        "id_stable": f.id_stable,
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "category": f.category,
                        "target": f.target,
                        "endpoint": f.endpoint,
                        "parameter": f.parameter,
                        "payload": f.payload,
                        "metadata": f.metadata_json if isinstance(f.metadata_json, dict) else {},
                    }
                    for f in db_findings
                ]
                graph = graph_builder.build(risk_graph_payload)
                scored = apply_risk_scores(scan_id, graph=graph)
                if scored:
                    _log_and_emit(scan_id, f"Risk scoring computed exploitability metadata for {scored} findings.", "INFO")
            except Exception as score_err:
                _log_and_emit(scan_id, f"Risk scoring skipped: {score_err}", "WARN")

            # Re-fetch scan logic to avoid ObjectDeletedError / Stale Session
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'completed' if success else 'failed'
                scan.end_time = datetime.utcnow()
                db.session.commit()

            try:
                from core.correlation import run_attack_chain_correlation
                run_attack_chain_correlation(scan_id)
            except Exception as corr_err:
                logger.warning(f"correlation_failed scan_id={scan_id} err={corr_err}")
        except Exception as e:
            _log_and_emit(scan_id, f"Pipeline Error: {str(e)}", "ERROR")
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = 'failed'
                db.session.commit()
        
        return "Scan Finished"
