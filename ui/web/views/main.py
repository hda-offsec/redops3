from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, jsonify
from flask_login import login_required, current_user
from urllib.parse import urlparse
import os
import json
import shutil
import functools
from datetime import datetime
from sqlalchemy import func
from sqlalchemy.orm import joinedload

from sqlalchemy.orm import joinedload
from core.models import (
    Target,
    Scan,
    Finding,
    Suggestion,
    ScanLog,
    Mission,
    Loot,
    KnowledgeNode,
    KnowledgeEdge,
    Asset,
    AssetTargetLink,
    ReplayVaultEntry,
    AuthIdentityMap,
    db,
)
from sqlalchemy import func
from core.results_store import load_results, save_results, delete_results
from core.reporting import generate_scan_report, generate_html_report
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.helpers.output_parsers import parse_nmap_open_ports
from scan_engine.orchestrator import ScanOrchestrator
from core.extensions import socketio
from core.tasks import run_scan_task
from core.replay_vault import (
    compare_replay_artifacts,
    extract_auth_identity_observations,
    normalize_replay_artifact,
)
from core.mission_intelligence import (
    MISSION_STATES,
    OBJECTIVE_TYPES,
    ACTION_STATUSES,
    aggregate_mission_intelligence,
    ensure_asset_for_target,
    link_asset_target,
    normalize_mission_status,
    normalize_objective_type,
    update_operator_action_status,
    aggregate_mission_quality_metrics,
)

main_bp = Blueprint("main", __name__)


def _serialize_replay_entry(entry):
    return {
        "id": entry.id,
        "scan_id": entry.scan_id,
        "finding_id": entry.finding_id,
        "mission_id": entry.mission_id,
        "target_id": entry.target_id,
        "source": entry.source,
        "method": entry.method,
        "url": entry.url,
        "endpoint": entry.endpoint,
        "query_params": entry.query_params_json or {},
        "request_headers": entry.request_headers_json or {},
        "request_cookies": entry.request_cookies_json or {},
        "request_body_summary": entry.request_body_summary_json or {},
        "status_code": entry.status_code,
        "response_headers": entry.response_headers_json or {},
        "response_body_summary": entry.response_body_summary_json or {},
        "content_type": entry.content_type,
        "redirect_chain": entry.redirect_chain_json or [],
        "identity_context": entry.identity_context_json or {},
        "provenance": entry.provenance_json or {},
        "observed_at": entry.observed_at.isoformat() if entry.observed_at else None,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def _serialize_auth_identity_map(entry):
    return {
        "id": entry.id,
        "replay_id": entry.replay_id,
        "scan_id": entry.scan_id,
        "mission_id": entry.mission_id,
        "target_id": entry.target_id,
        "route": entry.route,
        "route_auth_hints": entry.route_auth_hints_json or [],
        "session_cookie_names": entry.session_cookie_names_json or [],
        "bearer_token_present": bool(entry.bearer_token_present),
        "bearer_token_preview": entry.bearer_token_preview,
        "jwt_like_token": bool(entry.jwt_like_token),
        "response_session_cookie_hint": bool(entry.response_session_cookie_hint),
        "role_scope_claim_hints": entry.role_scope_claim_hints_json or [],
        "observation_only": bool(entry.observation_only),
        "notes": entry.notes,
        "source": entry.source,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@main_bp.route("/terminal")
def terminal():
    return render_template("terminal.html")


@main_bp.route("/test_graph")
def test_graph():
    return render_template("test_graph.html")


@functools.lru_cache(maxsize=16)
def _get_tool_path(tool_name):
    return shutil.which(tool_name)


@functools.lru_cache(maxsize=1)
def _get_tool_status():
    tools = ["nmap", "nuclei", "ffuf", "whatweb", "subfinder", "katana", "sqlmap", "dnsrecon"]
    status = {}
    for t in tools:
        path = _get_tool_path(t)
        status[t] = {
            "found": path is not None,
            "path": path or "Not Found"
        }
    return status


@main_bp.route("/api/dependencies")
def check_dependencies():
    return jsonify(_get_tool_status())


@main_bp.route("/api/scans/<int:scan_id>/findings")
def get_scan_findings(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    limit = min(request.args.get("limit", 200, type=int), 500)
    offset = request.args.get("offset", 0, type=int)
    
    findings_q = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.id.desc())
    total = findings_q.count()
    items = findings_q.limit(limit).offset(offset).all()
    
    return jsonify({
        "scan_id": scan_id,
        "total": total,
        "items": [{
            "exploit_score": (f.metadata_json or {}).get("exploit_score") if isinstance(f.metadata_json, dict) else None,
            "risk_level": (f.metadata_json or {}).get("risk_level") if isinstance(f.metadata_json, dict) else None,
            "attack_priority": (f.metadata_json or {}).get("attack_priority") if isinstance(f.metadata_json, dict) else None,
            "action_priority": (f.metadata_json or {}).get("action_priority") if isinstance(f.metadata_json, dict) else None,
            "action_type": (f.metadata_json or {}).get("action_type") if isinstance(f.metadata_json, dict) else None,
            "estimated_value": (f.metadata_json or {}).get("estimated_value") if isinstance(f.metadata_json, dict) else None,
            "estimated_complexity": (f.metadata_json or {}).get("estimated_complexity") if isinstance(f.metadata_json, dict) else None,
            "provider": (f.metadata_json or {}).get("provider") if isinstance(f.metadata_json, dict) else None,
            "component": (f.metadata_json or {}).get("component") if isinstance(f.metadata_json, dict) else None,
            "version": (f.metadata_json or {}).get("version") if isinstance(f.metadata_json, dict) else None,
            "objective_type": (f.metadata_json or {}).get("objective_type") if isinstance(f.metadata_json, dict) else None,
            "id": f.id,
            "id_stable": f.id_stable,
            "severity": f.severity,
            "confidence": f.confidence,
            "title": f.title,
            "description": f.description,
            "tool": f.tool_source,
            "target": f.target,
            "endpoint": f.endpoint,
            "parameter": f.parameter,
            "payload": f.payload,
            "category": f.category,
            "module": f.module,
            "evidence": f.evidence,
            "reproduction": f.reproduction,
            "raw_output": f.raw_output,
            "metadata": f.metadata_json,
            "signal_ids": f.signal_ids or [],
            "screenshot_path": f.screenshot_path,
            "request": f.request,
            "response": f.response,
            "repro_command": f.repro_command,
            "created_at": f.created_at.isoformat() if f.created_at else None
        } for f in items]
    })


@main_bp.route("/api/scans/<int:scan_id>/graph")
def get_scan_graph(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    nodes = KnowledgeNode.query.filter_by(scan_id=scan_id).all()
    edges = KnowledgeEdge.query.filter_by(scan_id=scan_id).all()
    
    return jsonify({
        "scan_id": scan_id,
        "nodes": [{
            "id": n.node_id,
            "type": n.type,
            "label": n.label,
            "data": n.metadata_json
        } for n in nodes],
        "edges": [{
            "from": e.source_node,
            "to": e.target_node,
            "type": e.relationship,
            "data": e.metadata_json
        } for e in edges]
    })


@main_bp.route("/api/replay-vault", methods=["GET", "POST"])
def replay_vault_collection():
    if request.method == "GET":
        limit = min(request.args.get("limit", 100, type=int), 500)
        offset = request.args.get("offset", 0, type=int)
        scan_id = request.args.get("scan_id", type=int)
        mission_id = request.args.get("mission_id", type=int)

        q = ReplayVaultEntry.query.order_by(ReplayVaultEntry.id.desc())
        if scan_id is not None:
            q = q.filter(ReplayVaultEntry.scan_id == scan_id)
        if mission_id is not None:
            q = q.filter(ReplayVaultEntry.mission_id == mission_id)

        total = q.count()
        items = q.limit(limit).offset(offset).all()
        return jsonify({
            "total": total,
            "items": [_serialize_replay_entry(item) for item in items],
        })

    payload = request.get_json(silent=True) or {}
    normalized = normalize_replay_artifact(payload)
    auth_obs = extract_auth_identity_observations(payload)

    entry = ReplayVaultEntry(
        scan_id=payload.get("scan_id"),
        finding_id=payload.get("finding_id"),
        mission_id=payload.get("mission_id"),
        target_id=payload.get("target_id"),
        source=payload.get("source") or (normalized.get("provenance") or {}).get("source"),
        method=normalized.get("method"),
        url=normalized.get("url"),
        endpoint=normalized.get("endpoint"),
        query_params_json=normalized.get("query_params"),
        request_headers_json=normalized.get("request_headers"),
        request_cookies_json=normalized.get("request_cookies"),
        request_body_summary_json=normalized.get("request_body_summary"),
        status_code=normalized.get("status_code"),
        response_headers_json=normalized.get("response_headers"),
        response_body_summary_json=normalized.get("response_body_summary"),
        content_type=normalized.get("content_type"),
        redirect_chain_json=normalized.get("redirect_chain"),
        identity_context_json=normalized.get("identity_context"),
        provenance_json=normalized.get("provenance"),
        observed_at=normalized.get("observed_at"),
    )
    db.session.add(entry)
    db.session.flush()

    identity_map = AuthIdentityMap(
        replay_id=entry.id,
        scan_id=entry.scan_id,
        mission_id=entry.mission_id,
        target_id=entry.target_id,
        route=entry.endpoint,
        route_auth_hints_json=auth_obs.get("route_auth_hints") or [],
        session_cookie_names_json=auth_obs.get("session_cookie_names") or [],
        bearer_token_present=bool(auth_obs.get("bearer_token_present")),
        bearer_token_preview=auth_obs.get("bearer_token_preview"),
        jwt_like_token=bool(auth_obs.get("jwt_like_token")),
        response_session_cookie_hint=bool(auth_obs.get("response_session_cookie_hint")),
        role_scope_claim_hints_json=auth_obs.get("role_scope_claim_hints") or [],
        observation_only=bool(auth_obs.get("observation_only", True)),
        notes=auth_obs.get("notes"),
        source=entry.source,
    )
    db.session.add(identity_map)
    db.session.commit()

    return jsonify({
        "replay": _serialize_replay_entry(entry),
        "auth_identity": _serialize_auth_identity_map(identity_map),
    }), 201


@main_bp.route("/api/replay-vault/<int:replay_id>", methods=["GET"])
def replay_vault_item(replay_id):
    entry = ReplayVaultEntry.query.get_or_404(replay_id)
    return jsonify(_serialize_replay_entry(entry))


@main_bp.route("/api/replay-vault/<int:left_id>/diff/<int:right_id>", methods=["GET"])
def replay_vault_diff(left_id, right_id):
    left = ReplayVaultEntry.query.get_or_404(left_id)
    right = ReplayVaultEntry.query.get_or_404(right_id)
    diff = compare_replay_artifacts(_serialize_replay_entry(left), _serialize_replay_entry(right))
    return jsonify({
        "left_id": left_id,
        "right_id": right_id,
        "diff": diff,
    })


@main_bp.route("/api/auth-identity-map", methods=["GET"])
def auth_identity_map_collection():
    limit = min(request.args.get("limit", 100, type=int), 500)
    offset = request.args.get("offset", 0, type=int)
    scan_id = request.args.get("scan_id", type=int)
    mission_id = request.args.get("mission_id", type=int)

    q = AuthIdentityMap.query.order_by(AuthIdentityMap.id.desc())
    if scan_id is not None:
        q = q.filter(AuthIdentityMap.scan_id == scan_id)
    if mission_id is not None:
        q = q.filter(AuthIdentityMap.mission_id == mission_id)

    total = q.count()
    items = q.limit(limit).offset(offset).all()
    return jsonify({
        "total": total,
        "items": [_serialize_auth_identity_map(item) for item in items],
    })


@main_bp.route("/")
def index():
    recent_scans = Scan.query.options(joinedload(Scan.target)).order_by(Scan.start_time.desc()).limit(10).all()
    target_count = Target.query.count()
    mission_count = Mission.query.count()
    loot_count = Loot.query.count()
    
    # --- CISO ANALYTICS ---
    severity_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Optimized aggregation using SQL GROUP BY
    results = db.session.query(
        func.lower(func.coalesce(Finding.severity, 'info')),
        func.count(Finding.id)
    ).group_by(
        func.lower(func.coalesce(Finding.severity, 'info'))
    ).all()

    total_findings = 0
    for sev, count in results:
        total_findings += count
        if sev in severity_stats:
            severity_stats[sev] += count
            
    # Scan history trend (last 7 days - simplified)
    # In a real app we'd use group_by(func.date(Scan.start_time))
    
    # Latest Telemetry
    latest_scan = Scan.query.order_by(Scan.start_time.desc()).first()
    recent_logs = (
        ScanLog.query.filter_by(scan_id=latest_scan.id)
        .order_by(ScanLog.id.desc())
        .limit(100)
        .all()
        if latest_scan
        else []
    )

    from core.scan_profiles import SCAN_PROFILES
    return render_template(
        "index.html",
        recent_scans=recent_scans,
        target_count=target_count,
        mission_count=mission_count,
        loot_count=loot_count,
        severity_stats=severity_stats,
        total_findings=total_findings,
        logs=recent_logs,
        scan_profiles=SCAN_PROFILES
    )


from scan_engine.step00_osint.passive_scanner import OSINTTool

@main_bp.route("/scan/<int:scan_id>/osint")
def scan_osint(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    tool = OSINTTool()
    intel = tool.passive_recon(scan.target.identifier)
    return render_template("scans/osint_results.html", scan=scan, intel=intel)

@main_bp.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    results_data = load_results(scan_id) or {}
    
    # Ensure a robust structure for the template
    default_results = {
        "scan_id": scan_id,
        "target": scan.target.identifier,
        "status": scan.status,
        "progress": {"percent": 0, "current_phase": "Initializing"},
        "phases": {
            "recon": {"open_ports": [], "raw_output": ""},
            "dns": {"subdomains": []},
            "intel": {},
            "osint": {
                "cloud": [],
                "favicon": {},
                "github": [],
                "emails": [],
                "dorks": [],
                "origin_ips": []
            },
            "enum": {
                "whatweb": {"summary": {}, "technologies": {}},
                "katana": {},
                "waf": {},
                "arjun": {},
                "js_secrets": {},
                "api": {}
            },
            "vuln": {
                "nuclei": {"findings": []},
                "takeover": [],
                "wpscan": {},
                "wordpress": {},
                "git": [],
                "backups": [],
                "graphql": [],
                "ssrf": [],
                "js_vulns": {},
                "xss": [],
                "redirects": [],
                "tech": {},
                "spring_boot": [],
                "ssti": [],
                "lfi": [],
                "cors_audit": [],
                "crlf": [],
                "firebase": [],
                "xxe": [],
                "deserialization": [],
                "acl_bypass": [],
                "email_security": [],
                "container_exposure": [],
                "websocket": [],
                "data_leaks": [],
                "prototype": []
            },
            "dirbusting": {
                "ffuf": {"endpoints": []}
            }
        }
    }
    
    from core.results_store import deep_merge
    results = deep_merge(default_results, results_data)
    
    # Final safety: Ensure ID and Target always match the current scan record, 
    # even if the loaded JSON file was stale or mismatched.
    results['scan_id'] = scan.id
    results['target'] = scan.target.identifier

    db_findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.id.desc()).all()
    
    from adapters.detection_adapter import DetectionAdapter
    normalized_findings = DetectionAdapter.normalize_findings(db_findings, results)
    
    suggestions = Suggestion.query.filter_by(scan_id=scan_id).order_by(Suggestion.id.desc()).all()
    logs = ScanLog.query.filter_by(scan_id=scan_id).order_by(ScanLog.timestamp.asc()).all()
    loots = Loot.query.filter_by(scan_id=scan_id).all()

    # Serialize findings for JS visualization
    results['findings'] = normalized_findings
    
    # Add metadata for UI persistence
    results['loot_count'] = len(loots)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in normalized_findings:
        sev = (finding.get('severity') or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["info"] += 1

    # Debug: Dump results to a file for review
    try:
        debug_path = os.path.join(current_app.root_path, '..', '..', f'debug_results_{scan_id}.json')
        with open(debug_path, 'w') as f:
            json.dump(results, f, default=str, indent=4)
    except Exception as e:
        print(f"Failed to write debug results: {e}")

    return render_template(
        "scan_detail.html",
        scan=scan,
        results=results,
        findings=normalized_findings,
        suggestions=suggestions,
        logs=logs,
        severity_counts=severity_counts,
        loots=loots
    )

def _normalize_target(value):
    if not value:
        return value
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        if parsed.hostname:
            return parsed.hostname
    return value


def _log_and_emit(scan_id, msg, level="INFO"):
    """
    Logs to database and emits to socket. 
    Wrapped in try/except to avoid crashing the whole pipeline if DB is locked.
    """
    try:
        log = ScanLog(scan_id=scan_id, message=msg, level=level)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        # If DB is locked, we still want the user to see the log via socket if possible
        print(f"[ERROR] DB Log Failed (ID: {scan_id}): {e}")
        db.session.rollback()

    try:
        if socketio:
            socketio.emit(
                "new_log",
                {
                    "message": msg,
                    "level": level,
                    "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
                    "scan_id": scan_id,
                },
                room=f"scan_{scan_id}" if scan_id else None
            )
            # Also broadcast globally for dashboard
            if not scan_id:
                socketio.emit("new_log", {
                    "message": msg,
                    "level": level,
                    "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
                    "scan_id": scan_id,
                })
    except Exception as e:
        print(f"[ERROR] Socket Emit Failed: {e}")



def _add_finding(scan_id, tool, severity, title, description=None, screenshot_path=None, command=None, confidence='medium', request=None, response=None, repro_command=None, id_stable=None):
    from core.utils import sanitize_evidence, cap_text
    
    if command and not repro_command:
        repro_command = command

    # P0 Hardening: Sanitize and Cap Evidence
    cleaned_request = cap_text(sanitize_evidence(request))
    cleaned_response = cap_text(sanitize_evidence(response))
    cleaned_repro = cap_text(sanitize_evidence(repro_command))

    finding = Finding(
        scan_id=scan_id,
        severity=severity,
        confidence=confidence,
        id_stable=id_stable,
        title=title,
        description=description,
        tool_source=tool,
        module=tool,
        category='general',
        evidence=cleaned_response[:1000] if cleaned_response else None,
        reproduction=cleaned_repro,
        raw_output=cleaned_response,
        screenshot_path=screenshot_path,
        request=cleaned_request,
        response=cleaned_response,
        repro_command=cleaned_repro
    )
    db.session.add(finding)
    db.session.commit()
    
    _log_and_emit(scan_id, f"Finding detected: {title}", "WARN")
    
    # Real-time finding emission for the specific scan detail page
    if socketio:
        socketio.emit("new_finding", {
            "scan_id": scan_id,
            "id": finding.id,
            "id_stable": finding.id_stable,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "tool": tool,
            "description": description,
            "module": tool,
            "category": 'general',
            "evidence": cleaned_response[:1000] if cleaned_response else None,
            "reproduction": cleaned_repro,
            "raw_output": cleaned_response,
            "screenshot_path": screenshot_path,
            "request": cleaned_request,
            "response": cleaned_response,
            "repro_command": cleaned_repro
        }, room=f"scan_{scan_id}")

        # Global Alert for Critical Issues
        if severity.lower() == 'critical':
            socketio.emit('global_notification', {
                'title': '🚨 CRITICAL VULNERABILITY',
                'message': f'{title} found on scan #{scan_id}',
                'severity': 'critical'
            })
    
    return finding


def _add_loot(scan_id, loot_type, content, context=None):
    scan = Scan.query.get(scan_id)
    if not scan: return None
    
    loot = Loot(
        mission_id=scan.target.mission_id if scan.target else None,
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
        
        # UI WOW Factor: Global Loot Alert
        socketio.emit('global_notification', {
            'title': '💰 LOOT HARVESTED',
            'message': f'New {loot_type} discovered in scan #{scan_id}',
            'severity': 'success'
        })
    
    return loot


def _add_suggestion(scan_id, tool, command, reason=None):
    suggestion = Suggestion(
        scan_id=scan_id,
        tool_name=tool,
        command_suggestion=command,
        reason=reason,
    )
    db.session.add(suggestion)
    db.session.commit()
    return suggestion


def background_scan(scan_id, target_identifier, scan_type, app):
    from datetime import datetime
    from core.scan_profiles import SCAN_PROFILES
    from core.reclassifier import PostDetectionReclassifier
    
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
             print(f"Scan {scan_id} not found!")
             return
        scan.status = 'running'
        db.session.commit()
        
        _log_and_emit(scan.id, f"Initializing Orchestrated Scan: {scan_type.upper()}", "INFO")

        # -- ORCHESTRATOR SETUP --
        def add_finding_cb(**kwargs):
            try:
                # Use the helper to ensure global notifications and model consistency
                _add_finding(
                    scan_id=scan.id,
                    tool=kwargs.get('tool_source', 'orchestrator'),
                    severity=kwargs.get('severity', 'info'),
                    title=kwargs.get('title', 'Untitled Finding'),
                    description=kwargs.get('description'),
                    screenshot_path=kwargs.get('screenshot_path'),
                    command=kwargs.get('command'),
                    id_stable=kwargs.get('id_stable'),
                    confidence=kwargs.get('confidence', 'medium'),
                    request=kwargs.get('request'),
                    response=kwargs.get('response'),
                    repro_command=kwargs.get('repro_command')
                )
            except Exception as e:
                print(f"[ERROR] Failed to save finding: {e}")
                db.session.rollback()

        def add_suggestion_cb(**kwargs):
            try:
                if 'scan_id' not in kwargs: kwargs['scan_id'] = scan.id
                s = Suggestion(**kwargs)
                db.session.add(s)
                db.session.commit()
                _log_and_emit(scan.id, f"Suggestion: Try {kwargs.get('tool_name')}", "SUCCESS")
                # Real-time suggestion emission
                if socketio:
                    socketio.emit("new_suggestion", {
                        "scan_id": scan.id,
                        "tool_name": s.tool_name,
                        "command": s.command_suggestion
                    })
            except Exception as e:
                print(f"[ERROR] Failed to save suggestion: {e}")
                db.session.rollback()

        def results_update_cb(scan_id, data, **kwargs):
            save_results(scan_id, data, **kwargs)
            # Emit the partial/full results update to the UI
            if socketio:
                # If progress is in data, emit specifically for progress handlers
                if "progress" in data:
                    socketio.emit("progress_update", {
                        "scan_id": scan_id,
                        "percent": data["progress"]["percent"],
                        "current_phase": data["progress"]["current_phase"]
                    }, room=f"scan_{scan_id}")

                socketio.emit("results_update", {
                    "scan_id": scan_id,
                    "results": data
                }, room=f"scan_{scan_id}")

        def add_loot_cb(loot_type, content, context=None):
            return _add_loot(scan.id, loot_type, content, context)

        def persist_graph_cb(nodes, edges):
            try:
                # Clear existing graph data for this scan to avoid duplicates
                KnowledgeEdge.query.filter_by(scan_id=scan.id).delete()
                KnowledgeNode.query.filter_by(scan_id=scan.id).delete()
                
                for node in nodes:
                    kn = KnowledgeNode(
                        scan_id=scan.id,
                        node_id=node.get('id'),
                        type=node.get('type'),
                        label=node.get('label'),
                        metadata_json=node.get('data')
                    )
                    db.session.add(kn)
                
                for edge in edges:
                    ke = KnowledgeEdge(
                        scan_id=scan.id,
                        source_node=edge.get('from'),
                        target_node=edge.get('to'),
                        relationship=edge.get('type'),
                        metadata_json=edge.get('data')
                    )
                    db.session.add(ke)
                
                db.session.commit()
                _log_and_emit(scan.id, f"Attack graph synchronized: {len(nodes)} nodes, {len(edges)} edges persisted.", "SUCCESS")
                
                # Notify UI to refresh graph
                from core.extensions import get_socketio
                sio = get_socketio()
                if sio:
                    sio.emit("graph_updated", {"scan_id": scan.id}, room=f"scan_{scan.id}")
            except Exception as e:
                print(f"[ERROR] Failed to persist graph: {e}")
                db.session.rollback()

        orchestrator = ScanOrchestrator(
            scan_id=scan.id,
            target=target_identifier,
            logger_func=lambda msg, lvl: _log_and_emit(scan.id, msg, lvl),
            finding_func=add_finding_cb,
            suggestion_func=add_suggestion_cb,
            results_func=results_update_cb,
            loot_func=add_loot_cb,
            graph_func=persist_graph_cb
        )
        
        # Execute Pipeline
        try:
             # Look up args from profile dict
             profile_args = None
             
             # Flatten profiles to find the matching key
             scan_args = ""
             for category, profiles in SCAN_PROFILES.items():
                 if scan_type in profiles:
                     scan_args = profiles[scan_type]['args']
                     break
             
             # If exact key match failed, maybe scan_type is legacy (quick/full)
             if not scan_args:
                  if scan_type == 'quick': scan_args = "-T4 --top-ports 100"
                  elif scan_type == 'full': scan_args = "-p- -T4"
                  elif scan_type == 'vuln': scan_args = "--script vuln"
                  else: scan_args = "-F" # default fallback
             
             # Pass the raw args to orchestrator
             # Note: Orchestrator currently expects a profile KEY (string) or needs refactoring.
             # The orchestrator uses NmapScanner which likely expects a list of args or a profile key.
             # Let's inspect orchestrator logic again.
             # It calls `scanner.command_for_profile(profile)`.
             # So we should pass the scan_type key, but Orchestrator needs to know about SCAN_PROFILES?
             # Or we refactor Orchestrator to accept raw args.
             
             # Let's pass the scan_type as profile, and Update Orchestrator to import SCAN_PROFILES.
             success = orchestrator.run_pipeline(profile=scan_type)
             
             if success:
                 _log_and_emit(scan.id, "Running Evidence-Based Reclassifier...", "INFO")
                 reclassifier = PostDetectionReclassifier(scan.id)
                 reclassifier.process()
                 _log_and_emit(scan.id, "Reclassification and deduplication complete.", "SUCCESS")
                 
        except Exception as e:
             _log_and_emit(scan.id, f"Pipeline Error: {str(e)}", "ERROR")
             success = False

        scan.status = 'completed' if success else 'failed'
        scan.end_time = datetime.utcnow()
        db.session.commit()
        
        _log_and_emit(scan.id, "Operation Concluded.", "SUCCESS" if success else "ERROR")


@main_bp.route("/scan/new", methods=["POST"])
@login_required
def new_scan():
    target_input = request.form.get("target")
    mission_id = request.form.get("mission_id", type=int)
    asset_id = request.form.get("asset_id", type=int)
    scan_type = request.form.get("scan_type", "pipeline")
    confirm_auth = request.form.get("confirm_auth")
    recursive = request.form.get("recursive") == "on"

    if not target_input:
        flash("Target is required", "error")
        return redirect(url_for("main.index"))
    if not confirm_auth:
        flash("Authorization confirmation is required before running scans.", "error")
        return redirect(url_for("main.index"))

    target_input = _normalize_target(target_input)

    try:
        from scan_engine.helpers.target_utils import validate_target
        validate_target(target_input)
    except ValueError as e:
        flash(f"Invalid target: {str(e)}", "error")
        return redirect(url_for("main.index"))

    target = Target.query.filter_by(identifier=target_input).first()
    if not target:
        target = Target(identifier=target_input, mission_id=mission_id)
        db.session.add(target)
        db.session.commit()
    elif mission_id and not target.mission_id:
        target.mission_id = mission_id
        db.session.commit()

    if mission_id:
        ensure_asset_for_target(mission_id, target, source="scan_form")

    if asset_id:
        asset = Asset.query.get(asset_id)
        if asset and asset.mission_id == (mission_id or target.mission_id):
            link_asset_target(asset, target, source="scan_form", metadata={"linked_via": "new_scan"})
            db.session.commit()

    scan_params = {"recursive": recursive}
    scan = Scan(target_id=target.id, scan_type=scan_type, status="pending", params=json.dumps(scan_params))
    db.session.add(scan)
    db.session.commit()

    # CRITICAL: If scan ID is recycled (e.g. after purge), ensure we don't inherit orphaned data
    # SQLite might not enforce FK constraints strictly, leading to orphans.
    try:
        ScanLog.query.filter_by(scan_id=scan.id).delete()
        Finding.query.filter_by(scan_id=scan.id).delete()
        Suggestion.query.filter_by(scan_id=scan.id).delete()
        Loot.query.filter_by(scan_id=scan.id).delete()
        db.session.commit()
    except Exception as e:
        print(f"Cleanup of potential orphans failed (non-blocking): {e}")

    # Ensure fresh results file (wipes stale data from previous deleted runs)
    delete_results(scan.id)

    # Launch via Celery
    task = run_scan_task.delay(scan.id, target.identifier, scan_type)
    
    # Save Task ID for revocation
    scan.task_id = task.id
    db.session.commit()

    flash(f"Started {scan_type} scan for {target_input}", "success")
    return redirect(url_for("main.scan_detail", scan_id=scan.id))

@main_bp.route("/scan/<int:scan_id>/notes", methods=["POST"])
@login_required
def update_notes(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    notes = request.form.get("notes")
    scan.notes = notes
    db.session.commit()
    flash("Operator notes updated.", "success")
    return redirect(url_for("main.scan_detail", scan_id=scan.id))

@main_bp.route("/scan/<int:scan_id>/report")
def scan_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db_findings = Finding.query.filter_by(scan_id=scan.id).all()
    results = load_results(scan_id)
    
    from adapters.detection_adapter import DetectionAdapter
    normalized_findings = DetectionAdapter.normalize_findings(db_findings, results)
    
    # Gather child scans findings if recursive
    child_scans = Scan.query.filter_by(parent_scan_id=scan.id).all()
    for child in child_scans:
        c_findings = Finding.query.filter_by(scan_id=child.id).all()
        c_results = load_results(child.id)
        c_norm = DetectionAdapter.normalize_findings(c_findings, c_results)
        normalized_findings.extend(c_norm)
        
    suggestions = Suggestion.query.filter_by(scan_id=scan_id).all()
    
    format = request.args.get('format', 'html')
    if format == 'pdf':
        from flask import send_from_directory
        import os
        filename = generate_scan_report(scan_id, scan, normalized_findings)
        return send_from_directory(os.path.join(current_app.root_path, "data/reports"), filename, as_attachment=False)
        
    if format == 'html_download':
        from flask import send_from_directory
        import os
        filename = generate_html_report(scan_id, scan, normalized_findings, suggestions)
        return send_from_directory(os.path.join(current_app.root_path, "data/reports"), filename, as_attachment=True)

    
    # Calculate duration
    duration = "N/A"
    if scan.end_time and scan.start_time:
        delta = scan.end_time - scan.start_time
        duration = str(delta).split('.')[0]

    return render_template(
        "reports/standard_report.html",
        scan=scan,
        results=results,
        findings=normalized_findings,
        suggestions=suggestions,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration
    )

@main_bp.route("/api/missions/<int:mission_id>/overview")
def mission_overview_api(mission_id):
    payload = aggregate_mission_intelligence(mission_id)
    return jsonify(payload)


@main_bp.route("/api/missions/<int:mission_id>/actions", methods=["GET"])
def mission_operator_actions_api(mission_id):
    payload = aggregate_mission_intelligence(mission_id)
    return jsonify({
        "mission_id": mission_id,
        "actions": payload.get("operator_actions", []),
        "status_model": {
            "allowed_statuses": sorted(ACTION_STATUSES),
            "transitions": {
                "suggested": ["reviewed", "blocked", "invalidated", "skipped"],
                "reviewed": ["queued", "blocked", "invalidated", "skipped"],
                "queued": ["executed", "blocked", "invalidated", "skipped"],
                "blocked": ["reviewed", "queued", "invalidated", "skipped"],
                "skipped": ["reviewed", "invalidated"],
                "invalidated": ["reviewed"],
                "executed": [],
            },
        },
    })


@main_bp.route("/api/missions/<int:mission_id>/actions/<int:action_id>/status", methods=["POST"])
def mission_operator_action_status_api(mission_id, action_id):
    data = request.get_json(silent=True) or request.form
    next_status = (data.get("status") or "").strip().lower()
    if not next_status:
        return jsonify({"error": "status is required"}), 400
    updated, err = update_operator_action_status(mission_id, action_id, next_status)
    if err == "not_found":
        return jsonify({"error": "operator action not found"}), 404
    if err == "invalid_transition":
        return jsonify({"error": "invalid status transition", "allowed_statuses": sorted(ACTION_STATUSES)}), 400
    return jsonify({"status": "updated", "action": updated})


@main_bp.route("/api/missions/<int:mission_id>/assets", methods=["GET", "POST"])
def mission_assets_api(mission_id):
    Mission.query.get_or_404(mission_id)
    if request.method == "GET":
        assets = Asset.query.filter_by(mission_id=mission_id).order_by(Asset.created_at.desc()).all()
        return jsonify({
            "mission_id": mission_id,
            "assets": [
                {
                    "id": a.id,
                    "type": a.type,
                    "identifier": a.identifier,
                    "label": a.label,
                    "confidence": a.confidence,
                    "source": a.source,
                    "provenance": a.provenance,
                    "tags": a.tags or [],
                    "target_ids": sorted({l.target_id for l in a.target_links}),
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in assets
            ]
        })

    data = request.get_json(silent=True) or request.form
    identifier = (data.get("identifier") or "").strip()
    if not identifier:
        return jsonify({"error": "identifier is required"}), 400

    asset = Asset.query.filter_by(mission_id=mission_id, identifier=identifier.lower()).first()
    created = False
    if not asset:
        asset = Asset(
            mission_id=mission_id,
            type=(data.get("type") or "domain").strip().lower(),
            identifier=identifier.lower(),
            label=data.get("label") or identifier,
            confidence=(data.get("confidence") or "medium").strip().lower(),
            source=data.get("source") or "operator",
            provenance=data.get("provenance") if isinstance(data.get("provenance"), dict) else None,
            tags=data.get("tags") if isinstance(data.get("tags"), list) else [],
        )
        db.session.add(asset)
        db.session.flush()
        created = True

    target_ids = data.get("target_ids") if isinstance(data.get("target_ids"), list) else []
    for tid in target_ids:
        target = Target.query.get(tid)
        if target and target.mission_id == mission_id:
            link_asset_target(asset, target, source="asset_api", metadata={"linked_via": "api"})

    db.session.commit()
    return jsonify({
        "status": "created" if created else "updated",
        "asset_id": asset.id,
    }), 201 if created else 200


@main_bp.route("/api/missions/<int:mission_id>/objectives", methods=["GET", "POST"])
def mission_objectives_api(mission_id):
    mission = Mission.query.get_or_404(mission_id)
    if request.method == "GET":
        return jsonify({
            "mission_id": mission.id,
            "mission_status": normalize_mission_status(mission.status),
            "objectives": mission.objectives_json or [],
            "allowed_objectives": sorted(OBJECTIVE_TYPES),
            "allowed_statuses": sorted(MISSION_STATES),
        })

    data = request.get_json(silent=True) or request.form
    objectives = data.get("objectives")
    if isinstance(objectives, str):
        objectives = [o.strip() for o in objectives.split(",") if o.strip()]
    if not isinstance(objectives, list):
        return jsonify({"error": "objectives must be a list"}), 400

    normalized_objectives = []
    invalid = []
    for item in objectives:
        if isinstance(item, str):
            objective_type = normalize_objective_type(item)
            if not objective_type:
                invalid.append(item)
                continue
            normalized_objectives.append({"objective_type": objective_type, "priority": "medium", "status": "draft"})
            continue
        if not isinstance(item, dict):
            invalid.append(item)
            continue
        objective_type = normalize_objective_type(item.get("objective_type") or item.get("type"))
        if not objective_type:
            invalid.append(item)
            continue
        normalized_objectives.append({
            "objective_type": objective_type,
            "priority": (item.get("priority") or "medium").lower(),
            "status": (item.get("status") or "draft").lower(),
            "confidence": item.get("confidence") if isinstance(item.get("confidence"), (int, float)) else None,
            "required_conditions": item.get("required_conditions") if isinstance(item.get("required_conditions"), list) else [],
            "recommended_next_steps": item.get("recommended_next_steps") if isinstance(item.get("recommended_next_steps"), list) else [],
        })

    if invalid:
        return jsonify({"error": "unsupported objectives", "invalid": invalid}), 400

    status = normalize_mission_status(data.get("status") or mission.status)
    mission.status = status
    mission.scope_summary = (data.get("scope_summary") or mission.scope_summary)
    mission.priority = (data.get("priority") or mission.priority or "medium").lower()

    tags = data.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    if isinstance(tags, list):
        mission.tags_json = sorted(set(str(t).strip().lower() for t in tags if str(t).strip()))

    dedup = {}
    for objective in normalized_objectives:
        dedup[objective["objective_type"]] = objective
    mission.objectives_json = [dedup[key] for key in sorted(dedup.keys())]
    db.session.commit()
    return jsonify({"mission_id": mission.id, "status": mission.status, "objectives": mission.objectives_json})


@main_bp.route("/mission/<int:mission_id>/map")
def mission_map(mission_id):
    mission = Mission.query.get_or_404(mission_id)
    targets = Target.query.filter_by(mission_id=mission_id).all()
    assets = Asset.query.filter_by(mission_id=mission_id).all()
    intelligence = aggregate_mission_intelligence(mission_id)

    # Bundle all relevant scan data for these targets
    graph_data = {"nodes": [], "edges": []}

    # Mission node
    graph_data["nodes"].append({"id": f"m{mission.id}", "label": mission.name, "group": "mission", "level": 0})
    for a in assets:
        aid = f"a{a.id}"
        graph_data["nodes"].append({"id": aid, "label": a.label or a.identifier, "group": "asset", "level": 1, "title": f"{a.type} | confidence={a.confidence}"})
        graph_data["edges"].append({"from": f"m{mission.id}", "to": aid})
    
    # Optimization: Fetch all latest scans for targets in one go
    scan_map = {}
    target_ids = [t.id for t in targets]
    if target_ids:
        # Get max scan ID for each target
        max_ids_q = db.session.query(func.max(Scan.id)).filter(Scan.target_id.in_(target_ids)).group_by(Scan.target_id)
        max_ids = [r[0] for r in max_ids_q.all()]

        if max_ids:
            # Fetch scans with findings
            scans = Scan.query.options(joinedload(Scan.findings)).filter(Scan.id.in_(max_ids)).all()
            scan_map = {s.target_id: s for s in scans}

    for t in targets:
        # Get latest scan for this target to obtain geolocation
        scan = scan_map.get(t.id)
        label = t.identifier
        if scan and scan.geolocation_data:
            label += f"\n({scan.geolocation_data.get('country', '??')})"
            
        graph_data["nodes"].append({"id": f"t{t.id}", "label": label, "group": "target", "level": 2, "title": f"ISP: {scan.geolocation_data.get('isp')}" if scan and scan.geolocation_data else ""})
        linked_assets = [l.asset_id for l in t.asset_links]
        if linked_assets:
            for asset_id in linked_assets:
                graph_data["edges"].append({"from": f"a{asset_id}", "to": f"t{t.id}"})
        else:
            graph_data["edges"].append({"from": f"m{mission.id}", "to": f"t{t.id}"})
        
        # Add icons for critical findings on this target
        if scan:
            findings = scan.findings
            for f in findings:
                f_id = f"f{f.id}"
                graph_data["nodes"].append({
                    "id": f_id, 
                    "label": f.title[:20] + "...", 
                    "group": f.severity.lower(),
                    "level": 2,
                    "title": f.description
                })
                graph_data["edges"].append({"from": f"t{t.id}", "to": f_id})

    return render_template("missions/map.html", mission=mission, graph_data=graph_data, intelligence=intelligence)

@main_bp.route("/missions")
def mission_list():
    missions = Mission.query.order_by(Mission.created_at.desc()).all()
    return render_template("missions/list.html", missions=missions)

@main_bp.route("/gallery")
def gallery():
    screenshots_dir = os.path.join(current_app.static_folder, "screenshots")
    images = []
    if os.path.exists(screenshots_dir):
        for f in os.listdir(screenshots_dir):
            if f.endswith(".png"):
                # parse filename: scan_{id}_port_{port}.png
                parts = f.replace(".png", "").split("_")
                port = "Unknown"
                if "port" in parts:
                    try:
                        port_idx = parts.index("port")
                        port = parts[port_idx + 1]
                    except Exception: pass
                
                images.append({
                    "path": f"screenshots/{f}",
                    "filename": f,
                    "port": port,
                    "service": "HTTP/HTTPS", # placeholder
                    "protocol": "tcp"
                })
    return render_template("gallery.html", images=images)

@main_bp.route("/mission/new", methods=["POST"])
@login_required
def mission_new():
    name = request.form.get("name")
    desc = request.form.get("description")
    objectives_input = request.form.get("objectives", "")
    objectives = [o.strip() for o in objectives_input.split(",") if o.strip()]
    normalized_objectives = []
    for objective in objectives:
        objective_type = normalize_objective_type(objective)
        if objective_type:
            normalized_objectives.append({"objective_type": objective_type, "priority": "medium", "status": "draft"})

    tags_input = request.form.get("tags", "")
    tags = sorted(set(tag.strip().lower() for tag in tags_input.split(",") if tag.strip()))

    mission = Mission(
        name=name,
        description=desc,
        status=normalize_mission_status(request.form.get("status") or "draft"),
        objectives_json=normalized_objectives or None,
        scope_summary=request.form.get("scope_summary") or None,
        priority=(request.form.get("priority") or "medium").lower(),
        tags_json=tags or None,
    )
    db.session.add(mission)
    db.session.commit()
    flash(f"Mission '{name}' created successfully.", "success")
    return redirect(url_for("main.mission_list"))

@main_bp.route("/loot")
def loot_list():
    loots = Loot.query.order_by(Loot.created_at.desc()).all()
    return render_template("loots/list.html", loots=loots)

@main_bp.route("/scan/<int:scan_id>/loot/add", methods=["POST"])
@login_required
def loot_add(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    loot_type = request.form.get("type")
    content = request.form.get("content")
    context = request.form.get("context")
    
    loot = Loot(
        mission_id=scan.target.mission_id if scan.target.mission_id else None,
        scan_id=scan_id,
        type=loot_type,
        content=content,
        context=context
    )
    db.session.add(loot)
    db.session.commit()
    flash("Loot added to mission database.", "success")
    return redirect(url_for("main.scan_detail", scan_id=scan_id))

@main_bp.route("/scan/verify", methods=["POST"])
@login_required
def verify_finding():
    data = request.json
    scan_id = data.get("scan_id")
    command = data.get("command")
    
    if not command:
        return {"status": "error", "message": "No command provided"}, 400

    def run_verification(sid, cmd, app):
        import shlex
        from subprocess import Popen, PIPE, STDOUT
        with app.app_context():
            _log_and_emit(sid, f"Starting Verification: {cmd}", "INFO")
            try:
                # Use shlex.split for safe tokenization and shell=False to prevent injection
                args = shlex.split(cmd)
                process = Popen(args, shell=False, stdout=PIPE, stderr=STDOUT, text=True)
                for line in process.stdout:
                    if line.strip():
                        _log_and_emit(sid, f"[Verify] {line.strip()}", "INFO")
                process.wait()
                _log_and_emit(sid, "Verification Task Completed.", "SUCCESS")
            except Exception as e:
                _log_and_emit(sid, f"Verification Failed: {str(e)}", "ERROR")

    app_obj = current_app._get_current_object()
    socketio.start_background_task(run_verification, scan_id, command, app_obj)
    
@main_bp.route("/settings/clear_logs", methods=["POST"])
@login_required
def clear_logs():
    try:
        from core.celery_app import celery
        
        # Stop specific tracked tasks first
        active_scans = Scan.query.filter(Scan.status == 'running').all()
        revoked_ids = set()
        
        for s in active_scans:
            if s.task_id:
                celery.control.revoke(s.task_id, terminate=True)
                revoked_ids.add(s.task_id)
        
        # AGGRESSIVE CLEANUP: Kill any other active tasks (Renegade/Zombie scans)
        try:
            inspector = celery.control.inspect()
            active_tasks = inspector.active()
            if active_tasks:
                for worker, tasks in active_tasks.items():
                    for task in tasks:
                        tid = task.get('id')
                        if tid and tid not in revoked_ids:
                            celery.control.revoke(tid, terminate=True)
                            print(f"Killed zombie task: {tid}")
        except Exception as e:
            print(f"Failed to kill zombie tasks: {e}")

        # Clear database records

        # Clear database records in correct order
        from core.models import Mission
        db.session.query(Finding).delete()
        db.session.query(Suggestion).delete()
        db.session.query(KnowledgeNode).delete()
        db.session.query(KnowledgeEdge).delete()
        db.session.query(ScanLog).delete()
        db.session.query(Loot).delete()
        db.session.query(Scan).delete()
        db.session.query(AssetTargetLink).delete()
        db.session.query(Asset).delete()
        db.session.query(Target).delete()
        db.session.query(Mission).delete()
        
        db.session.commit()
        
        # Clear result files from disk
        results_dir = os.path.join(current_app.root_path, "data/results")
        files_deleted = 0
        if os.path.exists(results_dir):
            for f in os.listdir(results_dir):
                if f.endswith(".json"):
                    try:
                        os.remove(os.path.join(results_dir, f))
                        files_deleted += 1
                    except Exception:
                        pass
        
        # Clean temp directories that fill up /tmp (WPScan cache, chromedp orphans)
        import glob
        try:
            if os.path.isdir("/tmp/wpscan/cache"):
                shutil.rmtree("/tmp/wpscan/cache", ignore_errors=True)
            for d in glob.glob("/tmp/chromedp-runner*"):
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass
        
        flash(f"Mission Log Purged ({num_scans} scans, {files_deleted} result files removed). Environment reset.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to clear logs: {str(e)}", "error")
        
    return redirect(url_for("main.index"))
    
@main_bp.route("/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        # 1. Stop the task if running
        if scan.status == 'running' and scan.task_id:
            from core.celery_app import celery
            celery.control.revoke(scan.task_id, terminate=True)
            
        # 2. Delete the result file
        delete_results(scan_id)
        
        # 3. Delete from DB (Cascade handles findings/logs/suggestions)
        db.session.delete(scan)
        db.session.commit()
        
        flash(f"Scan #{scan_id} deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete scan: {str(e)}", "error")
        
    return redirect(url_for("main.index"))


@main_bp.route("/api/missions/<int:mission_id>/quality-metrics", methods=["GET"])
def mission_quality_metrics(mission_id):
    limit = min(request.args.get("limit", 100, type=int), 500)
    payload = aggregate_mission_quality_metrics(mission_id, limit=limit)
    return jsonify({
        "mission_id": mission_id,
        "quality_metrics": payload,
    })


