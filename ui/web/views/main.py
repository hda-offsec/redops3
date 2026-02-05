from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from urllib.parse import urlparse
import os
import shutil
from datetime import datetime

from core.models import Target, Scan, Finding, Suggestion, ScanLog, db
from core.results_store import load_results, save_results
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.helpers.output_parsers import parse_nmap_open_ports
from scan_engine.orchestrator import ScanOrchestrator
from core.extensions import socketio

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    recent_scans = Scan.query.order_by(Scan.start_time.desc()).limit(5).all()
    targets = Target.query.all()
    latest_scan = Scan.query.order_by(Scan.start_time.desc()).first()
    latest_results = load_results(latest_scan.id) if latest_scan else None
    latest_findings = (
        Finding.query.filter_by(scan_id=latest_scan.id)
        .order_by(Finding.id.desc())
        .limit(15)
        .all()
        if latest_scan
        else []
    )
    latest_suggestions = (
        Suggestion.query.filter_by(scan_id=latest_scan.id)
        .order_by(Suggestion.id.desc())
        .limit(10)
        .all()
        if latest_scan
        else []
    )
    recent_logs = (
        ScanLog.query.filter_by(scan_id=latest_scan.id)
        .order_by(ScanLog.timestamp.desc())
        .limit(200)
        .all()
        if latest_scan
        else []
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in latest_findings:
        sev = (finding.severity or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["info"] += 1

    return render_template(
        "index.html",
        recent_scans=recent_scans,
        targets=targets,
        latest_scan=latest_scan,
        latest_results=latest_results,
        latest_findings=latest_findings,
        latest_suggestions=latest_suggestions,
        logs=recent_logs,
        severity_counts=severity_counts,
    )


@main_bp.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    results = load_results(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.id.desc()).all()
    suggestions = Suggestion.query.filter_by(scan_id=scan_id).order_by(Suggestion.id.desc()).all()
    logs = ScanLog.query.filter_by(scan_id=scan_id).order_by(ScanLog.timestamp.asc()).all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = (finding.severity or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["info"] += 1

    return render_template(
        "scan_detail.html",
        scan=scan,
        results=results,
        findings=findings,
        suggestions=suggestions,
        logs=logs,
        severity_counts=severity_counts,
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
    log = ScanLog(scan_id=scan_id, message=msg, level=level)
    db.session.add(log)
    db.session.commit()
    socketio.emit(
        "new_log",
        {
            "message": msg,
            "level": level,
            "timestamp": log.timestamp.strftime("%H:%M:%S"),
            "scan_id": scan_id,
        },
    )


def _add_finding(scan_id, tool, severity, title, description=None):
    finding = Finding(
        scan_id=scan_id,
        severity=severity,
        title=title,
        description=description,
        tool_source=tool,
    )
    db.session.add(finding)
    db.session.commit()
    return finding


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
    
    # Map UI types to internal profiles
    # 'quick' -> nmap -F + parse + suggest
    # 'full' -> nmap -p- + parse + suggest
    # 'vuln' -> nmap --script vuln + parse + suggest
    
    with app.app_context():
        scan = Scan.query.get(scan_id)
        scan.status = 'running'
        db.session.commit()
        
        _log_and_emit(scan.id, f"Initializing Orchestrated Scan: {scan_type.upper()}", "INFO")

        # -- ORCHESTRATOR SETUP --
        from scan_engine.orchestrator import ScanOrchestrator
        from core.results_store import save_results
        
        def add_finding_cb(**kwargs):
            # Helper to add finding inside existing context
            if 'scan_id' not in kwargs: kwargs['scan_id'] = scan.id
            f = Finding(**kwargs)
            db.session.add(f)
            db.session.commit()
            _log_and_emit(scan.id, f"Finding: {kwargs.get('title')}", "WARN")

        def add_suggestion_cb(**kwargs):
            if 'scan_id' not in kwargs: kwargs['scan_id'] = scan.id
            s = Suggestion(**kwargs)
            db.session.add(s)
            db.session.commit()
            _log_and_emit(scan.id, f"Suggestion: Try {kwargs.get('tool_name')}", "SUCCESS")

        orchestrator = ScanOrchestrator(
            scan_id=scan.id,
            target=target_identifier,
            logger_func=lambda msg, lvl: _log_and_emit(scan.id, msg, lvl),
            finding_func=add_finding_cb,
            suggestion_func=add_suggestion_cb,
            results_func=save_results
        )
        
        # Execute Pipeline
        try:
             # Map 'scan_type' from UI to profile expected by orchestrator
             # in orchestrator.py currently it handles 'quick' or 'full'
             # Let's pass the raw scan_type and ensure orchestrator handles it or mapped
             profile = scan_type
             if scan_type not in ['quick', 'full', 'deep', 'vuln']: 
                 profile = 'quick' # fallback for now or update orchestrator
             
             success = orchestrator.run_pipeline(profile=profile)
        except Exception as e:
             _log_and_emit(scan.id, f"Pipeline Error: {str(e)}", "ERROR")
             success = False

        scan.status = 'completed' if success else 'failed'
        scan.end_time = datetime.utcnow()
        db.session.commit()
        
        _log_and_emit(scan.id, "Operation Concluded.", "SUCCESS" if success else "ERROR")


@main_bp.route("/scan/new", methods=["POST"])
def new_scan():
    target_input = request.form.get("target")
    scan_type = request.form.get("scan_type", "pipeline")
    confirm_auth = request.form.get("confirm_auth")

    if not target_input:
        flash("Target is required", "error")
        return redirect(url_for("main.index"))
    if not confirm_auth:
        flash("Authorization confirmation is required before running scans.", "error")
        return redirect(url_for("main.index"))

    target_input = _normalize_target(target_input)

    target = Target.query.filter_by(identifier=target_input).first()
    if not target:
        target = Target(identifier=target_input)
        db.session.add(target)
        db.session.commit()

    scan = Scan(target_id=target.id, scan_type=scan_type, status="pending")
    db.session.add(scan)
    db.session.commit()

    app_obj = current_app._get_current_object()
    socketio.start_background_task(background_scan, scan.id, target.identifier, scan_type, app_obj)

    flash(f"Started {scan_type} scan for {target_input}", "success")
    return redirect(url_for("main.scan_detail", scan_id=scan.id))

@main_bp.route("/scan/<int:scan_id>/notes", methods=["POST"])
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
    results = load_results(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.severity.asc()).all()
    suggestions = Suggestion.query.filter_by(scan_id=scan_id).all()
    
    # Calculate duration
    duration = "N/A"
    if scan.end_time and scan.start_time:
        delta = scan.end_time - scan.start_time
        duration = str(delta).split('.')[0]

    return render_template(
        "reports/standard_report.html",
        scan=scan,
        results=results,
        findings=findings,
        suggestions=suggestions,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration
    )
