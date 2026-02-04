from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from urllib.parse import urlparse
import os
import shutil

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

    with app.app_context():
        scan = Scan.query.get(scan_id)
        scan.status = "running"
        db.session.commit()

        _log_and_emit(scan.id, f"Starting {scan_type} scan for {target_identifier}", "INFO")

        success = False

        if scan_type in {"pipeline", "pipeline_full"}:
            profile = "quick" if scan_type == "pipeline" else "full"
            try:
                orchestrator = ScanOrchestrator(
                    scan.id,
                    target_identifier,
                    lambda msg, level="INFO": _log_and_emit(scan.id, msg, level),
                    lambda **kwargs: _add_finding(scan.id, **kwargs),
                    lambda **kwargs: _add_suggestion(scan.id, **kwargs),
                    save_results,
                )
                success = orchestrator.run_pipeline(profile=profile)
            except Exception as exc:
                _log_and_emit(scan.id, f"Pipeline exception: {str(exc)}", "ERROR")
                success = False
        else:
            scanner = NmapScanner(target_identifier)

            if not shutil.which("nmap"):
                _log_and_emit(scan.id, "ERROR: 'nmap' binary not found.", "ERROR")
                scan.status = "failed"
                db.session.commit()
                return

            if NmapScanner.requires_root(scan_type) and os.geteuid() != 0:
                _log_and_emit(
                    scan.id,
                    f"ERROR: Nmap profile '{scan_type}' requires sudo/root privileges.",
                    "ERROR",
                )
                scan.status = "failed"
                db.session.commit()
                return

            stream = scanner.stream_profile(scan_type)
            output_lines = []
            exit_code = None
            for event in stream:
                if event["type"] == "stdout":
                    line = event["line"].strip()
                    if line:
                        output_lines.append(line)
                        _log_and_emit(scan.id, line, "INFO")
                elif event["type"] == "exit":
                    exit_code = event["code"]

            success = exit_code == 0
            if not success:
                _log_and_emit(scan.id, f"Nmap failed (exit {exit_code}).", "ERROR")
            else:
                ports = parse_nmap_open_ports("\n".join(output_lines))
                results = {
                    "scan_id": scan.id,
                    "target": target_identifier,
                    "started_at": scan.start_time.isoformat() + "Z",
                    "completed_at": datetime.utcnow().isoformat() + "Z",
                    "phases": {
                        "recon": {
                            "tool": "nmap",
                            "profile": scan_type,
                            "open_ports": ports,
                            "raw": output_lines[:200],
                        }
                    },
                }
                save_results(scan.id, results)

        scan.status = "completed" if success else "failed"
        scan.end_time = datetime.utcnow()
        db.session.commit()

        _log_and_emit(scan.id, "Scan completed successfully." if success else "Scan failed.", "SUCCESS" if success else "ERROR")


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
    return redirect(url_for("main.index"))
