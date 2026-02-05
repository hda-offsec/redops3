from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from urllib.parse import urlparse
import os
import shutil
from datetime import datetime

from core.models import Target, Scan, Finding, Suggestion, ScanLog, Mission, Loot, db
from core.results_store import load_results, save_results
from core.reporting import generate_scan_report
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.helpers.output_parsers import parse_nmap_open_ports
from scan_engine.orchestrator import ScanOrchestrator
from core.extensions import socketio

main_bp = Blueprint("main", __name__)


@main_bp.route("/terminal")
def terminal():
    return render_template("terminal.html")

@main_bp.route("/")
def index():
    recent_scans = Scan.query.order_by(Scan.start_time.desc()).limit(10).all()
    targets = Target.query.all()
    missions = Mission.query.all()
    loots = Loot.query.all()
    
    # --- CISO ANALYTICS ---
    all_findings = Finding.query.all()
    severity_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = (f.severity or "info").lower()
        if sev in severity_stats:
            severity_stats[sev] += 1
            
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

    return render_template(
        "index.html",
        recent_scans=recent_scans,
        targets=targets,
        missions=missions,
        loots=loots,
        severity_stats=severity_stats,
        total_findings=len(all_findings),
        logs=recent_logs
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
        socketio.emit(
            "new_log",
            {
                "message": msg,
                "level": level,
                "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
                "scan_id": scan_id,
            },
        )
    except Exception as e:
        print(f"[ERROR] Socket Emit Failed: {e}")



def _add_finding(scan_id, tool, severity, title, description=None, screenshot_path=None):
    finding = Finding(
        scan_id=scan_id,
        severity=severity,
        title=title,
        description=description,
        tool_source=tool,
        screenshot_path=screenshot_path
    )
    db.session.add(finding)
    db.session.commit()
    
    _log_and_emit(scan_id, f"Finding detected: {title}", "WARN")
    
    # Real-time finding emission for the specific scan detail page
    socketio.emit("new_finding", {
        "scan_id": scan_id,
        "title": title,
        "severity": severity,
        "tool": tool
    })

    # Global Alert for Critical Issues
    if severity.lower() == 'critical':
        socketio.emit('global_notification', {
            'title': '🚨 CRITICAL VULNERABILITY',
            'message': f'{title} found on scan #{scan_id}',
            'severity': 'critical'
        })
    
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
        def add_finding_cb(**kwargs):
            try:
                # Use the helper to ensure global notifications and model consistency
                _add_finding(
                    scan_id=scan.id,
                    tool=kwargs.get('tool_source', 'orchestrator'),
                    severity=kwargs.get('severity', 'info'),
                    title=kwargs.get('title', 'Untitled Finding'),
                    description=kwargs.get('description'),
                    screenshot_path=kwargs.get('screenshot_path')
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
                socketio.emit("new_suggestion", {
                    "scan_id": scan.id,
                    "tool_name": s.tool_name,
                    "command": s.command_suggestion
                })
            except Exception as e:
                print(f"[ERROR] Failed to save suggestion: {e}")
                db.session.rollback()

        def results_update_cb(scan_id, data):
            save_results(scan_id, data)
            # Emit the partial/full results update to the UI
            socketio.emit("results_update", {
                "scan_id": scan_id,
                "data": data
            })

        orchestrator = ScanOrchestrator(
            scan_id=scan.id,
            target=target_identifier,
            logger_func=lambda msg, lvl: _log_and_emit(scan.id, msg, lvl),
            finding_func=add_finding_cb,
            suggestion_func=add_suggestion_cb,
            results_func=results_update_cb
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
    findings = Finding.query.filter_by(scan_id=scan.id).all()
    results = load_results(scan_id)
    
    format = request.args.get('format', 'html')
    if format == 'pdf':
        from flask import send_from_directory
        import os
        filename = generate_scan_report(scan_id, scan, findings)
        return send_from_directory(os.path.join(current_app.root_path, "data/reports"), filename)

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

@main_bp.route("/mission/<int:mission_id>/map")
def mission_map(mission_id):
    mission = Mission.query.get_or_404(mission_id)
    targets = Target.query.filter_by(mission_id=mission_id).all()
    
    # Bundle all relevant scan data for these targets
    graph_data = {"nodes": [], "edges": []}
    
    # Mission node
    graph_data["nodes"].append({"id": f"m{mission.id}", "label": mission.name, "group": "mission", "level": 0})
    
    for t in targets:
        graph_data["nodes"].append({"id": f"t{t.id}", "label": t.identifier, "group": "target", "level": 1})
        graph_data["edges"].append({"from": f"m{mission.id}", "to": f"t{t.id}"})
        
        # Add icons for critical findings on this target
        latest_scan = Scan.query.filter_by(target_id=t.id).order_by(Scan.id.desc()).first()
        if latest_scan:
            findings = Finding.query.filter_by(scan_id=latest_scan.id).all()
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

    return render_template("missions/map.html", mission=mission, graph_data=graph_data)

@main_bp.route("/missions")
def mission_list():
    missions = Mission.query.order_by(Mission.created_at.desc()).all()
    return render_template("missions/list.html", missions=missions)

@main_bp.route("/mission/new", methods=["POST"])
def mission_new():
    name = request.form.get("name")
    desc = request.form.get("description")
    mission = Mission(name=name, description=desc)
    db.session.add(mission)
    db.session.commit()
    flash(f"Mission '{name}' created successfully.", "success")
    return redirect(url_for("main.mission_list"))

@main_bp.route("/loot")
def loot_list():
    loots = Loot.query.order_by(Loot.created_at.desc()).all()
    return render_template("loots/list.html", loots=loots)

@main_bp.route("/scan/<int:scan_id>/loot/add", methods=["POST"])
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
def verify_finding():
    data = request.json
    scan_id = data.get("scan_id")
    command = data.get("command")
    
    if not command:
        return {"status": "error", "message": "No command provided"}, 400

    def run_verification(sid, cmd, app):
        with app.app_context():
            from subprocess import Popen, PIPE, STDOUT
            _log_and_emit(sid, f"Starting Verification: {cmd}", "INFO")
            try:
                process = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT, text=True)
                for line in process.stdout:
                    if line.strip():
                        _log_and_emit(sid, f"[Verify] {line.strip()}", "INFO")
                process.wait()
                _log_and_emit(sid, "Verification Task Completed.", "SUCCESS")
            except Exception as e:
                _log_and_emit(sid, f"Verification Failed: {str(e)}", "ERROR")

    app_obj = current_app._get_current_object()
    socketio.start_background_task(run_verification, scan_id, command, app_obj)
    
    return {"status": "ok", "message": "Verification started"}
