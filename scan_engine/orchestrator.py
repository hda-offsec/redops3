import json
import threading
import traceback
import re
from datetime import datetime

try:
    from core.extensions import get_socketio
except Exception:
    def get_socketio():
        class _Dummy:
            def emit(self, *a, **k):
                pass

        return _Dummy()
from scan_engine.helpers.adaptive_hints import derive_adaptive_hints
from scan_engine.helpers.attack_graph import AttackGraphBuilder
from scan_engine.helpers.decision_cortex import suggest_actions
from scan_engine.helpers.execution_hints import derive_execution_hints
from scan_engine.helpers.safety_checks import validate_results_schema
from scan_engine.helpers.service_intelligence import derive_service_intel
from scan_engine.helpers.surface_expander import derive_surface_expansion
from scan_engine.helpers.js_mining_expert import JSDeepMiningExpert
from scan_engine.helpers.identity_spectre import IdentitySpectre
from scan_engine.helpers.finding_schema import generate_stable_id
from scan_engine.helpers.task_scheduler import TaskScheduler
from scan_engine.phases.dirbusting import run_dirbusting
from scan_engine.phases.enum import run_enum
from scan_engine.phases.intel import run_intel
from scan_engine.phases.recon import run_dns_osint, run_recon
from scan_engine.step01_recon.nse_scanner import NSEScanner
from scan_engine.step05_tactical.lateral_path_expert import LateralPathExpert
from scan_engine.step03_vuln.token_validator import TokenValidator
from scan_engine.step01_recon.cloud_storage_expert import CloudStorageExpert
from core.results_store import load_results
try:
    from scan_engine.phases.vuln import run_global_vuln_scans, run_vuln_scans
except Exception:
    def run_global_vuln_scans(*args, **kwargs):
        raise RuntimeError("vuln_phase_import_unavailable")

    def run_vuln_scans(*args, **kwargs):
        raise RuntimeError("vuln_phase_import_unavailable")


class ScanOrchestrator:
    def __init__(self, scan_id, target, logger_func, finding_func, suggestion_func, results_func, loot_func=None, recursion_func=None, options=None, **kwargs):
        self.scan_id = scan_id
        self.target = target
        self.log = logger_func
        self._finding_callback = finding_func
        self.add_suggestion = suggestion_func
        self.save_results = results_func
        self._loot_callback = loot_func
        self.graph_func = kwargs.get('graph_func')
        self.recursion_func = recursion_func
        self.options = options or {}
        self.config = self.options.get('config', {})
        self.results = {}
        self._results_lock = threading.RLock()
        self._control_lock = threading.Lock()
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._stop_requested = False
        self._skip_tasks = set()
        self._scheduler = None
        self.socketio = get_socketio()
        self._start_time = None
        self.control_flags = {
            "pause": False,
            "stop": False,
        }

    def thread_safe_results_update(self, fn):
        with self._results_lock:
            return fn()

    def _save_results_thread_safe(self, payload=None, overwrite=False):
        if payload is None:
            with self._results_lock:
                payload = json.loads(json.dumps(self.results))
        if overwrite:
            self.save_results(self.scan_id, payload, overwrite=True)
        else:
            self.save_results(self.scan_id, payload)

    def emit_event(self, event_type, module, port=None, level="INFO", data=None):
        evt = {
            "ts": datetime.utcnow().isoformat(),
            "type": event_type,
            "module": module,
            "port": str(port) if port is not None else None,
            "level": level,
            "data": data or {}
        }
        payload = {}

        def _update():
            if 'timeline' not in self.results:
                self.results['timeline'] = []
            self.results["timeline"].append(evt)
            payload["timeline"] = list(self.results.get("timeline", []))

        self.thread_safe_results_update(_update)
        self.socketio.emit("pipeline_event", evt, room=f"scan_{self.scan_id}")
        self._save_results_thread_safe(payload)
        return evt

    def mark_module(self, module, port, status, artifacts=0, reason=None):
        payload = {}

        def _update_module():
            if 'modules' not in self.results:
                self.results['modules'] = {}
            if module not in self.results['modules']:
                self.results['modules'][module] = {}

            normalized_reason = reason if reason is not None else ("" if status == "executed" else "no_reason_provided")
            self.results['modules'][module][str(port)] = {
                "status": status,
                "artifacts": int(artifacts),
                "reason": normalized_reason
            }
            payload["modules"] = dict(self.results.get("modules", {}))
            return normalized_reason

        normalized_reason = self.thread_safe_results_update(_update_module)

        self.socketio.emit(
            "module_status",
            {"module": module, "port": str(port), "status": status, "artifacts": artifacts, "reason": normalized_reason},
            room=f"scan_{self.scan_id}"
        )

        if status == "executed":
            evt_type = "MODULE_END"
        elif status in ["failed", "error"]:
            evt_type = "MODULE_ERROR"
        elif status == "running":
            evt_type = "MODULE_START"
        else:
            evt_type = "MODULE_SKIPPED"

        level = "ERROR" if status in ["failed", "error"] else "INFO"
        self.emit_event(evt_type, module, port, level=level, data={"artifacts": artifacts, "reason": normalized_reason})
        self._save_results_thread_safe(payload)

    def add_signal(self, **kwargs):
        if not self._signal_callback:
            return None
        return self._signal_callback(**kwargs)

    def add_finding(self, **kwargs):
        """
        Persist findings with immutable Signal capture
        + global deduplication fingerprint
        """

        if not self._finding_callback:
            return

        # V12: Aggressive Terminal Noise Filter (Global Orchestrator Gate)
        def _clean_ansi(s):
            if not isinstance(s, str) or not s: return s
            # Strip ANSI escape sequences
            s = re.sub(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]', '', s)
            # Strip literal leftover terminal codes like [2K
            s = re.sub(r'\[[0-9]{1,2}K', '', s)
            # Retain only printable characters (plus basic whitespace)
            return "".join(c for c in s if c.isprintable() or c in "\n\r\t").strip()

        # Sanitize all potentially affected fields
        for field in ["title", "description", "endpoint", "target", "parameter", "payload", "evidence", "raw_output"]:
            if field in kwargs:
                kwargs[field] = _clean_ansi(kwargs[field])

        normalized_conf = str(kwargs.get("confidence", "medium")).strip().lower()

        if normalized_conf not in {"low", "medium", "high"}:
            normalized_conf = "medium"

        kwargs["confidence"] = normalized_conf

        def _clean_text(value):
            if value is None:
                return ""
            if not isinstance(value, str):
                value = str(value)
            return value.strip()

        invalid_markers = {"", "none", "n/a", "na", "null", "todo", "tbd", "manual", "ui"}

        def _normalize_command_value(*candidates):
            for candidate in candidates:
                normalized = _clean_text(candidate)
                if not normalized:
                    continue
                if normalized.lower() in invalid_markers:
                    continue
                return normalized
            return ""

        def _normalize_locator_value(*candidates):
            for candidate in candidates:
                normalized = _clean_text(candidate)
                if not normalized:
                    continue
                if normalized.lower() in invalid_markers:
                    continue
                # Reject synthetic internal port references — not real network locators
                if normalized.lower().startswith("port:"):
                    continue
                return normalized
            return ""

        metadata_payload = kwargs.get("metadata") if isinstance(kwargs.get("metadata"), dict) else {}
        metadata_validation = metadata_payload.get("validation") if isinstance(metadata_payload.get("validation"), dict) else {}
        metadata_repro = metadata_payload.get("reproducibility") if isinstance(metadata_payload.get("reproducibility"), dict) else {}

        def _looks_like_command(s):
            """Heuristic: a real repro command starts with a known tool or path, not prose."""
            if not s:
                return False
            s_stripped = s.strip()
            # Reject pure human-prose remediation advice (sentence structure)
            if s_stripped[0].isupper() and '.' in s_stripped and len(s_stripped) > 40:
                return False
            known_prefixes = (
                'curl', 'wget', 'http', 'nmap', 'sqlmap', 'ffuf', 'gobuster', 'burp',
                'python', 'python3', 'ruby', 'node', 'bash', 'sh', 'zsh',
                'dalfox', 'nuclei', 'wpscan', 'hydra', 'nikto', 'dirb', 'wfuzz',
                'openssl', 'ssh', 'nc ', 'ncat', 'socat', 'aws ', 'docker', 'kubectl',
                '/', './', '#', '\\',
            )
            return any(s_stripped.lower().startswith(p) for p in known_prefixes)

        normalized_command = _normalize_command_value(
            kwargs.get("repro_command"),
            # Only use `reproduction` as a command if it actually looks like a command
            kwargs.get("reproduction") if _looks_like_command(kwargs.get("reproduction")) else None,
            kwargs.get("command"),
            metadata_repro.get("command"),
            metadata_validation.get("command"),
        )

        command_arguments = kwargs.get("arguments")
        if isinstance(command_arguments, list):
            command_arguments = {"argv": [item for item in command_arguments if item not in (None, "")]}
        elif isinstance(command_arguments, str) and command_arguments.strip():
            command_arguments = {"raw": command_arguments.strip()}
        elif not isinstance(command_arguments, dict):
            command_arguments = {}

        if not command_arguments:
            existing_args = metadata_repro.get("arguments")
            if isinstance(existing_args, dict):
                command_arguments = dict(existing_args)

        validation_status = kwargs.get("validation_status") or metadata_validation.get("status") or "not_run"

        metadata_payload["validation"] = {
            "status": str(validation_status).strip().lower() if validation_status is not None else "not_run",
            "target": _normalize_locator_value(
                metadata_validation.get("target"),
                kwargs.get("endpoint"),
                kwargs.get("target"),
                kwargs.get("url"),
            ),
            "command": _normalize_command_value(metadata_validation.get("command"), normalized_command),
            "expected": _clean_text(metadata_validation.get("expected")),
            "success_criteria": _clean_text(metadata_validation.get("success_criteria")),
            "failure_criteria": _clean_text(metadata_validation.get("failure_criteria")),
            "uncertainty_criteria": _clean_text(metadata_validation.get("uncertainty_criteria")),
            "artifact": _clean_text(metadata_validation.get("artifact") or kwargs.get("response") or kwargs.get("evidence")),
        }

        metadata_payload["reproducibility"] = {
            "command": _normalize_command_value(metadata_repro.get("command"), normalized_command),
            "url": _normalize_locator_value(
                metadata_repro.get("url"),
                kwargs.get("endpoint"),
                kwargs.get("target"),
                kwargs.get("url"),
            ),
            "arguments": command_arguments,
            "request_excerpt": _clean_text(metadata_repro.get("request_excerpt") or kwargs.get("request")),
            "response_excerpt": _clean_text(metadata_repro.get("response_excerpt") or kwargs.get("response")),
        }

        kwargs["metadata"] = metadata_payload
        if normalized_command and not kwargs.get("repro_command"):
            kwargs["repro_command"] = normalized_command

        signal_id = None

        evidence_value = kwargs.get("evidence")
        # Treat empty containers as absent — don't serialize {} or [] as string noise
        if isinstance(evidence_value, dict) and not evidence_value:
            evidence_value = None
        elif isinstance(evidence_value, list) and not evidence_value:
            evidence_value = None
        elif isinstance(evidence_value, (dict, list)):
            try:
                evidence_value = json.dumps(evidence_value, default=str)
            except Exception:
                evidence_value = str(evidence_value)

        signal_payload = {
            "tool": kwargs.get("tool_source") or kwargs.get("tool") or "orchestrator",
            "module": kwargs.get("module") or kwargs.get("tool_source") or kwargs.get("tool") or "orchestrator",
            "type": kwargs.get("category") or kwargs.get("type") or "finding",
            "target": kwargs.get("target") or kwargs.get("url") or self.target,
            "endpoint": kwargs.get("endpoint") or kwargs.get("url") or kwargs.get("target") or self.target,
            "parameter": kwargs.get("parameter"),
            "payload": kwargs.get("payload"),
            "status_code": kwargs.get("status_code"),
            "response_headers": kwargs.get("response_headers") or kwargs.get("headers"),
            "response_evidence": evidence_value,
            "raw_output": kwargs.get("raw_output")
            or kwargs.get("response")
            or kwargs.get("description")
            or kwargs.get("evidence"),
            "metadata": {
                **(kwargs.get("metadata") if isinstance(kwargs.get("metadata"), dict) else {}),
                "timestamp": datetime.utcnow().isoformat(),
                "finding_title": kwargs.get("title"),
            }
        }

        try:
            signal = self.add_signal(**signal_payload)
            if signal is not None:
                signal_id = signal.id
        except Exception:
            signal_id = None

        incoming_signal_ids = kwargs.get("signal_ids")

        if isinstance(incoming_signal_ids, list):
            merged = [sid for sid in incoming_signal_ids if sid is not None]
        elif incoming_signal_ids is None:
            merged = []
        else:
            merged = [incoming_signal_ids]

        if signal_id is not None:
            merged.append(signal_id)

        if merged:
            kwargs["signal_ids"] = sorted(set(merged))

        # V12: Use centralized stable ID generator for total system consistency
        fingerprint = generate_stable_id(kwargs)
        kwargs.setdefault("id_stable", fingerprint)

        self._finding_callback(**kwargs)

        def _inc():
            m = self.results.setdefault("metrics", {})
            m["findings_count"] = m.get("findings_count", 0) + 1

        self.thread_safe_results_update(_inc)

        if kwargs.get("severity") != "info":

            level = (
                "WARNING"
                if kwargs.get("severity") in ["high", "critical"]
                else "INFO"
            )

            self.emit_event(
                "FINDING",
                kwargs.get("tool_source", "engine"),
                level=level,
                data={
                    "title": kwargs.get("title", "Unknown Detection"),
                    "severity": kwargs.get("severity", "info"),
                    "confidence": normalized_conf,
                    "signal_ids": kwargs.get("signal_ids", [])
                }
            )

    def add_loot(self, loot_type, content, context=None):
        """Wrapper to track loot count in metrics"""
        if self._loot_callback:
            loot = self._loot_callback(loot_type, content, context)
            if loot:
                def _inc():
                    m = self.results.setdefault("metrics", {})
                    m["loot_count"] = m.get("loot_count", 0) + 1
                self.thread_safe_results_update(_inc)
            return loot
        return None

    def pause(self):
        with self._control_lock:
            self.control_flags["pause"] = True
            self._pause_event.clear()

    def resume(self):
        with self._control_lock:
            self.control_flags["pause"] = False
            self._pause_event.set()

    def stop(self):
        with self._control_lock:
            self._stop_requested = True
            self.control_flags["stop"] = True
            self._pause_event.set()

    def skip_task(self, task_id):
        with self._control_lock:
            self._skip_tasks.add(task_id)

    def _check_control(self, task_id=None):
        self._pause_event.wait()
        if self._stop_requested:
            raise RuntimeError("scan_stop_requested")
        if task_id and task_id in self._skip_tasks:
            raise RuntimeError(f"task_skipped:{task_id}")

    def _set_task_state(self, task_id, state, reason=None):
        payload = {}

        def _update():
            self.results.setdefault("task_status", {})
            self.results["task_status"][task_id] = {"state": state, "reason": reason}
            self._update_progress()
            payload["task_status"] = dict(self.results.get("task_status", {}))
            payload["progress"] = self.results.get("progress", {"percent": 0.0, "current_phase": "Initializing"})

        self.thread_safe_results_update(_update)
        self._save_results_thread_safe(payload)

    def _update_progress(self):
        task_status = self.results.get("task_status", {})
        total = len(task_status)
        completed_states = {"executed", "skipped", "failed"}
        done = sum(1 for info in task_status.values() if info.get("state") in completed_states)
        percent = float((done / total) * 100.0) if total else 0.0
        # Preserve current_phase if it already exists
        current_progress = self.results.get("progress")
        if isinstance(current_progress, dict):
            current_progress["percent"] = percent
            self.results["progress"] = current_progress
        else:
            self.results["progress"] = {
                "percent": percent,
                "current_phase": "Strategic Analysis" if percent < 100 else "Finalizing"
            }

    def _on_scheduler_progress(self, scheduler):
        payload = {}

        def _update():
            self.results.setdefault("task_status", {})
            task_snapshot = scheduler.snapshot_states()
            for task_id, task_data in task_snapshot.items():
                self.results["task_status"][task_id] = {"state": task_data["state"], "reason": task_data["reason"]}
            self.results.setdefault("metrics", {})
            self.results["metrics"]["tasks_total"] = len(self.results["task_status"])
            completed_states = {"executed", "skipped", "failed"}
            self.results["metrics"]["tasks_done"] = sum(
                1 for info in self.results["task_status"].values() if info.get("state") in completed_states
            )
            self._update_progress()
            payload["task_status"] = dict(self.results.get("task_status", {}))
            payload["progress"] = self.results.get("progress", {"percent": 0.0, "current_phase": "Initializing"})
            payload["metrics"] = dict(self.results.get("metrics", {}))

        self.thread_safe_results_update(_update)
        self._save_results_thread_safe(payload)

    def sync_graph(self):
        """Opportunistic attack graph synchronization to DB"""
        if not self.graph_func:
            return
        try:
            with self._results_lock:
                # Use a snapshot of results
                results_snapshot = json.loads(json.dumps(self.results))
            
            builder = AttackGraphBuilder()
            graph_data = builder.build(results_snapshot)
            nodes = graph_data.get('nodes', [])
            edges = graph_data.get('edges', [])
            if nodes:
                self.graph_func(nodes, edges)
        except Exception:
            # Silent failure for opportunistic sync
            pass

    def _task_wrapper(self, task_id, func, *args, **kwargs):
        from flask import has_app_context
        
        ctx = None
        if not has_app_context():
            # In a thread, we likely lost the context.
            # We recreate it using the app instance if we can find it
            try:
                from app import create_app
                _app = create_app()
                ctx = _app.app_context()
                ctx.push()
            except Exception as e:
                self.log(f"Failed to create app context in thread: {e}", "DEBUG")

        try:
            self._check_control(task_id)
            res = func(*args, **kwargs)
            # Opportunistic sync after major discovery milestones
            if self.graph_func:
                if any(x in task_id for x in ["recon", "dns", "intel", "vuln_", "discover", "strategic"]):
                    self.sync_graph()
            return res
        except Exception as exc:
            reason = str(exc)
            if not reason:
                reason = f"task_failed:{task_id}"
            if not reason.startswith("task_skipped:") and reason != "scan_stop_requested":
                self.log(f"Task {task_id} failed: {reason}", "ERROR")
                self.log(traceback.format_exc(), "DEBUG")
            raise RuntimeError(reason) from exc
        finally:
            if ctx:
                ctx.pop()

    def _build_web_ports(self, open_ports):
        web_ports = []
        for p_info in open_ports or []:
            port = p_info.get('port')
            svc = p_info.get('service', p_info.get('service_name', '')).lower()
            is_web = 'http' in svc or port in [80, 443, 8080, 8443]
            if is_web:
                web_ports.append((port, 'https' if port in [443, 8443] or 'https' in svc or 'ssl' in svc else 'http'))
        return web_ports

    def _init_results(self, start_time):
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": "running",
            "timestamp": start_time.isoformat(),
            "commands": [],
            "modules": {},
            "timeline": [],
            "phases": {
                "recon": {"open_ports": [], "raw_output": ""},
                "dns": {"subdomains": []},
                "intel": {},
                "osint": {"cloud": [], "favicon": {}, "github": [], "emails": [], "dorks": [], "origin_ips": [], "whois": {}},
                "enum": {
                    "whatweb": {}, "katana": {}, "api": {}, "arjun": {}, "headers": {},
                    "js_secrets": {},
                    "targets": {}, "injection_points": {}, "normalized": {}, "derived": {},
                    "seed_meta": {}, "attack_profile": {}, "mutation_strategy": {}
                },
                "vuln": {
                    "nuclei": {"findings": []}, "xss": [], "graphql": [], "git": [], "backups": [],
                    "ssrf": [], "redirects": [], "js_vulns": {}, "wordpress": {}, "tech": {}
                },
                "dirbusting": {}
            },
            "target_info": {},
            "attack_plan": [],
            "task_status": {},
            "progress": 0.0,
            "metrics": {
                "tasks_total": 0,
                "tasks_done": 0,
                "findings_count": 0,
                "loot_count": 0,
                "artifacts_count": 0,
                "duration_seconds": 0.0,
            }
        }

    def run_pipeline(self, profile='quick'):
        success = True
        self._start_time = datetime.utcnow()
        self.options['profile'] = profile
        try:
            self.results = self._init_results(self._start_time)
            self._save_results_thread_safe(overwrite=True)

            scheduler = TaskScheduler()
            scheduler.set_orchestrator(self)
            scheduler.set_progress_callback(self._on_scheduler_progress)
            self._scheduler = scheduler

            def recon_task():
                return run_recon(self) or []

            scheduler.add_task("recon", "phase", [], self._task_wrapper, args=("recon", recon_task))

            def nse_scan_task():
                open_ports = self.results.get("phases", {}).get("recon", {}).get("open_ports", [])
                if not open_ports:
                    self.log("NSE Scanner: Skipping — no open ports.", "DEBUG")
                    return {}
                nse = NSEScanner(self.target, options=self.options)
                nse_results, executed_commands = nse.run_on_ports(open_ports, logger_func=self.log)
                if nse_results:
                    def _store_nse():
                        recon = self.results.setdefault("phases", {}).setdefault("recon", {})
                        recon["nse_results"] = nse_results
                        recon.setdefault("commands_log", []).extend(executed_commands)
                    self.thread_safe_results_update(_store_nse)
                    self.save_results(self.scan_id, self.results)
                    # Surface key findings immediately
                    for port_num, scripts in nse_results.items():
                        for script_name, output in scripts.items():
                            if not output or len(str(output)) < 5:
                                continue
                            severity = "info"
                            if script_name == "ftp-anon" and "allowed" in str(output).lower():
                                severity = "medium"
                            elif script_name == "mysql-empty-password" and "empty" in str(output).lower():
                                severity = "high"
                            elif script_name == "smb-enum-shares" and output:
                                severity = "medium"
                            self.add_finding(
                                title=f"NSE: {script_name} (port {port_num})",
                                description=str(output)[:2000],
                                severity=severity,
                                tool_source="nse_scanner",
                                category="nse_result",
                                repro_command=next((c for c in executed_commands if f"-p {port_num}" in c or f"-p {port_num}," in c or f",{port_num}" in c), "")
                            )
                return nse_results

            scheduler.add_task("nse_scan", "phase", ["recon"], self._task_wrapper, args=("nse_scan", nse_scan_task))
            scheduler.add_task("dns_osint", "phase", [], self._task_wrapper, args=("dns_osint", run_dns_osint, self))
            scheduler.add_task("intel", "phase", ["dns_osint"], self._task_wrapper, args=("intel", run_intel, self))

            def discover_web_ports_task():
                open_ports = self.results.get("phases", {}).get("recon", {}).get("open_ports", [])
                web_ports = self._build_web_ports(open_ports)
                self.log(f"Discovery: Found {len(open_ports)} total ports, {len(web_ports)} web ports.", "DEBUG")
                
                enum_tasks = []
                for port, proto in web_ports:
                    enum_task_id = f"enum_{port}"
                    enum_tasks.append(enum_task_id)
                    scheduler.add_task(
                        enum_task_id,
                        "enum",
                        ["intel", "discover_web_ports"],
                        self._task_wrapper,
                        args=(enum_task_id, run_enum, self, port, proto),
                    )

                # Strategic Intelligence Task (Phase 3)
                # This depends on all discovery tasks and will run before vuln scans
                def strategic_analysis_task():
                    self.log("🧠 Cortex: Initializing Neural Profiling & Logic Engine...", "INFO")
                    
                    def _set_enum_derived(key, value, save=True):
                        def _inner():
                            self.results.setdefault("phases", {}).setdefault("enum", {}).setdefault("derived", {})[key] = value
                        self.thread_safe_results_update(_inner)
                        if save:
                            self._save_results_thread_safe()

                    _set_enum_derived("status", "Analyzing telemetry...")

                    # 1. Profile Intelligence
                    self.log("Cortex: Analyzing service telemetry for advanced signatures...", "DEBUG")
                    adaptive_hints = derive_adaptive_hints(self.results)
                    _set_enum_derived("adaptive_hints", adaptive_hints, save=False)

                    service_intel = derive_service_intel(self.results)
                    _set_enum_derived("service_intelligence", service_intel)
                    self.log(f"Cortex: Derived {len(service_intel)} intelligence tags from telemetry.", "INFO")

                    _set_enum_derived("status", "Evaluating attack vectors...")

                    # 2. Run Cortex Reasoning
                    self.log("Cortex: Evaluating attack surface for strategic vectors...", "DEBUG")
                    cortex_recommendations = suggest_actions(self.results)
                    _set_enum_derived("cortex_recommendations", cortex_recommendations)
                    self.log(f"Cortex: Deducted {len(cortex_recommendations)} strategic recommendations.", "SUCCESS")

                    _set_enum_derived("status", "Expanding environment...")

                    # 3. Expand Surface (Heuristics)
                    self.log("Cortex: Running heuristic surface expansion...", "DEBUG")
                    surface_expansion = derive_surface_expansion(self.results)
                    _set_enum_derived("surface_expansion", surface_expansion)
                    
                    # 4. Global Execution Hints
                    execution_hints = derive_execution_hints(self.results)
                    _set_enum_derived("execution_hints", execution_hints)
                    
                    # 5. Build Attack Plan (Ranking)
                    self.log("Cortex: Finalizing prioritized attack plan...", "DEBUG")
                    _set_enum_derived("status", "Finalizing attack plan...")
                    attack_builder = AttackGraphBuilder()
                    graph_data = attack_builder.build(self.results)
                    self.thread_safe_results_update(lambda: self.results.__setitem__("attack_plan", attack_builder.rank_actions()))
                    
                    # 6. Target Identity Spectre (Full Spectrum)
                    self.log("Cortex: Finalizing Target Identity Spectre...", "DEBUG")
                    spectre = IdentitySpectre.synthesize(self.results)
                    _set_enum_derived("identity_spectre", spectre)
                    
                    if self.graph_func:
                        self.graph_func(graph_data.get('nodes', []), graph_data.get('edges', []))
                    
                    self._save_results_thread_safe()
                    
                    # --- FEEDBACK LOOP: Dynamic Task Injection & Expert Mining ---
                    for rec in cortex_recommendations:
                        # 1. Trigger Deep JS Mining for SPAs
                        if rec.get('category') == 'enum' and 'js-mining' in rec.get('id', ''):
                            target_port = rec.get('port')
                            if not target_port: continue
                            
                            _set_enum_derived("status", f"Mining JS Expert (Port {target_port})...")
                            
                            def _set_js_status(status):
                                self.results.setdefault('phases', {}).setdefault('enum', {})['js_scan_status'] = status
                            self.thread_safe_results_update(lambda: _set_js_status('RUNNING'))
                            self._save_results_thread_safe()

                            self.log(f"🧠 Cortex Decision: SPA detected on port {target_port}. Initiating Hardened JS Expert Scan...", "INFO")
                            
                            # Collect JS URLs from Katana
                            katana_urls = self.results.get('phases', {}).get('enum', {}).get('katana', {}).get(str(target_port), [])
                            js_urls = [u for u in katana_urls if u.endswith('.js')]
                            
                            if js_urls:
                                expert = JSDeepMiningExpert(self.target, options=self.options)
                                # mine_endpoints now returns a structured report with status and findings
                                mining_results = expert.mine_endpoints(js_urls, timeout=60, logger=self.log)
                                
                                # Store mining findings
                                def _store_mining():
                                    enum = self.results.setdefault('phases', {}).setdefault('enum', {})
                                    enum['js_scan_status'] = mining_results['status']
                                    derived = enum.setdefault('derived', {})
                                    js_expert = derived.setdefault('js_expert_mining', {})
                                    js_expert[str(target_port)] = mining_results
                                    
                                    # Merge discovered endpoints into surface expansion
                                    expansion = derived.setdefault('surface_expansion', {})
                                    port_exp = expansion.setdefault('per_port', {}).setdefault(str(target_port), {})
                                    # Use a set to avoid duplicates during multiple saves if mining was chunked (though here it's full)
                                    existing_eps = set(port_exp.get('derived_endpoints', []))
                                    for new_ep in mining_results['discovered_endpoints']:
                                        existing_eps.add(new_ep)
                                    port_exp['derived_endpoints'] = list(existing_eps)
                                    
                                    if 'js_ast_mining' not in port_exp.get('reasons', []):
                                        port_exp.setdefault('reasons', []).append('js_ast_mining')
                                    
                                    # Populate the dedicated JS Secrets UI component
                                    js_secrets_ui = enum.setdefault('js_secrets', {})
                                    port_secrets = js_secrets_ui.setdefault(str(target_port), {})
                                    
                                    for f in mining_results['findings']:
                                        url_secrets = []
                                        for s in f['details']['secrets']:
                                            # Add to general findings
                                            self.add_finding(
                                                title=f"JS Secret: {s['type']}",
                                                description=f"Discovered in {f['source']}\nValue: {s['value']}\nContext: {s['context']}",
                                                severity="high",
                                                tool_source="js_mining_expert"
                                            )
                                            # Add to specialized UI list
                                            url_secrets.append({
                                                "type": s['type'],
                                                "match": s['value'],
                                                "line_context": s['context']
                                            })
                                        if url_secrets:
                                            port_secrets[f['source']] = url_secrets
                                
                                self.thread_safe_results_update(_store_mining)
                                self._save_results_thread_safe() # CRITICAL: Update UI after expert results
                                self.log(f"JS Expert: Mission success. Discovered {len(mining_results['discovered_endpoints'])} hidden endpoints.", "SUCCESS")
                            else:
                                self.log(f"JS Expert: Negative signal on port {target_port} (no JS found).", "DEBUG")

                    _set_enum_derived("status", "Audit Loop Concluded.")
                    self.log(f"Strategic Analysis Complete: Identified {len(cortex_recommendations)} tactical vectors.", "SUCCESS")
                    _set_enum_derived("status", "idle")
                    self._save_results_thread_safe()
                    return True

                scheduler.add_task("strategic_analysis", "intel", enum_tasks or ["discover_web_ports"], self._task_wrapper, args=("strategic_analysis", strategic_analysis_task))

                # Now add VULN tasks depending on strategic analysis
                for port, proto in web_ports:
                    vuln_task_id = f"vuln_{port}"
                    enum_task_id = f"enum_{port}"

                    def vuln_task(port=port, proto=proto, enum_task_id=enum_task_id):
                        snapshot = scheduler.snapshot_states()
                        fingerprint_data = (snapshot.get(enum_task_id) or {}).get("result") or ""
                        return run_vuln_scans(self, port, proto, fingerprint_data=fingerprint_data)

                    scheduler.add_task(
                        vuln_task_id,
                        "vuln",
                        ["strategic_analysis"], # V6 Fix: Depend on strategic analysis, not just enum
                        self._task_wrapper,
                        args=(vuln_task_id, vuln_task),
                    )
                    if "global_vuln" in scheduler.tasks and vuln_task_id not in scheduler.tasks["global_vuln"].deps:
                        scheduler.tasks["global_vuln"].deps.append(vuln_task_id)

                def _recalc_total():
                    self.results.setdefault("metrics", {})
                    self.results["metrics"]["tasks_total"] = len(scheduler.tasks)
                    for task_id in scheduler.tasks:
                        self.results.setdefault("task_status", {})
                        self.results["task_status"].setdefault(task_id, {"state": "pending", "reason": None})
                    self._update_progress()

                self.thread_safe_results_update(_recalc_total)
                self._save_results_thread_safe({"metrics": self.results.get("metrics", {}), "task_status": self.results.get("task_status", {}), "progress": self.results.get("progress", 0.0)})
                return web_ports

            scheduler.add_task("discover_web_ports", "phase", ["recon"], self._task_wrapper, args=("discover_web_ports", discover_web_ports_task))
            scheduler.add_task("global_vuln", "phase", ["discover_web_ports"], self._task_wrapper, args=("global_vuln", run_global_vuln_scans, self)) # Note: global_vuln might need strategic_analysis too if it uses its data
            scheduler.add_task("dirbusting", "phase", ["global_vuln"], self._task_wrapper, args=("dirbusting", run_dirbusting, self))

            def _prime_task_status():
                self.results["metrics"]["tasks_total"] = len(scheduler.tasks)
                for task_id in scheduler.tasks:
                    self.results["task_status"].setdefault(task_id, {"state": "pending", "reason": None})
                self._update_progress()

            self.thread_safe_results_update(_prime_task_status)
            self._save_results_thread_safe({"metrics": self.results["metrics"], "task_status": self.results["task_status"], "progress": self.results["progress"]})

            scheduler.run()

            # The post-run logic is mostly moved into the strategic_analysis_task or kept for final metrics
            safety_warnings = validate_results_schema(self.results)
            def _set_final_derived(key, value):
                self.results.setdefault("phases", {}).setdefault("enum", {}).setdefault("derived", {})[key] = value
            self.thread_safe_results_update(lambda: _set_final_derived("safety_warnings", safety_warnings[:50]))

            # Recalculate findings count from all vuln modules
            total_findings = 0
            vuln_data = self.results.get("phases", {}).get("vuln", {})
            for module, data in vuln_data.items():
                if isinstance(data, list):
                    total_findings += len(data)
                elif isinstance(data, dict):
                    if "findings" in data and isinstance(data["findings"], list):
                        total_findings += len(data["findings"])
                    else:
                        # Some modules like 'wordpress' might have nested vulns
                        if "vulns" in data and isinstance(data["vulns"], list):
                            total_findings += len(data["vulns"])
            
            self.results["metrics"]["findings_count"] = total_findings
            self.results["metrics"]["artifacts_count"] = sum(
                int(item.get("artifacts", 0))
                for module_data in self.results.get("modules", {}).values()
                for item in module_data.values()
                if isinstance(item, dict)
            )

            # 7. Lateral Movement Analysis (Wave 2 Tactical)
            try:
                self.log("🔗 Lateral Path Expert: Analyzing cross-asset pivot potentials...", "INFO")
                lpe = LateralPathExpert(self.scan_id, load_results)
                lateral_findings = lpe.analyze(logger=self.log)
                if lateral_findings:
                    self.thread_safe_results_update(lambda: (
                        self.results.setdefault("phases", {}).setdefault("tactical", {}).__setitem__("lateral_paths", lateral_findings)
                    ))
                    for f in lateral_findings:
                        # Normalize and add as a strategic finding
                        self.add_finding(
                            title=f['title'],
                            description=f['description'],
                            severity=f['severity'],
                            tool_source="lateral_expert",
                            endpoint=f.get('source', '')
                        )
                    self.log(f"🔗 Lateral Path Expert: Identified {len(lateral_findings)} potential pivot vectors.", "SUCCESS")
            except Exception as e:
                self.log(f"Lateral Path Expert Error: {e}", "DEBUG")

            # Final Attack Graph Update (including all findings)
            if self.graph_func:
                final_builder = AttackGraphBuilder()
                final_graph = final_builder.build(self.results)
                self.graph_func(final_graph.get('nodes', []), final_graph.get('edges', []))

            # Wave 4: Cloud Exposure & Token Validation (Precision Intelligence)
            try:
                self.log("☁️ Cloud Storage Expert: Scanning discovered assets for bucket exposure...", "INFO")
                cse = CloudStorageExpert(self.scan_id)
                cloud_findings = cse.scan(self.results, logger=self.log)
                for f in cloud_findings:
                    self.add_finding(**f)
            except Exception as e:
                self.log(f"Cloud Storage Expert Error: {e}", "DEBUG")

            try:
                self.log("🔑 Token Validator: Analyzing findings for actionable secrets...", "INFO")
                # Need consistent findings list
                all_findings_list = []
                # Extract findings from results
                vuln_ph = self.results.get("phases", {}).get("vuln", {})
                for mod, mod_data in vuln_ph.items():
                    if isinstance(mod_data, list): all_findings_list.extend(mod_data)
                    elif isinstance(mod_data, dict) and "findings" in mod_data: all_findings_list.extend(mod_data["findings"])

                tv = TokenValidator(self.scan_id)
                verified_secrets = tv.validate_discovered_secrets(all_findings_list, logger=self.log)
                for vf in verified_secrets:
                    self.add_finding(**vf)
            except Exception as e:
                self.log(f"Token Validator Error: {e}", "DEBUG")

            json.dumps(self.results)
        except Exception as e:
            self.log(f"Pipeline Critical Failure: {e}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
            success = False

        end_time = datetime.utcnow()
        self.results['status'] = "completed" if success else "failed"
        self.results["metrics"]["duration_seconds"] = (end_time - self._start_time).total_seconds()
        self._update_progress()
        self._save_results_thread_safe()
        self.log(f"Scan completed in {end_time - self._start_time}. Status: {self.results['status']}", "SUCCESS")
        return success
