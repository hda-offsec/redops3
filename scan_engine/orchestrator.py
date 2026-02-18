import json
import threading
import traceback
from datetime import datetime

from core.extensions import get_socketio
from scan_engine.helpers.attack_graph import AttackGraphBuilder
from scan_engine.helpers.task_scheduler import TaskScheduler
from scan_engine.phases.dirbusting import run_dirbusting
from scan_engine.phases.enum import run_enum
from scan_engine.phases.intel import run_intel
from scan_engine.phases.recon import run_dns_osint, run_recon
from scan_engine.phases.vuln import run_global_vuln_scans, run_vuln_scans


class ScanOrchestrator:
    def __init__(self, scan_id, target, logger_func, finding_func, suggestion_func, results_func, loot_func=None, recursion_func=None, options=None):
        self.scan_id = scan_id
        self.target = target
        self.log = logger_func
        self.add_finding = finding_func
        self.add_suggestion = suggestion_func
        self.save_results = results_func
        self.add_loot = loot_func
        self.recursion_func = recursion_func
        self.options = options or {}
        self.config = self.options.get('config', {})
        self.results = {}
        self._results_lock = threading.Lock()
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

    def emit_event(self, event_type, module, port=None, level="INFO", data=None):
        evt = {
            "ts": datetime.utcnow().isoformat(),
            "type": event_type,
            "module": module,
            "port": str(port) if port is not None else None,
            "level": level,
            "data": data or {}
        }

        def _update():
            if 'timeline' not in self.results:
                self.results['timeline'] = []
            self.results["timeline"].append(evt)

        self.thread_safe_results_update(_update)
        self.socketio.emit("pipeline_event", evt, room=f"scan_{self.scan_id}")
        self.save_results(self.scan_id, {"timeline": self.results.get("timeline", [])})
        return evt

    def mark_module(self, module, port, status, artifacts=0, reason=None):
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
        self.save_results(self.scan_id, {"modules": self.results.get("modules", {})})

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
        def _update():
            self.results.setdefault("task_status", {})
            self.results["task_status"][task_id] = {"state": state, "reason": reason}
            self._update_progress()

        self.thread_safe_results_update(_update)
        self.save_results(self.scan_id, {"task_status": self.results.get("task_status", {}), "progress": self.results.get("progress", 0.0)})

    def _update_progress(self):
        task_status = self.results.get("task_status", {})
        total = len(task_status)
        completed_states = {"executed", "skipped", "failed"}
        done = sum(1 for info in task_status.values() if info.get("state") in completed_states)
        self.results["progress"] = float((done / total) * 100.0) if total else 0.0

    def _on_scheduler_progress(self, scheduler):
        def _update():
            self.results.setdefault("task_status", {})
            for task_id, task in scheduler.tasks.items():
                self.results["task_status"][task_id] = {"state": task.state, "reason": task.reason}
            self._update_progress()

        self.thread_safe_results_update(_update)
        self.save_results(self.scan_id, {"task_status": self.results.get("task_status", {}), "progress": self.results.get("progress", 0.0)})

    def _task_wrapper(self, task_id, func, *args, **kwargs):
        self._check_control(task_id)
        self._set_task_state(task_id, "running", None)
        try:
            ret = func(*args, **kwargs)

            def _update_success():
                self.results.setdefault("metrics", {})
                self.results["metrics"]["tasks_done"] = int(self.results["metrics"].get("tasks_done", 0)) + 1

            self.thread_safe_results_update(_update_success)
            self._set_task_state(task_id, "executed", None)
            return ret
        except Exception as exc:
            reason = str(exc)

            def _update_error():
                self.results.setdefault("metrics", {})
                self.results["metrics"]["tasks_done"] = int(self.results["metrics"].get("tasks_done", 0)) + 1

            self.thread_safe_results_update(_update_error)

            if reason.startswith("task_skipped:"):
                self._set_task_state(task_id, "skipped", reason)
                return None

            self._set_task_state(task_id, "failed", reason)
            self.log(f"Task {task_id} failed: {reason}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
            return None

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
                "osint": {"cloud": [], "favicon": {}, "github": [], "emails": [], "dorks": [], "origin_ips": []},
                "enum": {
                    "whatweb": {}, "katana": {}, "api": {}, "arjun": {}, "headers": {},
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
            self.save_results(self.scan_id, self.results, overwrite=True)

            scheduler = TaskScheduler()
            scheduler.set_orchestrator(self)
            scheduler.set_progress_callback(self._on_scheduler_progress)
            self._scheduler = scheduler

            def recon_task():
                return run_recon(self) or []

            scheduler.add_task("recon", "phase", [], self._task_wrapper, args=("recon", recon_task))
            scheduler.add_task("dns_osint", "phase", ["recon"], self._task_wrapper, args=("dns_osint", run_dns_osint, self))
            scheduler.add_task("intel", "phase", ["dns_osint"], self._task_wrapper, args=("intel", run_intel, self))

            def discover_web_ports_task():
                open_ports = self.results.get("phases", {}).get("recon", {}).get("open_ports", [])
                web_ports = self._build_web_ports(open_ports)
                for port, proto in web_ports:
                    enum_task_id = f"enum_{port}"
                    vuln_task_id = f"vuln_{port}"
                    scheduler.add_task(
                        enum_task_id,
                        "enum",
                        ["intel", "discover_web_ports"],
                        self._task_wrapper,
                        args=(enum_task_id, run_enum, self, port, proto),
                    )
                    scheduler.add_task(
                        vuln_task_id,
                        "vuln",
                        [enum_task_id],
                        self._task_wrapper,
                        args=(vuln_task_id, run_vuln_scans, self, port, proto),
                        kwargs={"fingerprint_data": ""},
                    )
                    if "global_vuln" in scheduler.tasks:
                        scheduler.tasks["global_vuln"].deps.append(vuln_task_id)

                def _recalc_total():
                    self.results.setdefault("metrics", {})
                    self.results["metrics"]["tasks_total"] = len(scheduler.tasks)
                    for task_id in scheduler.tasks:
                        self.results.setdefault("task_status", {})
                        self.results["task_status"].setdefault(task_id, {"state": "pending", "reason": None})
                    self._update_progress()

                self.thread_safe_results_update(_recalc_total)
                self.save_results(self.scan_id, {"metrics": self.results.get("metrics", {}), "task_status": self.results.get("task_status", {}), "progress": self.results.get("progress", 0.0)})
                return web_ports

            scheduler.add_task("discover_web_ports", "phase", ["recon"], self._task_wrapper, args=("discover_web_ports", discover_web_ports_task))
            scheduler.add_task("global_vuln", "phase", ["discover_web_ports"], self._task_wrapper, args=("global_vuln", run_global_vuln_scans, self))
            scheduler.add_task("dirbusting", "phase", ["global_vuln"], self._task_wrapper, args=("dirbusting", run_dirbusting, self))

            def _prime_task_status():
                self.results["metrics"]["tasks_total"] = len(scheduler.tasks)
                for task_id in scheduler.tasks:
                    self.results["task_status"].setdefault(task_id, {"state": "pending", "reason": None})
                self._update_progress()

            self.thread_safe_results_update(_prime_task_status)
            self.save_results(self.scan_id, {"metrics": self.results["metrics"], "task_status": self.results["task_status"], "progress": self.results["progress"]})

            scheduler.run()

            attack_builder = AttackGraphBuilder()
            attack_builder.build(self.results)
            self.results["attack_plan"] = attack_builder.rank_actions()

            self.results["metrics"]["findings_count"] = len(self.results.get("phases", {}).get("vuln", {}).get("nuclei", {}).get("findings", []))
            self.results["metrics"]["artifacts_count"] = sum(
                int(item.get("artifacts", 0))
                for module_data in self.results.get("modules", {}).values()
                for item in module_data.values()
                if isinstance(item, dict)
            )

            json.dumps(self.results)
        except Exception as e:
            self.log(f"Pipeline Critical Failure: {e}", "ERROR")
            self.log(traceback.format_exc(), "DEBUG")
            success = False

        end_time = datetime.utcnow()
        self.results['status'] = "completed" if success else "failed"
        self.results["metrics"]["duration_seconds"] = (end_time - self._start_time).total_seconds()
        self._update_progress()
        self.save_results(self.scan_id, self.results)
        self.log(f"Scan completed in {end_time - self._start_time}. Status: {self.results['status']}", "SUCCESS")
        return success
