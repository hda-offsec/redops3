import json
import threading
import traceback
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
from scan_engine.helpers.task_scheduler import TaskScheduler

from scan_engine.phases.dirbusting import run_dirbusting
from scan_engine.phases.enum import run_enum
from scan_engine.phases.intel import run_intel
from scan_engine.phases.recon import run_dns_osint, run_recon

try:
    from scan_engine.phases.vuln import run_global_vuln_scans, run_vuln_scans
except Exception:
    def run_global_vuln_scans(*args, **kwargs):
        raise RuntimeError("vuln_phase_import_unavailable")

    def run_vuln_scans(*args, **kwargs):
        raise RuntimeError("vuln_phase_import_unavailable")


class ScanOrchestrator:

    def __init__(
        self,
        scan_id,
        target,
        logger_func,
        finding_func,
        suggestion_func,
        results_func,
        loot_func=None,
        recursion_func=None,
        options=None,
        **kwargs
    ):
        self.scan_id = scan_id
        self.target = target
        self.log = logger_func
        self._finding_callback = finding_func
        self.add_suggestion = suggestion_func
        self.save_results = results_func
        self._loot_callback = loot_func
        self._signal_callback = kwargs.get("signal_func")
        self.graph_func = kwargs.get("graph_func")
        self.recursion_func = recursion_func
        self.options = options or {}
        self.config = self.options.get("config", {})
        self.results = {'commands': []}

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
            self.results.setdefault("timeline", [])
            self.results["timeline"].append(evt)
            payload["timeline"] = list(self.results["timeline"])

        self.thread_safe_results_update(_update)

        self.socketio.emit(
            "pipeline_event",
            evt,
            room=f"scan_{self.scan_id}"
        )

        self._save_results_thread_safe(payload)
        return evt

    def mark_module(self, module, port, status, artifacts=0, reason=None):

        payload = {}

        def _update_module():
            self.results.setdefault("modules", {})
            self.results["modules"].setdefault(module, {})

            normalized_reason = (
                reason if reason is not None
                else ("" if status == "executed" else "no_reason_provided")
            )

            self.results["modules"][module][str(port)] = {
                "status": status,
                "artifacts": int(artifacts),
                "reason": normalized_reason
            }

            payload["modules"] = dict(self.results["modules"])
            return normalized_reason

        normalized_reason = self.thread_safe_results_update(_update_module)

        self.socketio.emit(
            "module_status",
            {
                "module": module,
                "port": str(port),
                "status": status,
                "artifacts": artifacts,
                "reason": normalized_reason
            },
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

        self.emit_event(
            evt_type,
            module,
            port,
            level=level,
            data={"artifacts": artifacts, "reason": normalized_reason}
        )

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

        normalized_conf = str(kwargs.get("confidence", "medium")).strip().lower()

        if normalized_conf not in {"low", "medium", "high"}:
            normalized_conf = "medium"

        kwargs["confidence"] = normalized_conf

        signal_id = None

        evidence_value = kwargs.get("evidence")
        if isinstance(evidence_value, (dict, list)):
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

        import hashlib
        from urllib.parse import urlparse

        endpoint_seed = kwargs.get("endpoint") or kwargs.get("target") or kwargs.get("url") or ""
        try:
            parsed = urlparse(str(endpoint_seed))
            endpoint_fingerprint = parsed.geturl() or parsed.path or "/"
        except Exception:
            endpoint_fingerprint = str(endpoint_seed)

        fp_seed = (
            str(kwargs.get("title", "")) + "|"
            + endpoint_fingerprint + "|"
            + str(kwargs.get("parameter", "")) + "|"
            + str(kwargs.get("payload", "")) + "|"
            + str(kwargs.get("severity", "")) + "|"
            + str(kwargs.get("tool_source", kwargs.get("tool", "")))
        )

        fingerprint = hashlib.sha256(fp_seed.encode()).hexdigest()

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

        if not self._loot_callback:
            return None

        loot = self._loot_callback(loot_type, content, context)

        if loot:
            def _inc():
                m = self.results.setdefault("metrics", {})
                m["loot_count"] = m.get("loot_count", 0) + 1
            self.thread_safe_results_update(_inc)

        return loot

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

    def _build_web_ports(self, open_ports):

        web_ports = []

        for p_info in open_ports or []:

            port = p_info.get("port")

            svc = p_info.get(
                "service",
                p_info.get("service_name", "")
            ).lower()

            is_web = "http" in svc or port in [80, 443, 8080, 8443]

            if is_web:

                proto = (
                    "https"
                    if port in [443, 8443] or "https" in svc or "ssl" in svc
                    else "http"
                )

                web_ports.append((port, proto))

        return web_ports

    def run_pipeline(self, profile="quick"):

        success = True
        self._start_time = datetime.utcnow()

        try:

            scheduler = TaskScheduler()
            scheduler.set_orchestrator(self)

            scheduler.add_task(
                "recon",
                "phase",
                [],
                lambda: run_recon(self)
            )

            scheduler.add_task(
                "dns_osint",
                "phase",
                ["recon"],
                lambda: run_dns_osint(self)
            )

            scheduler.add_task(
                "intel",
                "phase",
                ["dns_osint"],
                lambda: run_intel(self)
            )

            scheduler.run()

        except Exception as e:

            self.log(
                f"Pipeline Critical Failure: {e}",
                "ERROR"
            )

            self.log(
                traceback.format_exc(),
                "DEBUG"
            )

            success = False

        end_time = datetime.utcnow()

        self.results["status"] = (
            "completed" if success else "failed"
        )

        self.results.setdefault("metrics", {})

        self.results["metrics"]["duration_seconds"] = (
            end_time - self._start_time
        ).total_seconds()

        self._save_results_thread_safe()

        self.log(
            f"Scan completed in {end_time - self._start_time}. "
            f"Status: {self.results['status']}",
            "SUCCESS"
        )

        return success
