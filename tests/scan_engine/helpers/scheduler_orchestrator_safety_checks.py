import threading

from scan_engine.helpers.task_scheduler import TaskScheduler
from scan_engine.orchestrator import ScanOrchestrator


def _build_orchestrator():
    store = {}

    def logger(*_args, **_kwargs):
        return None

    def noop(*_args, **_kwargs):
        return None

    def save_results(scan_id, payload, overwrite=False):
        store[scan_id] = payload

    orch = ScanOrchestrator(
        scan_id="t1",
        target="example.com",
        logger_func=logger,
        finding_func=noop,
        suggestion_func=noop,
        results_func=save_results,
    )
    return orch


def test_scheduler_failed_task_and_dependency_skip_projection():
    scheduler = TaskScheduler()
    statuses = []
    scheduler.set_progress_callback(lambda s: statuses.append(s.snapshot_states()))

    scheduler.add_task("enum_80", "enum", [], lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    scheduler.add_task("vuln_80", "vuln", ["enum_80"], lambda: "should_not_run")

    scheduler.run()
    snapshot = scheduler.snapshot_states()

    assert snapshot["enum_80"]["state"] == "failed"
    assert snapshot["enum_80"]["reason"] == "boom"
    assert snapshot["vuln_80"]["state"] == "skipped"
    assert snapshot["vuln_80"]["reason"] == "dependencies_not_ready:enum_80"
    assert statuses, "progress callback should reflect scheduler state transitions"


def test_scheduler_parallel_execution_thread_safe():
    scheduler = TaskScheduler()
    counter = {"value": 0}
    lock = threading.Lock()

    def work():
        with lock:
            counter["value"] += 1
        return counter["value"]

    scheduler.add_task("enum_80", "enum", [], work)
    scheduler.add_task("enum_443", "enum", [], work)
    scheduler.run()
    snapshot = scheduler.snapshot_states()

    assert counter["value"] == 2
    assert snapshot["enum_80"]["state"] == "executed"
    assert snapshot["enum_443"]["state"] == "executed"


def test_orchestrator_wires_enum_fingerprint_into_vuln(monkeypatch):
    orch = _build_orchestrator()
    captured = {"fingerprint": None}

    def fake_recon(_orch):
        _orch.results.setdefault("phases", {}).setdefault("recon", {})["open_ports"] = [{"port": 80, "service": "http"}]
        return _orch.results["phases"]["recon"]["open_ports"]

    monkeypatch.setattr("scan_engine.orchestrator.run_recon", fake_recon)
    monkeypatch.setattr("scan_engine.orchestrator.run_dns_osint", lambda _orch: None)
    monkeypatch.setattr("scan_engine.orchestrator.run_intel", lambda _orch: None)
    monkeypatch.setattr("scan_engine.orchestrator.run_enum", lambda _orch, _port, _proto: "fp-data")

    def fake_vuln(_orch, _port, _proto, fingerprint_data=""):
        captured["fingerprint"] = fingerprint_data
        return True

    monkeypatch.setattr("scan_engine.orchestrator.run_vuln_scans", fake_vuln)
    monkeypatch.setattr("scan_engine.orchestrator.run_global_vuln_scans", lambda _orch: True)
    monkeypatch.setattr("scan_engine.orchestrator.run_dirbusting", lambda _orch: True)
    monkeypatch.setattr("scan_engine.orchestrator.validate_results_schema", lambda _results: [])

    assert orch.run_pipeline(profile="quick") is True
    assert captured["fingerprint"] == "fp-data"
