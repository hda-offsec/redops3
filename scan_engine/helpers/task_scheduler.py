import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Task:
    task_id: str
    kind: str
    deps: list[str] = field(default_factory=list)
    callable: Callable[..., Any] = None
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    state: str = "pending"
    reason: str | None = None
    result: Any = None


class TaskScheduler:
    def __init__(self):
        self.tasks: dict[str, Task] = {}
        self._lock = threading.RLock()
        self._orchestrator = None
        self._progress_callback = None

    def set_orchestrator(self, orchestrator):
        self._orchestrator = orchestrator

    def set_progress_callback(self, callback):
        self._progress_callback = callback

    def add_task(self, task_id, kind, deps, callable, args=None, kwargs=None):
        with self._lock:
            self.tasks[task_id] = Task(
                task_id=task_id,
                kind=kind,
                deps=list(deps or []),
                callable=callable,
                args=tuple(args or ()),
                kwargs=dict(kwargs or {}),
            )

    def _deps_ready(self, task: Task):
        return all(self.tasks[dep].state in {"executed", "skipped"} for dep in task.deps)

    def _deps_ready_snapshot(self, task: Task, task_snapshot: dict[str, Task]):
        return all(task_snapshot[dep].state in {"executed", "skipped"} for dep in task.deps)

    def _wait_if_paused(self):
        while self._orchestrator and self._orchestrator.control_flags.get("pause", False):
            time.sleep(0.2)

    def _stop_requested(self):
        return bool(self._orchestrator and self._orchestrator.control_flags.get("stop", False))

    def _notify_progress(self):
        if self._progress_callback:
            self._progress_callback(self)

    def _is_parallel_safe(self, task: Task):
        if task.kind not in {"enum", "vuln"}:
            return False
        return task.task_id.startswith("enum_") or task.task_id.startswith("vuln_")

    def execute_task(self, task_id):
        self._wait_if_paused()
        if self._stop_requested():
            notify_progress = False
            with self._lock:
                task = self.tasks[task_id]
                if task.state == "pending":
                    task.state = "skipped"
                    task.reason = "scan_stop_requested"
                    notify_progress = True
            if notify_progress:
                self._notify_progress()
            return None

        notify_progress = False
        with self._lock:
            task = self.tasks[task_id]
            if task.state in {"executed", "failed", "skipped"}:
                return task.result
            if not self._deps_ready(task):
                unmet = [dep for dep in task.deps if self.tasks[dep].state not in {"executed", "skipped"}]
                task.state = "skipped"
                task.reason = f"dependencies_not_ready:{','.join(unmet)}"
                notify_progress = True
            else:
                task.state = "running"
                task.reason = None

        if notify_progress:
            self._notify_progress()
            return None

        try:
            result = task.callable(*task.args, **task.kwargs)
            with self._lock:
                task.result = result
                task.state = "executed"
            return result
        except Exception as exc:
            with self._lock:
                reason = str(exc) or f"task_failed:{task_id}"
                if reason.startswith("task_skipped:"):
                    task.state = "skipped"
                elif reason == "scan_stop_requested":
                    task.state = "skipped"
                else:
                    task.state = "failed"
                task.reason = reason
                task.result = None
            return None
        finally:
            self._notify_progress()

    def run(self):
        max_workers = 4

        while True:
            self._wait_if_paused()
            if self._stop_requested():
                break

            with self._lock:
                task_snapshot = dict(self.tasks)
            
            pending_ids = [tid for tid, t in task_snapshot.items() if t.state == "pending"]
            running_ids = [tid for tid, t in task_snapshot.items() if t.state == "running"]

            if not pending_ids and not running_ids:
                break

            ready_queue = []
            for task_id, task in list(task_snapshot.items()):
                if task.state == "pending" and self._deps_ready_snapshot(task, task_snapshot):
                    ready_queue.append(task_id)

            if not ready_queue:
                if running_ids:
                    time.sleep(0.5)
                    continue
                else:
                    if pending_ids:
                        msg = f"Scheduler breaking with {len(pending_ids)} pending tasks but none ready. Unmet dependencies: "
                        for tid in pending_ids[:5]:
                            task = task_snapshot[tid]
                            unmet = [d for d in task.deps if task_snapshot.get(d) and task_snapshot[d].state not in {"executed", "skipped"}]
                            msg += f"[{tid} needs {unmet}] "
                        if self._orchestrator: self._orchestrator.log(msg, "DEBUG")
                    break

            adaptive_hints = {}
            if self._orchestrator:
                adaptive_hints = (
                    self._orchestrator.results.get("phases", {})
                    .get("enum", {})
                    .get("derived", {})
                    .get("adaptive_hints", {})
                )

            ready_queue.sort(
                key=lambda tid: adaptive_hints.get(tid, {}).get("priority_boost", 0),
                reverse=True,
            )

            sequential_ids = [tid for tid in ready_queue if not self._is_parallel_safe(task_snapshot[tid])]
            parallel_ids = [tid for tid in ready_queue if self._is_parallel_safe(task_snapshot[tid])]

            for task_id in sequential_ids:
                if self._stop_requested():
                    break
                self.execute_task(task_id)

            if parallel_ids and not self._stop_requested():
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(self.execute_task, task_id): task_id for task_id in parallel_ids}
                    for future in as_completed(futures):
                        _ = future.result()

        skipped_count = 0
        for task_id, task in list(self.tasks.items()):
            notify_progress = False
            with self._lock:
                if task.state == "pending":
                    if self._stop_requested():
                        reason = "scan_stop_requested"
                    else:
                        unmet = [dep for dep in task.deps if self.tasks.get(dep) and self.tasks[dep].state not in {"executed", "skipped"}]
                        reason = f"dependencies_not_ready:{','.join(unmet)}" if unmet else "dependencies_not_ready:unresolvable_dependencies"
                    task.state = "skipped"
                    task.reason = reason
                    notify_progress = True
                    skipped_count += 1
            if notify_progress:
                self._notify_progress()
        
        if skipped_count > 0 and self._orchestrator:
            self._orchestrator.log(f"Scheduler finished. {skipped_count} tasks were skipped.", "DEBUG")

        return {task_id: task.result for task_id, task in self.tasks.items()}

    def snapshot_states(self):
        with self._lock:
            return {
                task_id: {"state": task.state, "reason": task.reason, "result": task.result}
                for task_id, task in self.tasks.items()
            }
