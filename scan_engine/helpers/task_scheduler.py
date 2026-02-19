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
        self._lock = threading.Lock()
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
                    task.reason = "stop_requested"
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
                task.state = "failed"
                task.reason = str(exc)
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
                remaining = {task_id for task_id, task in task_snapshot.items() if task.state == "pending"}
            if not remaining:
                break

            ready_queue = []
            for task_id, task in list(task_snapshot.items()):
                if task.state == "pending" and self._deps_ready_snapshot(task, task_snapshot):
                    ready_queue.append(task_id)

            if not ready_queue:
                break

            sequential_ids = [tid for tid in ready_queue if not self._is_parallel_safe(task_snapshot[tid])]
            parallel_ids = [tid for tid in ready_queue if self._is_parallel_safe(task_snapshot[tid])]

            for task_id in sequential_ids:
                if self._stop_requested():
                    break
                self.execute_task(task_id)
                remaining.discard(task_id)

            if parallel_ids and not self._stop_requested():
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(self.execute_task, task_id): task_id for task_id in parallel_ids}
                    for future in as_completed(futures):
                        _ = future.result()
                        remaining.discard(futures[future])

        final_reason = "stop_requested" if self._stop_requested() else "unresolvable_dependencies"
        for task_id, task in list(self.tasks.items()):
            notify_progress = False
            with self._lock:
                if task.state == "pending":
                    task.state = "skipped"
                    task.reason = final_reason
                    notify_progress = True
            if notify_progress:
                self._notify_progress()

        return {task_id: task.result for task_id, task in self.tasks.items()}
