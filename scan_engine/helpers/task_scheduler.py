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

    def add_task(self, task_id, kind, deps, callable, args=None, kwargs=None):
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

    def execute_task(self, task_id):
        task = self.tasks[task_id]
        if task.state in {"executed", "failed", "skipped"}:
            return task.result
        if not self._deps_ready(task):
            unmet = [dep for dep in task.deps if self.tasks[dep].state not in {"executed", "skipped"}]
            task.state = "skipped"
            task.reason = f"dependencies_not_ready:{','.join(unmet)}"
            return None
        task.state = "running"
        try:
            task.result = task.callable(*task.args, **task.kwargs)
            task.state = "executed"
        except Exception as exc:
            task.state = "failed"
            task.reason = str(exc)
            task.result = None
        return task.result

    def run(self):
        remaining = set(self.tasks.keys())
        progress = True
        while remaining and progress:
            progress = False
            for task_id in list(remaining):
                task = self.tasks[task_id]
                if self._deps_ready(task):
                    self.execute_task(task_id)
                    remaining.remove(task_id)
                    progress = True
        for task_id in remaining:
            task = self.tasks[task_id]
            task.state = "skipped"
            task.reason = "unresolvable_dependencies"
        return {task_id: task.result for task_id, task in self.tasks.items()}
