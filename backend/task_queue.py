"""Background task queue — ThreadPoolExecutor with a polling-friendly task table."""

import concurrent.futures
import threading
import time
import traceback
import uuid

_tasks = {}
_tasks_lock = threading.Lock()
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

# Terminal tasks a caller never polled still pin whatever the runner closed
# over (e.g. a ~400 KB extract-packages payload). Drop them after this long.
_TERMINAL_TTL_S = 15 * 60


def _reap_locked(now):
    """Drop terminal tasks older than _TERMINAL_TTL_S. Caller holds _tasks_lock."""
    # finished_at is None for a moment after the status turns terminal (the
    # runner sets it in `finally`); such a task is fresh, so keep it.
    stale = [tid for tid, t in _tasks.items()
             if t['status'] in ('completed', 'failed')
             and t.get('finished_at') is not None
             and now - t['finished_at'] > _TERMINAL_TTL_S]
    for tid in stale:
        _tasks.pop(tid, None)


def submit(fn, *args, **kwargs):
    """Submit *fn* to the pool.

    *fn* receives a `set_stage(stage_name)` callable as its first positional
    argument so it can report progress.

    Returns the task_id (hex string) that the UI polls via /api/tasks/{id}.
    """
    task_id = uuid.uuid4().hex
    task = {'status': 'running', 'stage': 'queued', 'result': None,
            'error': None, 'finished_at': None}
    with _tasks_lock:
        _reap_locked(time.monotonic())
        _tasks[task_id] = task

    def set_stage(stage):
        task['stage'] = stage

    def runner():
        try:
            task['result'] = fn(set_stage, *args, **kwargs)
            task['status'] = 'completed'
        except Exception as exc:
            traceback.print_exc()
            task['error'] = str(exc)
            task['status'] = 'failed'
        finally:
            task['finished_at'] = time.monotonic()

    _executor.submit(runner)
    return task_id


def get(task_id):
    with _tasks_lock:
        return _tasks.get(task_id)


def consume(task_id):
    """Return the task and remove it from the table (terminal states only)."""
    with _tasks_lock:
        return _tasks.pop(task_id, None)
