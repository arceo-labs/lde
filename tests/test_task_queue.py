"""Terminal tasks nobody polled are dropped after _TERMINAL_TTL_S."""

import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import task_queue  # noqa: E402


@pytest.fixture(autouse=True)
def empty_table(monkeypatch):
    monkeypatch.setattr(task_queue, '_tasks', {})


def _task(status, finished_at):
    return {'status': status, 'stage': 'x', 'result': None, 'error': None, 'finished_at': finished_at}


def test_reap_drops_only_stale_terminal_tasks():
    ttl = task_queue._TERMINAL_TTL_S
    now = 10_000.0
    task_queue._tasks.update({
        'old-done': _task('completed', now - ttl - 1),
        'old-failed': _task('failed', now - ttl - 1),
        'fresh-done': _task('completed', now - 5),
        'running': _task('running', None),
        'old-running': _task('running', None),
    })
    with task_queue._tasks_lock:
        task_queue._reap_locked(now)
    assert set(task_queue._tasks) == {'fresh-done', 'running', 'old-running'}


def test_terminal_task_without_finished_at_is_kept_not_crashed():
    # The status turns terminal before the runner's `finally` sets finished_at.
    task_queue._tasks['just-finished'] = _task('completed', None)
    with task_queue._tasks_lock:
        task_queue._reap_locked(10_000.0)
    assert 'just-finished' in task_queue._tasks


def _wait_done(task_id):
    for _ in range(200):
        t = task_queue.get(task_id)
        if t and t['status'] != 'running' and t['finished_at'] is not None:
            return t
        threading.Event().wait(0.01)
    raise AssertionError('task did not finish')


def test_finished_at_is_set_on_success_and_failure():
    ok = _wait_done(task_queue.submit(lambda set_stage: 'result'))
    assert ok['status'] == 'completed' and ok['result'] == 'result'
    assert isinstance(ok['finished_at'], float)

    def boom(set_stage):
        raise ValueError('nope')

    bad = _wait_done(task_queue.submit(boom))
    assert bad['status'] == 'failed' and bad['error'] == 'nope'
    assert isinstance(bad['finished_at'], float)


def test_submit_reaps_stale_tasks(monkeypatch):
    task_queue._tasks['stale'] = _task('completed', 0.0)
    monkeypatch.setattr(task_queue.time, 'monotonic', lambda: task_queue._TERMINAL_TTL_S + 100.0)
    task_queue.submit(lambda set_stage: None)
    assert 'stale' not in task_queue._tasks
