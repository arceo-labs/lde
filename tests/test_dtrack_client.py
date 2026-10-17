"""Unit tests for backend/dtrack_client.py.

Focus on the safe_upload_bom guards because they are the regression we
just shipped: the original upload_bom would let a partial-resolution
re-run replace a healthy DT project with a zero-component BOM,
silently nuking every component until the next successful run.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import dtrack_client  # noqa: E402


# ---------------------------------------------------------------------------
# _bom_component_count
# ---------------------------------------------------------------------------

def test_bom_component_count_reads_components_array(tmp_path):
    bom = tmp_path / 'bom.json'
    bom.write_text(json.dumps({
        'bomFormat': 'CycloneDX',
        'components': [
            {'name': 'a', 'version': '1'},
            {'name': 'b', 'version': '2'},
            {'name': 'c', 'version': '3'},
        ],
    }))
    assert dtrack_client._bom_component_count(str(bom)) == 3


def test_bom_component_count_zero_for_empty_array(tmp_path):
    bom = tmp_path / 'bom.json'
    bom.write_text(json.dumps({'components': []}))
    assert dtrack_client._bom_component_count(str(bom)) == 0


def test_bom_component_count_zero_when_components_key_missing(tmp_path):
    bom = tmp_path / 'bom.json'
    bom.write_text(json.dumps({'bomFormat': 'CycloneDX'}))
    assert dtrack_client._bom_component_count(str(bom)) == 0


def test_bom_component_count_returns_none_for_invalid_json(tmp_path):
    bom = tmp_path / 'bom.json'
    bom.write_text('not { valid }')
    assert dtrack_client._bom_component_count(str(bom)) is None


# ---------------------------------------------------------------------------
# safe_upload_bom — empty-BOM guard
# ---------------------------------------------------------------------------

def _make_bom(tmp_path, components):
    bom = tmp_path / 'bom.json'
    bom.write_text(json.dumps({'components': components}))
    return str(bom)


def test_safe_upload_bom_refuses_empty_when_dt_has_components(tmp_path, monkeypatch):
    """Crucial guard: an empty BOM must NOT clobber a healthy DT project.

    Pre-fix, a transient resolution failure on a re-run would silently
    nuke every component in DT until the next successful run.
    """
    bom_path = _make_bom(tmp_path, [])  # zero components

    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 50)
    # If the guard fails to fire, _do_upload raises this assertion.
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: pytest.fail('upload should not have been attempted'))
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    with pytest.raises(dtrack_client.DtrackOverwriteRefused) as exc:
        dtrack_client.safe_upload_bom(
            'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert 'Refusing to upload empty BOM' in str(exc.value)
    assert '50 component' in str(exc.value)


def test_safe_upload_bom_force_env_overrides_empty_guard(tmp_path, monkeypatch):
    bom_path = _make_bom(tmp_path, [])

    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 50)
    upload_called = {}
    def _fake_upload(*args, **kwargs):
        upload_called['args'] = args
        upload_called['kwargs'] = kwargs
        return {'token': 't', 'new_component_count': 0,
                'prior_component_count': 50, 'regression_warning': None}
    monkeypatch.setattr(dtrack_client, '_do_upload', _fake_upload)
    monkeypatch.setenv('LDE_FORCE_BOM_OVERWRITE', '1')

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert upload_called, 'upload was not invoked despite force flag'
    assert result['token'] == 't'


def test_safe_upload_bom_force_kwarg_overrides_empty_guard(tmp_path, monkeypatch):
    bom_path = _make_bom(tmp_path, [])
    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 50)
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: {'token': 't', 'new_component_count': 0,
                                         'prior_component_count': 50,
                                         'regression_warning': None})
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path, force=True)
    assert result['token'] == 't'


def test_safe_upload_bom_allows_empty_when_dt_project_does_not_exist(tmp_path, monkeypatch):
    """First-time uploads of a no-deps repo are legitimate."""
    bom_path = _make_bom(tmp_path, [])
    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: None)
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: {'token': 't', 'new_component_count': 0,
                                         'prior_component_count': None,
                                         'regression_warning': None})
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert result['token'] == 't'
    assert result['prior_component_count'] is None


def test_safe_upload_bom_allows_empty_when_prior_was_also_empty(tmp_path, monkeypatch):
    bom_path = _make_bom(tmp_path, [])
    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 0)
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: {'token': 't', 'new_component_count': 0,
                                         'prior_component_count': 0,
                                         'regression_warning': None})
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert result['token'] == 't'


# ---------------------------------------------------------------------------
# safe_upload_bom — regression guard
# ---------------------------------------------------------------------------

def test_safe_upload_bom_regression_warning_when_dropped_more_than_half(tmp_path, monkeypatch):
    """A 60% drop should still upload but flag the regression."""
    bom_path = _make_bom(tmp_path, [{'name': 'a'} for _ in range(40)])

    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 100)
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: {'token': 't', 'new_component_count': k['new_count'],
                                         'prior_component_count': k['prior_count'],
                                         'regression_warning': k.get('regression_warning')})
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert result['regression_warning'] is not None
    assert '40' in result['regression_warning']
    assert '100' in result['regression_warning']


def test_safe_upload_bom_no_regression_warning_when_drop_is_minor(tmp_path, monkeypatch):
    """Routine churn (e.g. dropping a few deps) shouldn't trigger the warning."""
    bom_path = _make_bom(tmp_path, [{'name': 'a'} for _ in range(80)])

    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 100)
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: {'token': 't', 'new_component_count': k['new_count'],
                                         'prior_component_count': k['prior_count'],
                                         'regression_warning': k.get('regression_warning')})
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert result['regression_warning'] is None


def test_safe_upload_bom_skips_regression_check_for_small_priors(tmp_path, monkeypatch):
    """Tiny prior counts (≤10) are too noisy for a regression heuristic.

    A repo dropping from 5 → 1 is unlikely to be a transient resolution
    failure; it's almost always a legit dep removal. We don't want to
    cry wolf for those.
    """
    bom_path = _make_bom(tmp_path, [{'name': 'a'}])

    monkeypatch.setattr(dtrack_client, 'lookup_project',
                        lambda *args, **kwargs: 'fake-uuid')
    monkeypatch.setattr(dtrack_client, 'project_component_count',
                        lambda *args, **kwargs: 5)
    monkeypatch.setattr(dtrack_client, '_do_upload',
                        lambda *a, **k: {'token': 't', 'new_component_count': k['new_count'],
                                         'prior_component_count': k['prior_count'],
                                         'regression_warning': k.get('regression_warning')})
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)

    result = dtrack_client.safe_upload_bom(
        'http://dt', 'k', 'org/repo', 'main', bom_path)
    assert result['regression_warning'] is None


def test_safe_upload_bom_propagates_missing_bom_error(tmp_path, monkeypatch):
    monkeypatch.delenv('LDE_FORCE_BOM_OVERWRITE', raising=False)
    with pytest.raises(dtrack_client.DtrackError) as exc:
        dtrack_client.safe_upload_bom(
            'http://dt', 'k', 'org/repo', 'main', str(tmp_path / 'absent.json'))
    assert 'BOM not found' in str(exc.value)


# ---------------------------------------------------------------------------
# poll_bom_processing
# ---------------------------------------------------------------------------

def test_poll_bom_processing_returns_true_immediately_when_no_token():
    assert dtrack_client.poll_bom_processing('http://dt', 'k', None) is True
    assert dtrack_client.poll_bom_processing('http://dt', 'k', '') is True


def test_poll_bom_processing_returns_true_on_first_done_response(monkeypatch):
    calls = []

    def fake_request(method, base_url, path, api_key):
        calls.append(path)
        return {'processing': False}

    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    result = dtrack_client.poll_bom_processing('http://dt', 'k', 'tok-1')
    assert result is True
    assert len(calls) == 1


def test_poll_bom_processing_retries_until_done(monkeypatch):
    responses = [{'processing': True}, {'processing': True}, {'processing': False}]
    calls = []

    def fake_request(method, base_url, path, api_key):
        calls.append(1)
        return responses[len(calls) - 1]

    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    monkeypatch.setattr(dtrack_client.time, 'sleep', lambda _: None)
    result = dtrack_client.poll_bom_processing('http://dt', 'k', 'tok-2', timeout=30)
    assert result is True
    assert len(calls) == 3


def test_poll_bom_processing_returns_true_on_404(monkeypatch):
    """404 on the token endpoint means DT already discarded the token — treat as done."""
    def fake_request(method, base_url, path, api_key):
        raise dtrack_client.DtrackError('GET /api/v1/bom/token/x → HTTP 404: not found')

    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    result = dtrack_client.poll_bom_processing('http://dt', 'k', 'tok-3')
    assert result is True


def test_poll_bom_processing_returns_false_on_timeout(monkeypatch):
    import time as _time

    def fake_request(method, base_url, path, api_key):
        return {'processing': True}

    # Make monotonic() advance past the deadline immediately on the second call.
    _calls = []
    _real_mono = _time.monotonic

    def fake_mono():
        _calls.append(1)
        # First call sets the deadline; after that, always return deadline+1.
        return 0.0 if len(_calls) == 1 else 100.0

    monkeypatch.setattr(dtrack_client, '_request', fake_request)
    monkeypatch.setattr(dtrack_client.time, 'monotonic', fake_mono)
    monkeypatch.setattr(dtrack_client.time, 'sleep', lambda _: None)
    result = dtrack_client.poll_bom_processing('http://dt', 'k', 'tok-4', timeout=15)
    assert result is False
