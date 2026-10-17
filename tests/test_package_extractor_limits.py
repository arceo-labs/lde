"""Input cap, output shape and usage logging for the Gemini package extractor."""

import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import package_extractor  # noqa: E402


class _FakeResp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _gemini_reply(items, usage=None):
    body = {'candidates': [{'finishReason': 'STOP',
                            'content': {'parts': [{'text': json.dumps(items)}]}}]}
    if usage:
        body['usageMetadata'] = usage
    return json.dumps(body).encode()


def test_cap_text_keeps_text_under_limit():
    text = 'x' * 60_000  # longer than the old 50k cap
    assert package_extractor._cap_text(text) == (text, False)


def test_cap_text_truncates_over_limit():
    limit = package_extractor._MAX_TEXT_CHARS
    capped, truncated = package_extractor._cap_text('y' * (limit + 10))
    assert truncated
    assert capped.startswith('y' * limit)
    assert 'Content truncated' in capped
    assert len(capped) < limit + 100


def test_html_to_text_is_not_capped():
    html = '<p>' + 'z' * 120_000 + '</p>'
    assert len(package_extractor._html_to_text(html)) == 120_000


def test_prompt_no_longer_asks_for_context():
    assert '"context"' not in package_extractor._SYSTEM_PROMPT


def test_call_gemini_returns_name_and_ecosystem_only(monkeypatch):
    reply = _gemini_reply([{'name': '@antv/g2', 'ecosystem': 'npm', 'context': 'ignored'}])
    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen',
                        lambda req, timeout=None: _FakeResp(reply))
    assert package_extractor._call_gemini('text', 'fake-key') == [
        {'name': '@antv/g2', 'ecosystem': 'npm'}]


def test_usage_is_logged_without_the_key(monkeypatch, caplog):
    reply = _gemini_reply([], usage={'promptTokenCount': 1234,
                                     'candidatesTokenCount': 56,
                                     'thoughtsTokenCount': 7})
    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen',
                        lambda req, timeout=None: _FakeResp(reply))
    with caplog.at_level(logging.INFO, logger=package_extractor.logger.name):
        package_extractor._call_gemini('text', 'secret-key-value')
    log = caplog.text
    assert 'promptTokens=1234' in log and 'outputTokens=56' in log and 'thoughtsTokens=7' in log
    assert 'finishReason=STOP' in log
    assert 'secret-key-value' not in log


def test_run_from_text_sends_long_text_untruncated(monkeypatch):
    sent = {}

    def fake_call(text, key, model=None):
        sent['text'] = text
        return []

    monkeypatch.setattr(package_extractor, '_extract_packages', fake_call)
    body = 'pkg\n' * 30_000  # 120k chars
    package_extractor.run_from_text(lambda s: None, body, 'list.txt', 'k')
    assert sent['text'] == body


def test_run_from_text_sends_csv_as_plain_text(monkeypatch):
    sent = {}
    monkeypatch.setattr(package_extractor, '_call_gemini',
                        lambda text, key, model=None: sent.setdefault('text', text) and [])
    csv = 'package,version\n@antv/g2,5.1.0\n@antv/g2,5.1.1\n'
    package_extractor.run_from_text(lambda s: None, csv, '22-packages.csv', 'k')
    assert sent['text'] == csv.rstrip('\n')  # blank lines are dropped


# --- chunked extraction -----------------------------------------------------

def test_short_text_is_one_chunk():
    text = '\n'.join(f'line{i}' for i in range(package_extractor._CHUNK_THRESHOLD_LINES))
    assert package_extractor._split_chunks(text) == [text]


def test_long_text_splits_and_repeats_first_line():
    lines = ['Ecosystem,Namespace,Name'] + [f'npm,antv,pkg{i}' for i in range(400)]
    chunks = package_extractor._split_chunks('\n'.join(lines))
    size = package_extractor._CHUNK_LINES
    assert len(chunks) == -(-len(lines) // size)
    assert all(c.split('\n')[0] == lines[0] for c in chunks)
    # Dropping the repeated header from chunks 2..n rebuilds the input exactly.
    rebuilt = chunks[0].split('\n') + [l for c in chunks[1:] for l in c.split('\n')[1:]]
    assert rebuilt == lines


def test_extract_packages_merges_in_order_without_duplicates(monkeypatch):
    calls = []

    def fake_call(text, key, model=None, part=None):
        calls.append(part)
        k = part[0]
        return [{'name': f'@antv/p{k}', 'ecosystem': 'npm'},
                {'name': '@antv/shared', 'ecosystem': 'npm'},
                {'name': '@ANTV/Shared', 'ecosystem': 'npm'}]

    monkeypatch.setattr(package_extractor, '_call_gemini', fake_call)
    text = '\n'.join(['header'] + ['row'] * 400)
    result = package_extractor._extract_packages(text, 'k')
    n = len(package_extractor._split_chunks(text))
    assert sorted(calls) == [(i, n) for i in range(1, n + 1)]
    assert [r['name'] for r in result] == ['@antv/p1', '@antv/shared'] + [f'@antv/p{i}' for i in range(2, n + 1)]


def test_extract_packages_short_text_makes_one_plain_call(monkeypatch):
    calls = []
    monkeypatch.setattr(package_extractor, '_call_gemini',
                        lambda text, key, model=None, part=None: calls.append(part) or [])
    package_extractor._extract_packages('one line', 'k')
    assert calls == [None]


def test_extract_packages_fails_if_any_chunk_fails(monkeypatch):
    def fake_call(text, key, model=None, part=None):
        if part[0] == 2:
            raise ValueError('Gemini API error 429')
        return [{'name': f'p{part[0]}', 'ecosystem': 'npm'}]

    monkeypatch.setattr(package_extractor, '_call_gemini', fake_call)
    import pytest
    with pytest.raises(ValueError, match='429'):
        package_extractor._extract_packages('\n'.join(['h'] + ['r'] * 400), 'k')


def test_part_prompt_mentions_position(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured['payload'] = json.loads(req.data.decode())
        return _FakeResp(_gemini_reply([]))

    monkeypatch.setattr(package_extractor.urllib.request, 'urlopen', fake_urlopen)
    package_extractor._call_gemini('rows', 'k', part=(2, 7))
    prompt = captured['payload']['contents'][0]['parts'][0]['text']
    assert 'part 2 of 7' in prompt and prompt.endswith('rows\n')



# --- fan-out bounds -----------------------------------------------------------

def test_blank_lines_are_dropped_before_chunking():
    # 400k newlines used to become ~2,667 chunks.
    assert package_extractor._split_chunks('\n' * 399_999) == []
    assert package_extractor._split_chunks('pkg\n' + '\n' * 10_000 + 'other') == ['pkg\nother']


def test_too_many_chunks_is_rejected_before_any_call(monkeypatch):
    calls = []
    monkeypatch.setattr(package_extractor, '_call_gemini',
                        lambda *a, **k: calls.append(1) or [])
    lines = package_extractor._MAX_CHUNKS * package_extractor._CHUNK_LINES + 1
    text = '\n'.join(f'pkg{i}' for i in range(lines))
    with pytest.raises(ValueError, match='Package list too long'):
        package_extractor._extract_packages(text, 'k')
    assert calls == []


def test_repeated_header_is_capped():
    head = 'h' * 200_000
    chunks = package_extractor._split_chunks('\n'.join([head] + [f'r{i}' for i in range(400)]))
    assert len(chunks[0].split('\n')[0]) == 200_000          # first chunk keeps the real line
    assert all(len(c.split('\n')[0]) == package_extractor._CHUNK_HEAD_CHARS for c in chunks[1:])


def test_first_failure_cancels_queued_chunks(monkeypatch):
    import threading
    started, gate = [], threading.Event()

    def fake_call(text, key, model=None, part=None):
        started.append(part[0])
        if part[0] == 1:
            raise ValueError('Gemini API error 429')
        gate.wait(2)  # keep the other workers busy so later chunks stay queued
        return []

    monkeypatch.setattr(package_extractor, '_call_gemini', fake_call)
    text = '\n'.join(['h'] + ['r'] * 2_000)   # 14 chunks, 4 workers
    with pytest.raises(ValueError, match='429'):
        package_extractor._extract_packages(text, 'k')
    gate.set()
    total = len(package_extractor._split_chunks(text))
    # The failing chunk's worker may pick up one more before the cancel lands.
    assert len(started) <= package_extractor._CHUNK_WORKERS + 1 < total


def test_deadline_stops_the_extraction(monkeypatch):
    import threading
    gate = threading.Event()
    monkeypatch.setattr(package_extractor, '_EXTRACT_DEADLINE_S', 0.2)
    monkeypatch.setattr(package_extractor, '_call_gemini',
                        lambda *a, **k: gate.wait(2) and [])
    with pytest.raises(ValueError, match='did not finish within'):
        package_extractor._extract_packages('\n'.join(['h'] + ['r'] * 400), 'k')
    gate.set()
