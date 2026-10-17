"""Static checks for Ingest and Package Search UI markup."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ingest_form_has_no_ort_method_menu():
    text = (ROOT / 'js' / 'runs.js').read_text()
    assert 'method-input' not in text
    assert 'ORT (Docker-based, full manifest analysis)' not in text
    assert "api.createRun(orgs, repos, 'github_sbom'" in text


def test_package_search_does_not_render_fallback_box_up_front():
    text = (ROOT / 'js' / 'package_search.js').read_text()
    template = text.split('// Tab switching')[0]
    assert 'Clipboard unavailable' not in template
    assert 'function showFallbackPromptBox' in text
    assert 'Choose File' not in text
    assert 'class="visually-hidden"' in text
    assert 'type="file"' in text
    assert 'id="panel-url" class="hidden" hidden' in template
    assert 'id="results-card" hidden' in template or 'id="results-card" class="hidden" hidden' in template
    assert 'style.display' not in text


def test_no_inline_style_attributes():
    # CSP style-src 'self' makes the browser ignore style="..."; use css/styles.css.
    files = [ROOT / 'index.html', *sorted((ROOT / 'js').glob('*.js'))]
    offenders = [f.name for f in files if 'style="' in f.read_text()]
    assert offenders == []


def test_upload_accepts_csv_and_json():
    # Package lists exported as CSV or JSON go to Gemini as plain text.
    text = (ROOT / 'js' / 'package_search.js').read_text()
    accept = text.split('id="file-input"')[1].split('accept="')[1].split('"')[0].split(',')
    assert '.csv' in accept and '.json' in accept

