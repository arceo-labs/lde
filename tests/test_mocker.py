import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import mocker  # noqa: E402


def test_npmrc_written_next_to_package_json(tmp_path):
    (tmp_path / 'package.json').write_text('{}')
    mocker.mock(str(tmp_path), {'package.json'})
    npmrc = tmp_path / '.npmrc'
    assert npmrc.exists()
    assert 'legacy-peer-deps=true' in npmrc.read_text()


def test_npmrc_written_for_nested_package_json(tmp_path):
    sub = tmp_path / 'packages' / 'core'
    sub.mkdir(parents=True)
    (sub / 'package.json').write_text('{}')
    mocker.mock(str(tmp_path), {'package.json'})
    assert 'legacy-peer-deps=true' in (sub / '.npmrc').read_text()


def test_npmrc_not_written_without_package_json(tmp_path):
    (tmp_path / 'requirements.txt').write_text('requests\n')
    mocker.mock(str(tmp_path), {'requirements.txt'})
    assert not (tmp_path / '.npmrc').exists()


def test_npmrc_not_overwritten_when_setting_already_present(tmp_path):
    (tmp_path / 'package.json').write_text('{}')
    existing = 'registry=https://custom.example.com\nlegacy-peer-deps=true\n'
    (tmp_path / '.npmrc').write_text(existing)
    mocker.mock(str(tmp_path), {'package.json'})
    assert (tmp_path / '.npmrc').read_text() == existing


def test_npmrc_setting_appended_to_existing_without_it(tmp_path):
    (tmp_path / 'package.json').write_text('{}')
    existing = 'registry=https://custom.example.com\n'
    (tmp_path / '.npmrc').write_text(existing)
    mocker.mock(str(tmp_path), {'package.json'})
    content = (tmp_path / '.npmrc').read_text()
    assert 'registry=https://custom.example.com' in content
    assert 'legacy-peer-deps=true' in content


def test_npmrc_skips_node_modules(tmp_path):
    nm = tmp_path / 'node_modules' / 'some-pkg'
    nm.mkdir(parents=True)
    (nm / 'package.json').write_text('{}')
    mocker.mock(str(tmp_path), set())
    assert not (nm / '.npmrc').exists()
