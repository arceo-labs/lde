#!/usr/bin/env python3
"""Bootstrap Dependency-Track: rotate fresh admin password, grant Automation
permissions, create an API key, optionally store it in Secrets Manager.

A fresh Dependency-Track 4.14 install accepts admin/admin once, then returns
HTTP 401 with body FORCE_PASSWORD_CHANGE. The stock Automation team already
has BOM_UPLOAD and VIEW_PORTFOLIO. It does not have PROJECT_CREATION_UPLOAD.
Ingest needs that permission; package search uses VIEW_PORTFOLIO.

Never print the password or the API key. Print only the key's public prefix
(first 8 characters), the key length, the team name, permission names, and
the password / key file paths. The API key is written to --key-out (mode 0600)
when not stored in Secrets Manager.

--password-out defaults to ~/.lde/dtrack-admin.txt, the local instance's
login. When bootstrapping any other instance (for example AWS), pass a
different --password-out, or the local password is overwritten and lost.

Bootstrap also applies COST_SETTINGS. Dependency-Track keeps these in its
database and ignores environment variables for them. --settings-only
re-applies them to an instance that is already bootstrapped, without
touching the password or creating an API key. Task scheduler cadences
take effect at the next Dependency-Track restart.
"""

import argparse
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = 'http://127.0.0.1:8081'
DEFAULT_PASSWORD_OUT = os.path.expanduser('~/.lde/dtrack-admin.txt')
DEFAULT_KEY_OUT = os.path.expanduser('~/.lde/dtrack-api-key.txt')
USERNAME = 'admin'
PERMISSION = 'PROJECT_CREATION_UPLOAD'
TEAM_NAME = 'Automation'

# (group, property, value). See docs/aws-cost-control.md.
# LDE uses Dependency-Track for projects, BOMs and component search only, never
# vulnerabilities. Vulnerability mirroring and analysis are therefore off:
# the NVD mirror alone held Aurora near 3 ACU for hours at a time.
# - Metrics jobs default to hourly; each run pushes Aurora to its maximum ACU.
# - nvd.api.enabled goes back to its default so re-enabling the NVD later
#   does not start a full API catch-up by surprise.
COST_SETTINGS = (
    ('task-scheduler', 'portfolio.metrics.update.cadence', '24'),
    ('task-scheduler', 'vulnerability.metrics.update.cadence', '24'),
    ('vuln-source', 'nvd.enabled', 'false'),
    ('vuln-source', 'nvd.api.enabled', 'false'),
    ('vuln-source', 'epss.enabled', 'false'),
    ('scanner', 'internal.enabled', 'false'),
    ('scanner', 'ossindex.enabled', 'false'),
)


def _write_0600(path, body):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, body.encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def write_password_file(path, username, password):
    _write_0600(path, f'{username}\n{password}\n')


def write_key_file(path, api_key):
    _write_0600(path, f'{api_key}\n')


def generate_password(length=32):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _current_password(args):
    env = os.environ.get('DTRACK_ADMIN_PASSWORD', '')
    if env != '':
        return env
    if args.password_file:
        with open(args.password_file) as fh:
            lines = fh.read().splitlines()
        if len(lines) < 2 or lines[1] == '':
            raise ValueError(f'{args.password_file}: need username on line 1 and password on line 2')
        return lines[1]
    raise ValueError('Set DTRACK_ADMIN_PASSWORD or pass --password-file')


def _request(method, url, path, data=None, token=None, form=False):
    full = url.rstrip('/') + path
    headers = {}
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = json.dumps(data).encode()
            headers['Content-Type'] = 'application/json'
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(full, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return resp.status, raw, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, raw, dict(exc.headers)


def login(url, username, password):
    status, raw, _ = _request(
        'POST', url, '/api/v1/user/login',
        data={'username': username, 'password': password},
        form=True,
    )
    body = raw.decode(errors='replace')
    return status, body


def force_change_password(url, username, old_password, new_password):
    status, raw, _ = _request(
        'POST', url, '/api/v1/user/forceChangePassword',
        data={
            'username': username,
            'password': old_password,
            'newPassword': new_password,
            'confirmPassword': new_password,
        },
        form=True,
    )
    if status != 200:
        detail = raw.decode(errors='replace').strip() or f'HTTP {status}'
        raise RuntimeError(f'forceChangePassword failed: {detail}')


def list_teams(url, token):
    status, raw, _ = _request('GET', url, '/api/v1/team', token=token)
    if status != 200:
        detail = raw.decode(errors='replace').strip() or f'HTTP {status}'
        raise RuntimeError(f'list teams failed: {detail}')
    return json.loads(raw.decode())


def grant_permission(url, token, team_uuid, permission):
    path = f'/api/v1/permission/{permission}/team/{team_uuid}'
    status, raw, _ = _request('POST', url, path, token=token)
    if status in (200, 304):
        return status
    detail = raw.decode(errors='replace').strip() or f'HTTP {status}'
    raise RuntimeError(f'grant {permission} failed: {detail}')


def create_api_key(url, token, team_uuid):
    path = f'/api/v1/team/{team_uuid}/key'
    status, raw, _ = _request('PUT', url, path, token=token)
    if status not in (200, 201):
        detail = raw.decode(errors='replace').strip() or f'HTTP {status}'
        raise RuntimeError(f'create API key failed: {detail}')
    return json.loads(raw.decode())


def apply_settings(url, token, settings=COST_SETTINGS):
    items = [
        {'groupName': g, 'propertyName': p, 'propertyValue': v}
        for g, p, v in settings
    ]
    status, raw, _ = _request(
        'POST', url, '/api/v1/configProperty/aggregate', data=items, token=token,
    )
    if status != 200:
        detail = raw.decode(errors='replace').strip() or f'HTTP {status}'
        raise RuntimeError(f'update config properties failed: {detail}')
    for g, p, v in settings:
        print(f'setting: {g}/{p} = {v}')


def apply_settings_only(url, username, password):
    status, body = login(url, username, password)
    if status == 401 and body.strip() == 'FORCE_PASSWORD_CHANGE':
        raise RuntimeError(
            'instance still has the default admin password; run the full bootstrap first'
        )
    if status != 200:
        raise RuntimeError(f'login failed: HTTP {status}: {body.strip()}')
    apply_settings(url, body.strip())
    return 0


def put_secret(secret_id, value, region):
    """Store the API key via Secrets Manager without putting it on argv.

    Writes a mode-0600 temp file and passes --secret-string file://{path},
    matching scripts/set_lde_password.py. Unlinks the file even on failure.
    """
    fd, path = tempfile.mkstemp(prefix='lde-dtrack-key-')
    os.close(fd)
    try:
        _write_0600(path, value)
        result = subprocess.run(
            ['aws', 'secretsmanager', 'put-secret-value',
             '--secret-id', secret_id,
             '--secret-string', f'file://{path}',
             '--region', region],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or 'put-secret-value failed'
            raise RuntimeError(detail)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def find_team(teams, name):
    for team in teams:
        if team.get('name') == name:
            return team
    raise RuntimeError(f'team {name!r} not found')


def permission_names(team):
    perms = team.get('permissions') or []
    names = []
    for p in perms:
        if isinstance(p, dict):
            n = p.get('name')
            if n:
                names.append(n)
        elif isinstance(p, str):
            names.append(p)
    return names


def key_public_prefix(api_key_obj, key_value):
    public_id = (api_key_obj or {}).get('publicId') or ''
    if public_id:
        return public_id[:8]
    return (key_value or '')[:8]


def bootstrap(url, username, current_password, password_out, secret_id=None,
              region='us-east-1', no_aws=False, key_out=None):
    status, body = login(url, username, current_password)
    password_for_file = current_password
    if status == 401 and body.strip() == 'FORCE_PASSWORD_CHANGE':
        new_password = generate_password()
        # Persist first so a lost response cannot leave an unknown admin password.
        write_password_file(password_out, username, new_password)
        password_for_file = new_password
        try:
            force_change_password(url, username, current_password, new_password)
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f'forceChangePassword transport failed ({exc}). '
                f'The remote password may already be the value in {password_out}. '
                f'Retry with DTRACK_ADMIN_PASSWORD from that file; do not reuse admin/admin.'
            ) from exc
        except RuntimeError as exc:
            raise RuntimeError(
                f'{exc}. Remote password was not changed. '
                f'{password_out} holds a generated password that was not applied; '
                f'retry with the previous password (usually admin).'
            ) from exc
        status, body = login(url, username, new_password)
        if status != 200:
            raise RuntimeError(
                f'login after password change failed: HTTP {status}. '
                f'Password file: {password_out}'
            )
        token = body.strip()
    elif status == 401:
        raise RuntimeError(
            f'login rejected (HTTP 401): {body.strip() or "UNAUTHORIZED"}. '
            'Password was already changed; not rotating it.'
        )
    elif status != 200:
        raise RuntimeError(f'login failed: HTTP {status}: {body.strip()}')
    else:
        token = body.strip()
        write_password_file(password_out, username, password_for_file)

    teams = list_teams(url, token)
    team = find_team(teams, TEAM_NAME)
    team_uuid = team['uuid']
    grant_permission(url, token, team_uuid, PERMISSION)
    # Refresh team so printed permissions include the grant.
    teams = list_teams(url, token)
    team = find_team(teams, TEAM_NAME)
    api_key_obj = create_api_key(url, token, team_uuid)
    key_value = api_key_obj.get('key') or ''
    if not key_value:
        raise RuntimeError('API key response missing key field')

    store_aws = bool(secret_id) and not no_aws
    if store_aws:
        put_secret(secret_id, key_value, region)
    else:
        if not key_out:
            raise RuntimeError(
                'No destination for the API key. Pass --secret-id for Secrets Manager, '
                'or --key-out for a mode-0600 local file (default ~/.lde/dtrack-api-key.txt).'
            )
        write_key_file(key_out, key_value)

    try:
        apply_settings(url, token)
    except (RuntimeError, urllib.error.URLError) as exc:
        raise RuntimeError(
            f'{exc}. The password and API key are saved. Re-apply the settings with '
            f'--password-file {password_out} --settings-only'
        ) from exc

    perms = permission_names(team)
    prefix = key_public_prefix(api_key_obj, key_value)
    print(f'team: {team.get("name")}')
    print(f'permissions: {", ".join(perms)}')
    print(f'key prefix: {prefix}')
    print(f'key length: {len(key_value)}')
    print(f'password file: {password_out}')
    if store_aws:
        print(f'stored in {secret_id}. LDE reads it within a minute.')
    else:
        print(f'key file: {key_out}')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default=DEFAULT_URL)
    parser.add_argument('--password-file', default='')
    parser.add_argument('--password-out', default=DEFAULT_PASSWORD_OUT)
    parser.add_argument(
        '--key-out', default=DEFAULT_KEY_OUT,
        help='Mode-0600 file for the API key when not using --secret-id '
             '(default: ~/.lde/dtrack-api-key.txt). Never printed.',
    )
    parser.add_argument('--secret-id', default='')
    parser.add_argument('--region', default=os.environ.get('AWS_REGION', 'us-east-1'))
    parser.add_argument('--no-aws', action='store_true')
    parser.add_argument('--username', default=USERNAME)
    parser.add_argument(
        '--settings-only', action='store_true',
        help='Only apply COST_SETTINGS to an already-bootstrapped instance. '
             'Writes no files and creates no API key.',
    )
    args = parser.parse_args(argv)

    password = _current_password(args)
    if args.settings_only:
        return apply_settings_only(args.url, args.username.strip() or USERNAME, password)
    secret_id = args.secret_id or None
    return bootstrap(
        url=args.url,
        username=args.username.strip() or USERNAME,
        current_password=password,
        password_out=args.password_out,
        secret_id=secret_id,
        region=args.region,
        no_aws=args.no_aws,
        key_out=args.key_out or None,
    )


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError) as exc:
        print(f'bootstrap_dtrack: {exc}', file=sys.stderr)
        sys.exit(1)
