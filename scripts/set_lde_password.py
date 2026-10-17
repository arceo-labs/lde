#!/usr/bin/env python3
"""Write the LDE basic-auth secret and keep the plaintext off the screen.

Run this before terraform plan. It asks for a username and password, writes
~/.lde/basic-auth.json as {"username": "<sha256 hex>"} mode 0600, and writes
the plaintext to ~/.lde/lde-admin.txt mode 0600. Terraform reads the JSON on
the first apply. When lde/basic-auth already exists, the script stores that
JSON with put-secret-value. LDE reads it within a minute.

The browser username is the JSON key. The browser password is the plaintext.
Dependency-Track's first visit is a different login: admin / admin, then the
password Dependency-Track asks you to set.
"""

import argparse
import getpass
import hashlib
import json
import os
import subprocess
import sys

DEFAULT_JSON = os.path.expanduser('~/.lde/basic-auth.json')
DEFAULT_PLAINTEXT = os.path.expanduser('~/.lde/lde-admin.txt')


def _validate_credentials(username, password):
    """Reject characters that break Basic Auth or the two-line plaintext file.

    Basic Auth parsing splits at the first colon, so a username containing ':'
    can never authenticate. Newlines corrupt ~/.lde/lde-admin.txt.
    """
    username = username.strip()
    if username == '':
        raise ValueError('username is empty')
    if password == '':
        raise ValueError('password is empty')
    if ':' in username:
        raise ValueError("username must not contain ':' (Basic Auth splits on the first colon)")
    if '\n' in username or '\r' in username:
        raise ValueError('username must not contain line breaks')
    if '\n' in password or '\r' in password:
        raise ValueError('password must not contain line breaks')
    return username


def credential_document(username, password):
    username = _validate_credentials(username, password)
    digest = hashlib.sha256(password.encode()).hexdigest()
    return json.dumps({username: digest}, separators=(',', ':'))


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


def write_credential_file(path, username, password):
    body = credential_document(username, password)
    _write_0600(path, body)
    return body


def write_plaintext_file(path, username, password):
    username = _validate_credentials(username, password)
    _write_0600(path, f'{username}\n{password}\n')


def secret_exists(secret_id, region):
    result = subprocess.run(
        ['aws', 'secretsmanager', 'describe-secret',
         '--secret-id', secret_id, '--region', region],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return True
    if 'ResourceNotFoundException' in result.stderr:
        return False
    detail = result.stderr.strip() or 'describe-secret failed'
    raise RuntimeError(detail)


def put_secret(secret_id, path, region):
    result = subprocess.run(
        ['aws', 'secretsmanager', 'put-secret-value',
         '--secret-id', secret_id,
         '--secret-string', f'file://{path}',
         '--region', region],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or 'put-secret-value failed'
        raise RuntimeError(detail)


def _password(args):
    env = os.environ.get('LDE_ADMIN_PASSWORD', '')
    if env != '':
        return env
    if not sys.stdin.isatty():
        raise ValueError('Set LDE_ADMIN_PASSWORD, or run this in a terminal.')
    first = getpass.getpass('LDE password: ')
    second = getpass.getpass('LDE password again: ')
    if first != second:
        raise ValueError('passwords do not match')
    return first


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username', default='admin')
    parser.add_argument('--out', default=DEFAULT_JSON)
    parser.add_argument('--plaintext-out', default=DEFAULT_PLAINTEXT)
    parser.add_argument('--secret-id', default='lde/basic-auth')
    parser.add_argument('--region', default=os.environ.get('AWS_REGION', 'us-east-1'))
    parser.add_argument('--no-aws', action='store_true')
    args = parser.parse_args(argv)

    print('This password is for the LDE site only.')
    print('Dependency-Track\'s first visit is username admin, password admin, then the password it asks you to set.')
    username = args.username.strip() or 'admin'
    if sys.stdin.isatty() and os.environ.get('LDE_ADMIN_PASSWORD', '') == '':
        typed = input(f'LDE username [{username}]: ').strip()
        if typed:
            username = typed
    password = _password(args)
    write_credential_file(args.out, username, password)
    write_plaintext_file(args.plaintext_out, username, password)
    print(f'Wrote {args.out}')
    print(f'Wrote {args.plaintext_out}')
    if args.no_aws:
        return 0
    if secret_exists(args.secret_id, args.region):
        put_secret(args.secret_id, args.out, args.region)
        print(f'Updated {args.secret_id}. LDE reads it within a minute.')
    else:
        print(f'{args.secret_id} does not exist yet. Terraform reads {args.out} on the first apply.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, RuntimeError) as exc:
        print(f'set_lde_password: {exc}', file=sys.stderr)
        sys.exit(1)
