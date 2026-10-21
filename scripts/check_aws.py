#!/usr/bin/env python3
"""Read-only checks for the AWS deployment in docs/aws-deployment.md.

preflight  Run before terraform plan or apply: identity, config files, state,
           resources left from an earlier stack, the ECS cluster, certificates,
           the ALB allowlist and the lde_image tag.
verify     Run after apply and after Step 4/5: ECS services, target health,
           DNS, the lde/* secrets, and LDE and Dependency-Track over HTTPS.

Changes nothing in AWS, Terraform state or DNS. Secrets are read inside this
process and reported by shape only (length, prefix, placeholder, whitespace).
Every line starts OK, WARN or FAIL; the exit code is 1 when any line is FAIL.
"""

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request

SERVE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TF_DIR = os.path.join(SERVE_DIR, 'terraform')
BASIC_AUTH_FILE = os.path.expanduser('~/.lde/basic-auth.json')
LDE_LOGIN_FILE = os.path.expanduser('~/.lde/lde-admin.txt')
DOC = 'docs/aws-deployment.md'
CALL_TIMEOUT = 60

# Secret name -> Terraform address of the secret shell.
SECRETS = {
    'lde/basic-auth': 'aws_secretsmanager_secret.basic_auth',
    'lde/github-pat': 'aws_secretsmanager_secret.github_pat',
    'lde/dtrack-api-key': 'aws_secretsmanager_secret.dtrack_api_key',
    'lde/gemini-api-key': 'aws_secretsmanager_secret.gemini_api_key',
}
PLACEHOLDER = 'REPLACE_ME'


class Report:
    def __init__(self):
        self.lines = []
        self.failed = False

    def _emit(self, level, msg):
        line = f'{level:<4} {msg}'
        self.lines.append(line)
        print(line, flush=True)

    def ok(self, msg):
        self._emit('OK', msg)

    def warn(self, msg):
        self._emit('WARN', msg)

    def fail(self, msg):
        self.failed = True
        self._emit('FAIL', msg)


# ---------------------------------------------------------------------------
# Runners (replaced by fakes in tests)
# ---------------------------------------------------------------------------

def make_aws(region):
    """Return aws(*args) -> (returncode, parsed JSON or None, stderr)."""
    def aws(*args):
        cmd = ['aws', *args, '--region', region, '--output', 'json']
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=CALL_TIMEOUT)
        except subprocess.TimeoutExpired:
            return 124, None, f'timed out after {CALL_TIMEOUT}s'
        try:
            out = json.loads(p.stdout) if p.stdout.strip() else None
        except ValueError:
            out = None
        return p.returncode, out, p.stderr.strip()
    return aws


def terraform(*args):
    p = subprocess.run(['terraform', f'-chdir={TF_DIR}', *args],
                       capture_output=True, text=True, timeout=CALL_TIMEOUT)
    return p.returncode, p.stdout, p.stderr.strip()


def resolve(name):
    """Return [canonical name, *addresses] for name, or None."""
    try:
        canonical, _, addrs = socket.gethostbyname_ex(name)
    except OSError:
        return None
    return [canonical, *addrs]


def public_ip():
    with urllib.request.urlopen('https://checkip.amazonaws.com', timeout=10) as r:
        return r.read().decode().strip()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_ASSIGN = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')


def _strip_comment(line):
    out, in_str = [], False
    for i, ch in enumerate(line):
        if ch == '"' and (i == 0 or line[i - 1] != '\\'):
            in_str = not in_str
        if not in_str and (ch == '#' or line[i:i + 2] == '//'):
            break
        out.append(ch)
    return ''.join(out).strip()


def _value(text):
    text = text.strip().rstrip(',')
    if text.startswith('['):
        return re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    if text.startswith('"'):
        return text[1:text.rindex('"')]
    if text in ('true', 'false'):
        return text == 'true'
    try:
        return float(text) if '.' in text else int(text)
    except ValueError:
        return text


def parse_tfvars(text):
    """Parse the flat terraform.tfvars this module uses: scalars and string lists."""
    values, key, buf = {}, None, []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line:
            continue
        if key is not None:
            buf.append(line)
            if line.endswith(']'):
                values[key] = _value(' '.join(buf))
                key, buf = None, []
            continue
        m = _ASSIGN.match(line)
        if not m:
            continue
        name, rest = m.groups()
        if rest.startswith('[') and not rest.endswith(']'):
            key, buf = name, [rest]
        else:
            values[name] = _value(rest)
    return values


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_identity(report, aws):
    rc, out, err = aws('sts', 'get-caller-identity')
    if rc != 0 or not out:
        report.fail(f'AWS credentials: {(err or "no identity").rstrip(".")}. Set AWS_PROFILE ({DOC}, Prerequisites).')
        return None
    arn = out.get('Arn', '')
    if arn.endswith(':root'):
        report.warn(f'AWS identity is the root user of account {out.get("Account")}. '
                    'Prefer an IAM role or user profile.')
    else:
        report.ok(f'AWS identity {arn}')
    return out.get('Account')


def check_files(report):
    for path, fix in (
        (os.path.join(TF_DIR, 'terraform.tfvars'), 'cp terraform.tfvars.example terraform.tfvars'),
        (os.path.join(TF_DIR, 'backend.hcl'), f'see {DOC}, One-time Terraform state bootstrap'),
        (BASIC_AUTH_FILE, 'python3 scripts/set_lde_password.py'),
    ):
        if os.path.exists(path):
            report.ok(f'{os.path.relpath(path, SERVE_DIR) if path.startswith(SERVE_DIR) else path} exists')
        else:
            report.fail(f'{path} is missing: {fix}')


def check_allowlist(report, tfvars, ip):
    if tfvars.get('alb_internal', True):
        report.ok('ALB is internal; allowlist applies to VPN or office ranges')
        return
    blocks = tfvars.get('alb_ingress_cidr_blocks') or []
    addr = ipaddress.ip_address(ip)
    if any(addr in ipaddress.ip_network(b, strict=False) for b in blocks):
        report.ok(f'public IP {ip} is in alb_ingress_cidr_blocks')
    else:
        report.fail(f'public IP {ip} is outside alb_ingress_cidr_blocks {blocks}: '
                    f'set it as "{ip}/32" in terraform.tfvars and apply')


def check_state(report):
    rc, out, err = terraform('state', 'list')
    if rc != 0:
        report.fail(f'terraform state list failed: {err.splitlines()[-1] if err else rc}. '
                    'Run terraform init -backend-config=backend.hcl')
        return None
    state = {line.strip() for line in out.splitlines() if line.strip()}
    report.ok(f'Terraform state holds {len(state)} resource(s)')
    return state


def check_leftovers(report, aws, prefix, state):
    """FAIL for named resources that exist in AWS but not in Terraform state."""
    probes = [
        ('aws_lb.main', 'load balancer',
         ('elbv2', 'describe-load-balancers', '--names', prefix), 'LoadBalancers'),
        ('module.aurora_postgresql.aws_rds_cluster.this[0]', 'Aurora cluster',
         ('rds', 'describe-db-clusters', '--db-cluster-identifier', f'{prefix}-dtrack'), 'DBClusters'),
        ('aws_ecr_repository.lde', 'ECR repository',
         ('ecr', 'describe-repositories', '--repository-names', prefix), 'repositories'),
    ]
    clean = True
    for address, label, args, key in probes:
        rc, out, _ = aws(*args)
        if rc == 0 and out and out.get(key) and address not in state:
            clean = False
            report.fail(f'{label} {args[-1]} exists but is not in Terraform state: '
                        f'left from an earlier stack. Finish {DOC}, Teardown.')

    rc, out, _ = aws('secretsmanager', 'list-secrets', '--include-planned-deletion')
    for s in (out or {}).get('SecretList', []) if rc == 0 else []:
        name = s.get('Name')
        if name not in SECRETS:
            continue
        if s.get('DeletedDate'):
            clean = False
            report.fail(f'secret {name} is scheduled for deletion and still holds the name: '
                        f'force-delete it ({DOC}, Teardown step 6)')
        elif SECRETS[name] not in state:
            clean = False
            report.fail(f'secret {name} exists but is not in Terraform state: '
                        f'left from an earlier stack ({DOC}, Teardown step 6)')

    snap = f'{prefix}-dtrack-final'
    rc, out, _ = aws('rds', 'describe-db-cluster-snapshots', '--db-cluster-snapshot-identifier', snap)
    if rc == 0 and out and out.get('DBClusterSnapshots'):
        report.warn(f'snapshot {snap} exists: the next terraform destroy fails until it is deleted '
                    f'({DOC}, Teardown step 5)')
    if clean:
        report.ok('no resources left from an earlier stack')


def check_cluster(report, aws, name):
    rc, out, err = aws('ecs', 'describe-clusters', '--clusters', name)
    clusters = (out or {}).get('clusters') or []
    status = clusters[0].get('status') if clusters else 'MISSING'
    if status == 'ACTIVE':
        report.ok(f'ECS cluster {name} is ACTIVE')
    else:
        report.fail(f'ECS cluster {name} is {status}: create it ({DOC}, Step 3)')


def check_certs(report, aws, arns, domains):
    if not arns:
        report.ok('no listener_certificate_arns: Terraform requests the certificate')
        return
    names = set()
    for arn in arns:
        rc, out, err = aws('acm', 'describe-certificate', '--certificate-arn', arn)
        cert = (out or {}).get('Certificate') or {}
        if rc != 0 or not cert:
            report.fail(f'certificate {arn} not found: {err}')
            continue
        names.add(cert.get('DomainName'))
        names.update(cert.get('SubjectAlternativeNames') or [])
        if cert.get('Status') != 'ISSUED':
            report.fail(f'certificate {cert.get("DomainName")} is {cert.get("Status")}, not ISSUED')
        else:
            report.ok(f'certificate {cert.get("DomainName")} ISSUED, expires {cert.get("NotAfter")}')
    for d in domains:
        wild = '*.' + d.split('.', 1)[-1]
        if d not in names and wild not in names:
            report.fail(f'no listener certificate covers {d}')


def check_image(report, aws, image):
    if not image or ':' not in image.rsplit('/', 1)[-1]:
        report.warn('lde_image is unset: the task uses the ECR repository :latest tag')
        return
    repo_part, tag = image.rsplit(':', 1)
    repo = repo_part.rsplit('/', 1)[-1]
    rc, out, _ = aws('ecr', 'describe-images', '--repository-name', repo, '--image-ids', f'imageTag={tag}')
    if rc == 0 and out and out.get('imageDetails'):
        report.ok(f'lde_image {repo}:{tag} is in ECR')
    else:
        report.fail(f'lde_image {repo}:{tag} is not in ECR: build and push it ({DOC}, Step 2)')


def check_services(report, aws, cluster, prefix):
    names = [prefix, f'{prefix}-dtrack-api', f'{prefix}-dtrack-frontend']
    rc, out, err = aws('ecs', 'describe-services', '--cluster', cluster, '--services', *names)
    found = {s['serviceName']: s for s in (out or {}).get('services', [])}
    for name in names:
        s = found.get(name)
        if not s or s.get('status') != 'ACTIVE':
            report.fail(f'ECS service {name} is missing')
            continue
        running, desired = s.get('runningCount'), s.get('desiredCount')
        primary = (s.get('deployments') or [{}])[0]
        rollout = primary.get('rolloutState')
        if running == desired and rollout == 'COMPLETED':
            report.ok(f'ECS service {name}: {running}/{desired} running')
        elif rollout == 'IN_PROGRESS' and primary.get('runningCount') == desired:
            # The new tasks are up; the old ones are still draining.
            report.warn(f'ECS service {name}: new task running, rollout IN_PROGRESS while '
                        'the old task drains. Rerun verify in about 5 minutes.')
        else:
            event = (s.get('events') or [{}])[0].get('message', '')
            report.fail(f'ECS service {name}: {running}/{desired} running, rollout {rollout}. '
                        f'Latest event: {event}')


def check_running_image(report, aws, cluster, prefix, expected):
    """FAIL when the LDE service runs an image other than lde_image."""
    rc, out, err = aws('ecs', 'describe-services', '--cluster', cluster, '--services', prefix)
    services = (out or {}).get('services') or []
    if not services:
        report.fail(f'ECS service {prefix} is missing')
        return
    rc, out, err = aws('ecs', 'describe-task-definition',
                       '--task-definition', services[0]['taskDefinition'])
    containers = ((out or {}).get('taskDefinition') or {}).get('containerDefinitions') or []
    running = next((c.get('image') for c in containers if c.get('name') == 'lde'), None)
    if running == expected:
        report.ok(f'LDE runs lde_image {running.rsplit(":", 1)[-1]}')
    else:
        report.fail(f'LDE runs {running}, but lde_image is {expected}: the apply has not rolled out')


def check_targets(report, aws, prefix):
    for tg in (f'{prefix}-lde-tg', f'{prefix}-dtrack-tg', f'{prefix}-dtrack-api-tg'):
        rc, out, err = aws('elbv2', 'describe-target-groups', '--names', tg)
        groups = (out or {}).get('TargetGroups') or []
        if not groups:
            report.fail(f'target group {tg} is missing')
            continue
        rc, out, err = aws('elbv2', 'describe-target-health',
                           '--target-group-arn', groups[0]['TargetGroupArn'])
        states = [d['TargetHealth']['State'] for d in (out or {}).get('TargetHealthDescriptions', [])]
        if states and all(s == 'healthy' for s in states):
            report.ok(f'target group {tg}: {len(states)} healthy')
        elif 'healthy' in states and set(states) <= {'healthy', 'draining'}:
            # A redeployed task's predecessor drains for the deregistration delay (300s).
            report.warn(f'target group {tg}: {states.count("healthy")} healthy, '
                        f'{states.count("draining")} draining after a deploy. '
                        'Rerun verify in about 5 minutes.')
        else:
            report.fail(f'target group {tg}: {states or "no targets"}')


def check_dns(report, domains, alb_dns, resolver):
    want = alb_dns.rstrip('.').lower()
    for d in domains:
        answer = resolver(d)
        if not answer:
            report.fail(f'{d} does not resolve: create a CNAME to {want} ({DOC}, Application DNS)')
            continue
        got = answer[0].rstrip('.').lower()
        if got == want:
            report.ok(f'{d} -> {want}')
        else:
            report.fail(f'{d} resolves to {got}, not {want}: edit its CNAME target '
                        f'({DOC}, Application DNS)')


def secret_shape(secret_id, value):
    """Return (level, message) describing value without revealing it."""
    stripped = value.strip()
    if secret_id == 'lde/gemini-api-key' and value == PLACEHOLDER:
        return 'WARN', f'{secret_id} is {PLACEHOLDER}: Gemini package extraction is off'
    if not stripped:
        return 'FAIL', f'{secret_id} is empty'
    if value == PLACEHOLDER:
        return 'FAIL', f'{secret_id} is still {PLACEHOLDER}'
    if value != stripped:
        return 'FAIL', f'{secret_id} has leading or trailing whitespace (missing tr -d \'\\n\'?)'
    if secret_id == 'lde/basic-auth':
        try:
            doc = json.loads(value)
        except ValueError:
            return 'FAIL', f'{secret_id} is not JSON'
        if not isinstance(doc, dict) or not doc or not all(
                isinstance(h, str) and re.fullmatch(r'[0-9a-f]{64}', h) for h in doc.values()):
            return 'FAIL', f'{secret_id} must map each username to a 64-char sha256 hex'
        return 'OK', f'{secret_id}: {len(doc)} user(s), sha256 hashes'
    if secret_id == 'lde/github-pat':
        try:
            doc = json.loads(value)
        except ValueError:
            return 'FAIL', f'{secret_id} is not JSON: write an object of {{"<org>": "<token>"}}'
        if not isinstance(doc, dict) or not doc or not all(
                isinstance(k, str) and re.fullmatch(r'\*|[A-Za-z0-9._-]+', k)
                and isinstance(t, str) and t and t == t.strip() for k, t in doc.items()):
            return 'FAIL', (f'{secret_id} must map each GitHub org (or "*") to a non-empty token '
                            'with no surrounding whitespace')
        odd = sorted(k for k, t in doc.items() if not t.startswith(('github_pat_', 'ghp_')))
        if odd:
            return 'WARN', f'{secret_id}: {len(doc)} org(s); no github_pat_ or ghp_ prefix for {", ".join(odd)}'
        return 'OK', f'{secret_id}: {len(doc)} org(s)'
    return 'OK', f'{secret_id}: {len(value)} chars'


def check_secrets(report, aws):
    for secret_id in SECRETS:
        rc, out, err = aws('secretsmanager', 'get-secret-value', '--secret-id', secret_id)
        if rc != 0 or not out:
            report.fail(f'{secret_id}: {err.splitlines()[-1] if err else "unreadable"}')
            continue
        level, msg = secret_shape(secret_id, out.get('SecretString', ''))
        {'OK': report.ok, 'WARN': report.warn, 'FAIL': report.fail}[level](msg)


def _http(url, auth=None, follow=False):
    """GET *url*. Never follows redirects by default: an authenticated
    request's Authorization header would otherwise be resent to whatever
    host a redirect names, which could leak the Basic Auth credential off
    this domain. Pass follow=True only for checks that have no credential
    to protect and genuinely need to see the final destination.
    """
    headers = {'Authorization': 'Basic ' + auth} if auth else {}
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.read().decode(errors='replace'), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors='replace'), e.headers
    except (urllib.error.URLError, OSError) as e:
        return None, str(e), {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _lde_auth():
    try:
        user, password = open(LDE_LOGIN_FILE).read().splitlines()[:2]
    except (OSError, ValueError):
        return None, None
    return user, base64.b64encode(f'{user}:{password}'.encode()).decode()


def check_endpoints(report, lde_domain, dtrack_domain):
    base = f'https://{lde_domain}'
    status, _, _ = _http(base + '/')
    if status == 401:
        report.ok(f'{base}/ without a login: 401')
    else:
        report.fail(f'{base}/ without a login: {status}, expected 401')

    status, _, headers = _http(f'http://{lde_domain}/')
    location = (headers or {}).get('Location', '')
    if status == 301 and location.startswith('https://'):
        report.ok(f'http://{lde_domain}/ redirects to HTTPS')
    else:
        report.warn(f'http://{lde_domain}/ returned {status}, expected a 301 to HTTPS')

    user, auth = _lde_auth()
    if not auth:
        report.fail(f'{LDE_LOGIN_FILE} is missing or unreadable: run python3 scripts/set_lde_password.py')
    else:
        status, _, _ = _http(base + '/', auth)
        if status == 200:
            report.ok(f'{base}/ as {user}: 200')
        else:
            report.fail(f'{base}/ as {user}: {status}. lde/basic-auth does not match {LDE_LOGIN_FILE}')
        for path, key, level in (('/api/gh-status', 'logged_in', 'fail'),
                                 ('/api/dtrack-status', 'ok', 'fail'),
                                 ('/api/gemini-status', 'ok', 'warn')):
            status, body, _ = _http(base + path, auth)
            try:
                data = json.loads(body)
            except ValueError:
                data = {}
            if status == 200 and data.get(key):
                who = (data.get('accounts') or [{}])[0].get('user') if key == 'logged_in' else None
                report.ok(f'{path}: ' + (f'authenticated as {who}' if who else data.get('message', 'ok')))
            else:
                msg = data.get('message') or data.get('raw') or body[:120] or status
                getattr(report, level)(f'{path}: {msg}')

    dt = f'https://{dtrack_domain}'
    for path in ('/', '/api/version'):
        status, body, _ = _http(dt + path)
        if status == 200:
            extra = ''
            if path == '/api/version':
                try:
                    extra = f' (Dependency-Track {json.loads(body).get("version")})'
                except ValueError:
                    pass
            report.ok(f'{dt}{path}: 200{extra}')
        else:
            report.fail(f'{dt}{path}: {status}')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_tfvars(report):
    path = os.path.join(TF_DIR, 'terraform.tfvars')
    try:
        return parse_tfvars(open(path).read())
    except OSError:
        report.fail(f'{path} is missing: cp terraform.tfvars.example terraform.tfvars')
        return None


def preflight(report, aws, tfvars):
    prefix = f'{tfvars.get("env", "dev")}-lde'
    check_identity(report, aws)
    check_files(report)
    state = check_state(report)
    if state is not None:
        check_leftovers(report, aws, prefix, state)
    check_cluster(report, aws, tfvars.get('ecs_cluster_name', ''))
    domains = [d for d in (tfvars.get('lde_domain'), tfvars.get('dtrack_domain')) if d]
    if not tfvars.get('route53_zone_id'):
        check_certs(report, aws, tfvars.get('listener_certificate_arns') or [], domains)
    try:
        check_allowlist(report, tfvars, public_ip())
    except (urllib.error.URLError, OSError) as e:
        report.warn(f'could not read this machine\'s public IP: {e}')
    check_image(report, aws, tfvars.get('lde_image', ''))


def verify(report, aws, tfvars):
    prefix = f'{tfvars.get("env", "dev")}-lde'
    if check_identity(report, aws) is None:
        return
    rc, alb_dns, err = terraform('output', '-raw', '-no-color', 'alb_dns_name')
    if rc != 0:
        error = next((ln.strip('│ ') for ln in err.splitlines() if 'Error:' in ln), err[:200])
        report.fail(f'terraform output alb_dns_name: {error}')
        return
    if not alb_dns.strip():
        report.fail('terraform output alb_dns_name is empty: the stack is not applied')
        return
    report.ok(f'alb_dns_name {alb_dns.strip()}')
    check_services(report, aws, tfvars.get('ecs_cluster_name', ''), prefix)
    if tfvars.get('lde_image'):
        check_running_image(report, aws, tfvars.get('ecs_cluster_name', ''), prefix,
                            tfvars['lde_image'])
    check_targets(report, aws, prefix)
    lde, dtrack = tfvars.get('lde_domain'), tfvars.get('dtrack_domain')
    if not tfvars.get('route53_zone_id'):
        check_dns(report, [lde, dtrack], alb_dns.strip(), resolve)
    check_secrets(report, aws)
    check_endpoints(report, lde, dtrack)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('phase', choices=['preflight', 'verify'])
    args = parser.parse_args(argv)
    report = Report()
    tfvars = _load_tfvars(report)
    if tfvars is None:
        return 1
    aws = make_aws(tfvars.get('aws_region', 'us-east-1'))
    (preflight if args.phase == 'preflight' else verify)(report, aws, tfvars)
    print('\nFAIL lines block the next step.' if report.failed else '\nNo FAIL lines.', flush=True)
    return 1 if report.failed else 0


if __name__ == '__main__':
    sys.exit(main())
