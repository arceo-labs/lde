"""Unit tests for scripts/check_aws.py with a fake aws CLI runner."""

import importlib.util
import os

import pytest


def _load():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "check_aws.py",
    )
    spec = importlib.util.spec_from_file_location("check_aws", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ca = _load()

TFVARS = '''
aws_region = "us-east-1"
env        = "dev"   # trailing comment
lde_domain = "lde.example.com"
# listener_certificate_arns = ["commented-out"]
listener_certificate_arns = [
  "arn:aws:acm:us-east-1:111:certificate/a",
  "arn:aws:acm:us-east-1:111:certificate/b",
]
alb_internal            = false
alb_ingress_cidr_blocks = ["203.0.113.7/32", "198.51.100.0/24"]
db_instance_class       = 0.5
'''


class FakeAws:
    """Answers aws CLI calls from a dict keyed by the first two arguments."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        answer = self.answers.get(args[:2], (254, None, 'NotFound'))
        return answer(args) if callable(answer) else answer


def _lines(report):
    return '\n'.join(report.lines)


# --- parse_tfvars ----------------------------------------------------------

def test_parse_tfvars_reads_strings_lists_bools_numbers():
    v = ca.parse_tfvars(TFVARS)
    assert v['env'] == 'dev'
    assert v['listener_certificate_arns'] == [
        'arn:aws:acm:us-east-1:111:certificate/a',
        'arn:aws:acm:us-east-1:111:certificate/b',
    ]
    assert v['alb_internal'] is False
    assert v['alb_ingress_cidr_blocks'] == ['203.0.113.7/32', '198.51.100.0/24']
    assert v['db_instance_class'] == 0.5


# --- allowlist -------------------------------------------------------------

def test_allowlist_passes_when_ip_inside_a_block():
    report = ca.Report()
    ca.check_allowlist(report, ca.parse_tfvars(TFVARS), '198.51.100.42')
    assert not report.failed


def test_allowlist_fails_when_ip_outside_every_block():
    report = ca.Report()
    ca.check_allowlist(report, ca.parse_tfvars(TFVARS), '192.0.2.1')
    assert report.failed
    assert '192.0.2.1' in _lines(report)


def test_allowlist_skipped_for_internal_alb():
    report = ca.Report()
    ca.check_allowlist(report, {'alb_internal': True, 'alb_ingress_cidr_blocks': []}, '192.0.2.1')
    assert not report.failed


# --- secret shape ----------------------------------------------------------

@pytest.mark.parametrize('secret_id,value,level', [
    ('lde/github-pat', 'REPLACE_ME', 'FAIL'),
    ('lde/github-pat', '', 'FAIL'),
    ('lde/github-pat', 'github_pat_' + 'x' * 82 + '\n', 'FAIL'),
    ('lde/github-pat', 'github_pat_' + 'x' * 82, 'OK'),
    ('lde/github-pat', 'something-else-40-chars-long-xxxxxxxxxxxx', 'WARN'),
    ('lde/gemini-api-key', 'REPLACE_ME', 'WARN'),
    ('lde/gemini-api-key', 'k' * 39, 'OK'),
    ('lde/dtrack-api-key', 'REPLACE_ME', 'FAIL'),
    ('lde/basic-auth', '{"admin": "' + 'a' * 64 + '"}', 'OK'),
    ('lde/basic-auth', '{"admin": "plaintext"}', 'FAIL'),
])
def test_secret_shape(secret_id, value, level):
    got, message = ca.secret_shape(secret_id, value)
    assert got == level
    assert value.strip() not in message or value.strip() in ('', 'REPLACE_ME')


# --- leftovers -------------------------------------------------------------

def test_leftovers_fail_for_resources_missing_from_state():
    aws = FakeAws({
        ('elbv2', 'describe-load-balancers'): (0, {'LoadBalancers': [{'LoadBalancerName': 'dev-lde'}]}, ''),
        ('secretsmanager', 'list-secrets'): (0, {'SecretList': [
            {'Name': 'lde/github-pat', 'DeletedDate': '2026-10-01T00:00:00Z'},
        ]}, ''),
    })
    report = ca.Report()
    ca.check_leftovers(report, aws, 'dev-lde', state=set())
    text = _lines(report)
    assert report.failed
    assert 'dev-lde' in text and 'load balancer' in text
    assert 'lde/github-pat' in text and 'scheduled for deletion' in text


def test_leftovers_ignore_resources_in_state():
    aws = FakeAws({
        ('elbv2', 'describe-load-balancers'): (0, {'LoadBalancers': [{'LoadBalancerName': 'dev-lde'}]}, ''),
        ('ecr', 'describe-repositories'): (0, {'repositories': [{'repositoryName': 'dev-lde'}]}, ''),
        ('secretsmanager', 'list-secrets'): (0, {'SecretList': [{'Name': 'lde/github-pat'}]}, ''),
    })
    report = ca.Report()
    ca.check_leftovers(report, aws, 'dev-lde', state={
        'aws_lb.main', 'aws_ecr_repository.lde', 'aws_secretsmanager_secret.github_pat',
    })
    assert not report.failed, _lines(report)


def test_final_snapshot_is_a_warning():
    aws = FakeAws({
        ('rds', 'describe-db-cluster-snapshots'): (0, {'DBClusterSnapshots': [
            {'DBClusterSnapshotIdentifier': 'dev-lde-dtrack-final'}]}, ''),
    })
    report = ca.Report()
    ca.check_leftovers(report, aws, 'dev-lde', state=set())
    assert not report.failed
    assert 'dev-lde-dtrack-final' in _lines(report)


# --- cluster ---------------------------------------------------------------

@pytest.mark.parametrize('payload,failed', [
    ({'clusters': [{'status': 'ACTIVE'}], 'failures': []}, False),
    ({'clusters': [{'status': 'INACTIVE'}], 'failures': []}, True),
    ({'clusters': [], 'failures': [{'reason': 'MISSING'}]}, True),
])
def test_cluster_status(payload, failed):
    aws = FakeAws({('ecs', 'describe-clusters'): (0, payload, '')})
    report = ca.Report()
    ca.check_cluster(report, aws, 'lde-eval')
    assert report.failed is failed


# --- dns -------------------------------------------------------------------

def test_dns_fails_when_cname_names_another_load_balancer():
    report = ca.Report()
    resolve = {'lde.example.com': ['dev-lde-1.us-east-1.elb.amazonaws.com.', '54.0.0.1']}.get
    ca.check_dns(report, ['lde.example.com'], 'dev-lde-2.us-east-1.elb.amazonaws.com', resolve)
    assert report.failed
    assert 'dev-lde-1' in _lines(report)


def test_dns_passes_when_cname_matches():
    report = ca.Report()
    resolve = {'lde.example.com': ['dev-lde-2.us-east-1.elb.amazonaws.com.', '54.0.0.1']}.get
    ca.check_dns(report, ['lde.example.com'], 'dev-lde-2.us-east-1.elb.amazonaws.com', resolve)
    assert not report.failed


# --- identity --------------------------------------------------------------

def test_root_identity_warns():
    aws = FakeAws({('sts', 'get-caller-identity'): (
        0, {'Account': '111', 'Arn': 'arn:aws:iam::111:root'}, '')})
    report = ca.Report()
    ca.check_identity(report, aws)
    assert not report.failed
    assert 'WARN' in _lines(report) and 'root' in _lines(report)


# --- running image ---------------------------------------------------------

def _image_aws(running_image):
    return FakeAws({
        ('ecs', 'describe-services'): (0, {'services': [
            {'serviceName': 'dev-lde', 'taskDefinition': 'arn:aws:ecs:us-east-1:111:task-definition/dev-lde:8'}]}, ''),
        ('ecs', 'describe-task-definition'): (0, {'taskDefinition': {
            'containerDefinitions': [{'name': 'lde', 'image': running_image}]}}, ''),
    })


def test_running_image_matches_lde_image():
    report = ca.Report()
    ca.check_running_image(report, _image_aws('repo/dev-lde:abc1234'), 'lde-eval', 'dev-lde',
                           'repo/dev-lde:abc1234')
    assert not report.failed
    assert 'abc1234' in _lines(report)


def test_running_image_differs_from_lde_image():
    report = ca.Report()
    ca.check_running_image(report, _image_aws('repo/dev-lde:6c5e0e5'), 'lde-eval', 'dev-lde',
                           'repo/dev-lde:abc1234')
    assert report.failed
    assert '6c5e0e5' in _lines(report) and 'abc1234' in _lines(report)


# --- services and targets during a rollout ---------------------------------

def _service(rollout, primary_running, running=1, desired=1):
    return {
        'serviceName': 'dev-lde', 'status': 'ACTIVE',
        'runningCount': running, 'desiredCount': desired,
        'deployments': [{'status': 'PRIMARY', 'rolloutState': rollout,
                         'runningCount': primary_running, 'desiredCount': desired}],
        'events': [{'message': '(service dev-lde) has begun draining connections on 1 tasks.'}],
    }


def _services_aws(lde_service):
    def answer(args):
        names = args[args.index('--services') + 1:]
        others = [dict(_service('COMPLETED', 1), serviceName=n) for n in names if n != 'dev-lde']
        return 0, {'services': [lde_service] + others}, ''
    return FakeAws({('ecs', 'describe-services'): answer})


def test_service_rollout_completed_is_ok():
    report = ca.Report()
    ca.check_services(report, _services_aws(_service('COMPLETED', 1)), 'lde-eval', 'dev-lde')
    assert not report.failed
    assert 'WARN' not in _lines(report)


def test_service_rollout_with_new_task_running_warns():
    report = ca.Report()
    ca.check_services(report, _services_aws(_service('IN_PROGRESS', 1)), 'lde-eval', 'dev-lde')
    assert not report.failed
    assert 'WARN ECS service dev-lde' in _lines(report)


def test_service_rollout_without_new_task_fails():
    # The old task still serves, so the service shows 1/1, but the new one is not up.
    report = ca.Report()
    ca.check_services(report, _services_aws(_service('IN_PROGRESS', 0)), 'lde-eval', 'dev-lde')
    assert report.failed


def test_service_rollout_failed_fails():
    report = ca.Report()
    ca.check_services(report, _services_aws(_service('FAILED', 1)), 'lde-eval', 'dev-lde')
    assert report.failed


def _targets_aws(states):
    return FakeAws({
        ('elbv2', 'describe-target-groups'): (0, {'TargetGroups': [{'TargetGroupArn': 'arn:tg'}]}, ''),
        ('elbv2', 'describe-target-health'): (0, {'TargetHealthDescriptions': [
            {'TargetHealth': {'State': s}} for s in states]}, ''),
    })


def test_targets_healthy_with_draining_old_task_warns():
    report = ca.Report()
    ca.check_targets(report, _targets_aws(['healthy', 'draining']), 'dev-lde')
    assert not report.failed
    assert 'WARN target group dev-lde-lde-tg' in _lines(report)


@pytest.mark.parametrize('states', [['draining'], ['healthy', 'unhealthy'], []])
def test_targets_without_a_clean_healthy_set_fail(states):
    report = ca.Report()
    ca.check_targets(report, _targets_aws(states), 'dev-lde')
    assert report.failed


# --- verify entry point ----------------------------------------------------

_ID_OK = (0, {'Account': '111', 'Arn': 'arn:aws:iam::111:user/deploy'}, '')
_TF_CRED_ERR = (1, '', '╷\n│ Error: No valid credential sources found\n│\n│ Please see https://developer.hashicorp.com\n╵')


def test_verify_stops_on_expired_credentials(monkeypatch):
    monkeypatch.setattr(ca, 'terraform', lambda *a: _TF_CRED_ERR)
    aws = FakeAws({('sts', 'get-caller-identity'): (255, None, 'ExpiredToken: the token is expired')})
    report = ca.Report()
    ca.verify(report, aws, {'env': 'dev'})
    assert report.failed
    assert 'AWS credentials' in _lines(report)
    assert 'not applied' not in _lines(report)
    assert aws.calls == [('sts', 'get-caller-identity')]


def test_verify_reports_terraform_output_error(monkeypatch):
    monkeypatch.setattr(ca, 'terraform', lambda *a: _TF_CRED_ERR)
    report = ca.Report()
    ca.verify(report, FakeAws({('sts', 'get-caller-identity'): _ID_OK}), {'env': 'dev'})
    assert report.failed
    assert 'No valid credential sources found' in _lines(report)
    assert 'not applied' not in _lines(report)


def test_verify_empty_output_means_not_applied(monkeypatch):
    monkeypatch.setattr(ca, 'terraform', lambda *a: (0, '', ''))
    report = ca.Report()
    ca.verify(report, FakeAws({('sts', 'get-caller-identity'): _ID_OK}), {'env': 'dev'})
    assert report.failed
    assert 'not applied' in _lines(report)
