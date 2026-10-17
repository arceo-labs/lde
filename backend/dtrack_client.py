"""Dependency-Track REST client — stdlib only (urllib).

Uses DT's auto-create-via-BOM-upload flow: `PUT /api/v1/bom` with
`autoCreate=true` creates the project if it doesn't exist AND uploads the
CycloneDX BOM in a single atomic call. This needs only `BOM_UPLOAD` and
`PROJECT_CREATION_UPLOAD` on the API key's team — no `PORTFOLIO_MANAGEMENT`
(which `PUT /api/v1/project` would require) and no mandatory
`VIEW_PORTFOLIO` (used only as a best-effort lookup for UI deep links).
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from . import log as log_mod

logger = log_mod.get('dtrack')

_DEFAULT_PAGE_SIZE = 100


class DtrackError(RuntimeError):
    pass


class DtrackOverwriteRefused(DtrackError):
    """Raised by safe_upload_bom when the empty-BOM guard refuses an upload.

    Distinct from generic DtrackError so callers (the pipeline) can keep
    the run alive — refusing an overwrite is a *deliberate* outcome, not
    a transport failure. The pipeline records the reason on run_repos
    and continues; the prior healthy DT project keeps its components.
    """


def _request(method, base_url, path, api_key, body=None, content_type='application/json',
             timeout=30):
    url = base_url.rstrip('/') + path
    headers = {
        'X-Api-Key': api_key,
        'Accept': 'application/json',
    }
    data = None
    if body is not None:
        if content_type == 'application/json':
            data = json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        else:
            data = body
            headers['Content-Type'] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    logger.debug('%s %s', method, log_mod.safe(path))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            logger.debug('%s %s -> %d (%d bytes)', method, log_mod.safe(path),
                         resp.status, len(payload))
            if not payload:
                return None
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                return payload.decode('utf-8', errors='replace')
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='replace')[:500]
        logger.warning('%s %s -> HTTP %d: %s', method, log_mod.safe(path),
                       exc.code, log_mod.safe(detail))
        raise DtrackError(f'{method} {path} → HTTP {exc.code}: {detail}') from exc
    except urllib.error.URLError as exc:
        logger.warning('%s %s -> URLError: %s', method, log_mod.safe(path), log_mod.safe(exc.reason))
        raise DtrackError(f'{method} {path} → {exc.reason}') from exc


# Permissions this tool actually needs on the API key's team (see module
# docstring). Surfaced as informational hints by connection_status — their
# absence does not fail the test (the key is still valid).
_REQUIRED_PERMISSIONS = ('BOM_UPLOAD', 'PROJECT_CREATION_UPLOAD')


def connection_status(base_url, api_key, timeout=10):
    """Validate the configured Dependency-Track API key.

    Calls ``GET /api/v1/team/self`` — a self-introspection endpoint that any
    valid API key can reach without elevated privileges — to confirm the key
    is accepted and report the team name and granted permissions.

    Returns a dict the Settings UI consumes::

        {
          'configured': bool,            # URL + key both present
          'ok': bool,                    # key accepted by DT
          'message': str,                # human-readable, never leaks raw DT bodies
          'team': str | None,            # team name when ok
          'permissions': [str],          # granted permissions when ok
          'missing_permissions': [str],  # required perms not granted (informational)
        }

    Never logs or returns the API key.
    """
    if not (base_url or '').strip():
        return {'configured': False, 'ok': False, 'team': None, 'permissions': [],
                'missing_permissions': [],
                'message': 'No Dependency-Track API URL configured.'}
    if not (api_key or '').strip():
        return {'configured': False, 'ok': False, 'team': None, 'permissions': [],
                'missing_permissions': [],
                'message': 'No Dependency-Track API key configured.'}
    try:
        result = _request('GET', base_url, '/api/v1/team/self', api_key, timeout=timeout)
    except DtrackError as exc:
        msg = str(exc)
        if any(code in msg for code in ('HTTP 400', 'HTTP 401', 'HTTP 404')):
            return {'configured': True, 'ok': False, 'team': None, 'permissions': [],
                    'missing_permissions': [],
                    'message': 'API key rejected by Dependency-Track. Check that the key '
                               'is valid and has not been revoked.'}
        # Network / other transport failure — keep the message generic so we
        # don't leak internal infrastructure details or raw DT response bodies.
        return {'configured': True, 'ok': False, 'team': None, 'permissions': [],
                'missing_permissions': [],
                'message': 'Could not reach Dependency-Track at the configured URL. '
                           'Verify the API URL and network connectivity.'}

    team = result.get('name') if isinstance(result, dict) else None
    permissions = []
    if isinstance(result, dict):
        permissions = [p.get('name') for p in (result.get('permissions') or [])
                       if isinstance(p, dict) and p.get('name')]
    missing = [p for p in _REQUIRED_PERMISSIONS if p not in permissions]
    message = f'API key valid (team: {team}).' if team else 'API key valid.'
    if missing:
        message += f' Missing recommended permission(s): {", ".join(missing)}.'
    return {'configured': True, 'ok': True, 'team': team, 'permissions': permissions,
            'missing_permissions': missing, 'message': message}


def lookup_project(base_url, api_key, name, version='main'):
    """Return the project UUID for (name, version) or None.

    Used as a best-effort post-upload lookup so the UI can deep-link into
    DT. Requires VIEW_PORTFOLIO on the API key's team. Callers should
    tolerate failure when this permission isn't granted.
    """
    qs = urllib.parse.urlencode({'name': name, 'version': version})
    try:
        result = _request('GET', base_url, f'/api/v1/project/lookup?{qs}', api_key)
    except DtrackError as exc:
        if '404' in str(exc):
            return None
        raise
    if isinstance(result, dict):
        return result.get('uuid')
    return None


def upload_bom(base_url, api_key, project_name, project_version, bom_path,
               is_latest=None):
    """Upload *bom_path* with DT's autoCreate flow.

    Atomically creates the project (if it doesn't exist) and queues the
    CycloneDX BOM for async processing. Requires BOM_UPLOAD and
    PROJECT_CREATION_UPLOAD on the API key's team.

    When *is_latest* is True/False the ``isLatest`` flag is set accordingly
    (DT 4.12+: marking a version latest auto-unsets it on the project's other
    versions). When None the flag is omitted so DT's existing value is left
    untouched.

    Returns the async processing token DT issues for the upload.
    """
    if not os.path.isfile(bom_path):
        raise DtrackError(f'BOM not found: {bom_path}')

    import base64
    with open(bom_path, 'rb') as f:
        encoded = base64.b64encode(f.read()).decode('ascii')

    body = {
        'projectName': project_name,
        'projectVersion': project_version,
        'autoCreate': True,
        'bom': encoded,
    }
    if is_latest is not None:
        body['isLatest'] = bool(is_latest)
    result = _request('PUT', base_url, '/api/v1/bom', api_key, body=body)
    if isinstance(result, dict):
        return result.get('token')
    return None


def poll_bom_processing(base_url, api_key, token, timeout=15, interval=1.0):
    """Block until DT finishes processing a BOM upload or *timeout* seconds elapse.

    Polls ``GET /api/v1/bom/token/{token}`` at *interval*-second intervals.
    Returns True when ``processing`` is false (upload complete), or False on
    timeout. Callers should treat False as a transient delay — the component
    count may still be stale but the upload itself succeeded.

    Called from worker threads so blocking sleep is acceptable.
    """
    if not token:
        return True
    deadline = time.monotonic() + timeout
    path = f'/api/v1/bom/token/{urllib.parse.quote(str(token), safe="")}'
    while time.monotonic() < deadline:
        try:
            result = _request('GET', base_url, path, api_key)
            if isinstance(result, dict) and not result.get('processing', True):
                return True
        except DtrackError as exc:
            if '404' in str(exc):
                # Token unknown / already expired — DT considers it done.
                logger.debug('poll_bom_processing: token %s 404 (treating as done)',
                             log_mod.safe(token))
                return True
            logger.warning('poll_bom_processing: token %s error (aborting poll): %s',
                           log_mod.safe(token), log_mod.safe(exc))
            return False
        time.sleep(interval)
    logger.warning('poll_bom_processing: token %s timed out after %.0fs',
                   log_mod.safe(token), timeout)
    return False


# ---------------------------------------------------------------------------
# Read-side helpers (paginated component listing + cross-project search).
# ---------------------------------------------------------------------------

def _paginate(base_url, api_key, path, page_size=_DEFAULT_PAGE_SIZE, max_pages=200):
    """Yield items from a DT endpoint that uses pageNumber/pageSize.

    Stops when the server returns fewer than `page_size` items OR when
    `max_pages` is reached (defensive: prevents accidental infinite loops
    against a misbehaving DT install).
    """
    page = 1
    while page <= max_pages:
        sep = '&' if '?' in path else '?'
        qs = urllib.parse.urlencode({'pageNumber': page, 'pageSize': page_size})
        items = _request('GET', base_url, f'{path}{sep}{qs}', api_key)
        if not isinstance(items, list) or not items:
            break
        yield from items
        if len(items) < page_size:
            break
        page += 1


def list_components(base_url, api_key, project_uuid):
    """Return every component DT currently has for a project.

    Used by the per-repo dtrack-components endpoint to compute "what DT
    actually retains" for cross-checking against locally-resolved deps.

    Component search requires VIEW_PORTFOLIO on Dependency-Track 4.14.
    """
    if not project_uuid:
        return []
    path = f'/api/v1/component/project/{urllib.parse.quote(project_uuid, safe="")}'
    try:
        return list(_paginate(base_url, api_key, path))
    except DtrackError as exc:
        # Permission failures should bubble up; missing project is benign
        # (returns empty list so callers can render coverage_ratio=0).
        if '404' in str(exc):
            return []
        raise


def project_component_count(base_url, api_key, project_uuid):
    """Return DT's current component count for *project_uuid* (or None).

    Cheaper-than-list_components for the safe_upload_bom guard; we only
    need a single count to make the overwrite decision. Pulls one page
    and inspects the X-Total-Count header when available, falling back
    to a paginated count if the header isn't returned.
    """
    if not project_uuid:
        return None
    qs = urllib.parse.urlencode({'pageNumber': 1, 'pageSize': 1})
    path = f'/api/v1/component/project/{urllib.parse.quote(project_uuid, safe="")}?{qs}'
    url = base_url.rstrip('/') + path
    req = urllib.request.Request(url, headers={
        'X-Api-Key': api_key,
        'Accept': 'application/json',
    }, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            total = resp.headers.get('X-Total-Count')
            if total is not None and total.isdigit():
                return int(total)
            try:
                _payload = resp.read()
            except OSError:
                _payload = b''
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 0
        return None
    except urllib.error.URLError:
        return None
    # Header missing — fall back to pagination.
    try:
        return sum(1 for _ in _paginate(base_url, api_key,
                                        f'/api/v1/component/project/{urllib.parse.quote(project_uuid, safe="")}'))
    except DtrackError:
        return None


def search_components(base_url, api_key, query):
    """Cross-project component search with project membership.

    DT's `/api/v1/search/component?query=` returns matching components
    *without* their project membership (only ``name``, ``group``,
    ``version``, ``uuid``). To answer "which projects contain
    @tanstack/*?" we need to iterate every project and filter its
    components ourselves — slower than a single search call but the
    only correct way to surface project context.

    Each returned dict has the standard component fields PLUS a
    synthesised ``projects`` list of ``{name, version, uuid}`` so the
    server-side handler can group by project.

    Component search requires VIEW_PORTFOLIO on Dependency-Track 4.14.
    """
    if not query:
        return []
    needle = query.lower()
    out = []
    for proj in list_projects(base_url, api_key):
        proj_uuid = proj.get('uuid')
        proj_name = proj.get('name', '')
        proj_version = proj.get('version', '')
        if not proj_uuid:
            continue
        try:
            components = list_components(base_url, api_key, proj_uuid)
        except DtrackError:
            continue
        for c in components:
            haystack = ' '.join(filter(None, [
                c.get('name'), c.get('group'), c.get('version'), c.get('purl'),
            ])).lower()
            if needle in haystack:
                # Mutate a copy so we don't pollute the cached dict
                # under a thread-shared reference.
                enriched = dict(c)
                enriched['projects'] = [{
                    'name': proj_name, 'version': proj_version, 'uuid': proj_uuid,
                }]
                out.append(enriched)
    return out


def search_components_by_name(base_url, api_key, name):
    """Server-side substring search for components across all projects.

    Two-step approach that avoids downloading the full portfolio:

    1. ``GET /v1/search/component?query=<name>`` — DT's Lucene-backed
       full-text search.  Returns a ``SearchResult`` with a ``COMPONENT``
       list of lightweight objects (uuid, name, group, purl — no project).
       Lucene tokenises the query on ``/``, ``@``, and other separators, so
       a query like ``wordpress/scripts`` expands to ``wordpress OR scripts``
       and returns far more items than intended.

    2. Client-side precision filter on each search result item — checks that
       the full *name* string (lowercased) appears somewhere in the item's
       canonical identifier before paying for a UUID lookup:

       a. ``name in purl`` — most reliable; purl encodes the full package
          coordinate (``pkg:npm/@wordpress/scripts@6.0``).
       b. ``name in "{group}/{component_name}"`` — handles scoped packages
          stored as separate group + name fields.
       c. ``name.lstrip('@') in combined.lstrip('@')`` — normalises
          ``@``-prefix mismatches (user types ``wordpress/scripts``, DT stores
          ``group=@wordpress, name=scripts``).
       d. ``name in component_name`` — plain fallback for single-token
          queries like ``requests`` or ``lodash`` (preserves prior behaviour).

    3. ``GET /v1/component/{uuid}`` for each surviving UUID.
       Returns the full ``Component`` object including the embedded
       ``project`` field (name, version, uuid).

    Total requests = 1 search call + O(precise matches), rather than
    O(projects) * O(components_per_project) for a full portfolio dump.

    Returns a list of dicts with keys: project, project_version, component,
    component_version, purl.  Components whose UUID lookup fails or whose
    embedded project is absent (orphan/internal entries) are skipped with
    a logged warning.

    Component search requires VIEW_PORTFOLIO on Dependency-Track 4.14.
    """
    if not name:
        return []
    needle = name.lower()
    needle_plain = needle.lstrip('@')
    qs = urllib.parse.urlencode({'query': name})
    result = _request('GET', base_url, f'/api/v1/search/component?{qs}', api_key)
    seen = set()
    uuids = []
    if isinstance(result, dict):
        # DT returns lowercase "component" key; deduplicate UUIDs since the
        # search index emits one entry per project-occurrence of a component.
        for item in result.get('results', {}).get('component', []):
            uid = item.get('uuid')
            if not uid or uid in seen:
                continue
            # Precision filter: ensure the full query string is present in
            # the component's canonical identifier before fetching its UUID.
            # This prevents Lucene tokenisation from surfacing false positives
            # when the query contains path separators or other non-word chars.
            item_name  = (item.get('name')  or '').lower()
            item_group = (item.get('group') or '').lower()
            item_purl  = (item.get('purl')  or '').lower()
            combined   = f'{item_group}/{item_name}' if item_group else item_name
            combined_plain = combined.lstrip('@')
            if not (needle in item_purl
                    or needle in combined
                    or needle_plain in combined_plain
                    or needle in item_name):
                continue
            seen.add(uid)
            uuids.append(uid)
    rows = []
    for uid in uuids:
        try:
            c = _request('GET', base_url,
                         f'/api/v1/component/{urllib.parse.quote(uid, safe="")}',
                         api_key)
        except DtrackError as exc:
            logger.warning('search_components_by_name: UUID lookup failed for %s: %s',
                           log_mod.safe(uid), log_mod.safe(exc))
            continue
        if not isinstance(c, dict):
            continue
        proj = c.get('project') or {}
        proj_name = proj.get('name', '')
        if not proj_name:
            logger.debug('search_components_by_name: skipping component %s — no project', uid)
            continue
        c_group = c.get('group') or ''
        c_name  = c.get('name')  or ''
        c_full  = f'{c_group}/{c_name}' if c_group else c_name
        rows.append({
            'project': proj_name,
            'project_uuid': proj.get('uuid', ''),
            'project_version': proj.get('version', ''),
            'component': c_full,
            'component_uuid': c.get('uuid', uid),
            'component_version': c.get('version', ''),
            'purl': c.get('purl', ''),
        })
    return rows


def list_projects(base_url, api_key):
    """Return every project DT has — used by the coverage rollup."""
    return list(_paginate(base_url, api_key, '/api/v1/project'))


def _bom_component_count(bom_path):
    """Return the number of `components` in a CycloneDX BOM file."""
    try:
        with open(bom_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    comps = data.get('components')
    return len(comps) if isinstance(comps, list) else 0


def safe_upload_bom(base_url, api_key, project_name, project_version,
                   bom_path, force=False, is_latest=None):
    """upload_bom with two guards against partial-resolution clobbers.

    1. **Empty-BOM guard:** when the new BOM has zero components AND the
       target DT project (name, version) already has >0 components,
       refuses the upload. Raises DtrackOverwriteRefused so the pipeline
       can record the reason on run_repos.error and keep going. The
       prior healthy project is preserved.

       Override with `force=True` (or the LDE_FORCE_BOM_OVERWRITE=1 env
       var, set by ops) when the caller knows the empty BOM is correct
       (e.g. a repo that genuinely had all its deps removed).

    2. **Regression guard:** when the new BOM has >0 components but
       drops by more than 50% vs the current DT count, the upload IS
       performed (legitimate dep removals would otherwise be impossible
       to ingest), but a warning is logged and the result dict carries
       a `regression_warning` field so the pipeline can surface it on
       run_repos.error for the operator to review.

    Returns a dict: `{token, new_component_count, prior_component_count,
    regression_warning: str | None}`. Raises DtrackOverwriteRefused on
    guard #1 and DtrackError on transport failures (same as upload_bom).
    """
    if not os.path.isfile(bom_path):
        raise DtrackError(f'BOM not found: {bom_path}')

    new_count = _bom_component_count(bom_path)
    if new_count is None:
        # Unparseable BOM — let upload_bom fail with a clearer DT error.
        return _do_upload(base_url, api_key, project_name, project_version,
                          bom_path, new_count=None, prior_count=None,
                          is_latest=is_latest)

    # Look up prior component count for the existing project (if any).
    prior_count = None
    try:
        existing_uuid = lookup_project(base_url, api_key, project_name, project_version)
    except DtrackError:
        existing_uuid = None
    if existing_uuid:
        try:
            prior_count = project_component_count(base_url, api_key, existing_uuid)
        except DtrackError:
            prior_count = None

    env_force = os.environ.get('LDE_FORCE_BOM_OVERWRITE') == '1'

    # Guard 1: empty BOM would clobber a healthy project.
    if new_count == 0 and (prior_count or 0) > 0 and not (force or env_force):
        msg = (f'Refusing to upload empty BOM for {project_name}@{project_version}: '
               f'DT currently has {prior_count} component(s). '
               f'Set LDE_FORCE_BOM_OVERWRITE=1 to override.')
        logger.warning('safe_upload_bom: %s', log_mod.safe(msg))
        raise DtrackOverwriteRefused(msg)

    # Guard 2: large regression — upload anyway but flag for the operator.
    regression_warning = None
    if (prior_count or 0) > 10 and new_count > 0 and new_count < (prior_count // 2):
        regression_warning = (
            f'BOM regression: new={new_count} vs DT prior={prior_count} '
            f'(dropped {prior_count - new_count} component(s), '
            f'{int(100 * (1 - new_count / prior_count))}%) — verify before '
            f'considering this run authoritative'
        )
        logger.warning('safe_upload_bom %s@%s: %s',
                       log_mod.safe(project_name), log_mod.safe(project_version),
                       log_mod.safe(regression_warning))

    return _do_upload(base_url, api_key, project_name, project_version,
                      bom_path, new_count=new_count, prior_count=prior_count,
                      regression_warning=regression_warning, is_latest=is_latest)


def _do_upload(base_url, api_key, project_name, project_version, bom_path,
               new_count=None, prior_count=None, regression_warning=None,
               is_latest=None):
    token = upload_bom(base_url, api_key, project_name, project_version, bom_path,
                       is_latest=is_latest)
    return {
        'token': token,
        'new_component_count': new_count,
        'prior_component_count': prior_count,
        'regression_warning': regression_warning,
    }
