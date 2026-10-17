import { api } from '/js/api.js';
import { navigate } from '/js/app.js';

export async function renderRuns(root) {
  root.innerHTML = `
    <div class="card">
      <h2>Start a new run</h2>
      <p class="muted">Orgs (comma separated). Leave blank to use defaults from settings.</p>
      <input id="orgs-input" type="text" placeholder="example-org,another-org" />
      <p class="muted stack-gap">Repo filter (optional — leave blank to scan all repos in the org).</p>
      <input id="repos-input" type="text" placeholder="bec-api, core-services" />
      <p class="muted stack-gap">Ingest uses GitHub's Dependency Graph. The local ORT Docker pipeline is deprecated.</p>
      <p class="muted stack-gap">Branch</p>
      <label class="checkbox-row"><input id="use-default-branch" type="checkbox" checked /> Use default branch (main / GitHub default)</label>
      <input id="branch-input" type="text" placeholder="e.g. develop or release/1.2" disabled />
      <p class="muted gap-above-xs" id="branch-hint">When left on default, every repo uses its GitHub default branch. Uncheck to pin one branch for the whole run.</p>
      <p class="gap-above"><button id="start-run">Start run</button> <span id="start-status" class="muted"></span></p>
    </div>
    <div class="card">
      <h2>Recent runs</h2>
      <div id="runs-list">Loading…</div>
    </div>
  `;

  const useDefaultEl = document.getElementById('use-default-branch');
  const branchInputEl = document.getElementById('branch-input');
  useDefaultEl.addEventListener('change', () => {
    branchInputEl.disabled = useDefaultEl.checked;
    if (useDefaultEl.checked) branchInputEl.value = '';
  });

  document.getElementById('start-run').addEventListener('click', async () => {
    const rawOrgs = document.getElementById('orgs-input').value.trim();
    const orgs = rawOrgs ? rawOrgs.split(',').map((s) => s.trim()).filter(Boolean) : [];
    const rawRepos = document.getElementById('repos-input').value.trim();
    const repos = rawRepos ? rawRepos.split(',').map((s) => s.trim()).filter(Boolean) : [];
    const useDefault = useDefaultEl.checked;
    const branch = branchInputEl.value.trim();
    const status = document.getElementById('start-status');
    if (!useDefault && !branch) {
      status.textContent = 'Enter a branch name or re-check "Use default branch".';
      return;
    }
    status.textContent = 'Starting…';
    try {
      const { run_id } = await api.createRun(orgs, repos, 'github_sbom', { useDefault, branch });
      navigate(`/runs/${run_id}`);
    } catch (err) {
      status.textContent = `Failed: ${err.message}`;
    }
  });

  const runs = await api.listRuns();
  const list = document.getElementById('runs-list');
  if (!runs.length) {
    list.innerHTML = '<p class="muted">No runs yet.</p>';
    return;
  }
  list.innerHTML = `
    <table>
      <thead><tr><th>ID</th><th>Started</th><th>Status</th><th>Stage</th><th>Method</th><th>Scope</th></tr></thead>
      <tbody>
        ${runs.map((r) => `
          <tr>
            <td><a href="/runs/${r.id}" data-route="runs">${r.id.slice(0, 8)}</a></td>
            <td>${r.started_at}</td>
            <td><span class="tag ${runStatusTag(r.status)}">${r.status}</span></td>
            <td>${r.stage}</td>
            <td><span class="tag ${r.method === 'github_sbom' ? 'ok' : ''}" title="${r.method === 'github_sbom' ? 'GitHub Dependency Graph API' : 'ORT Docker pipeline'}">${r.method === 'github_sbom' ? 'gh-sbom' : 'ort'}</span></td>
            <td class="muted">${escapeHtml((r.orgs || []).join(', '))}${(r.repos && r.repos.length) ? ` <span class="tag">${escapeHtml(r.repos.join(', '))}</span>` : ''}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

export async function renderRunDetail(root, runId) {
  root.innerHTML = `
    <div class="card">
      <h2>Run ${runId.slice(0, 8)}</h2>
      <div id="run-summary">Loading…</div>
      <div id="run-actions" class="gap-above"></div>
    </div>
    <div class="card">
      <h2>Repositories</h2>
      <div id="run-repos">Loading…</div>
    </div>
  `;

  let polling = true;
  async function tick() {
    try {
      const [run, repos] = await Promise.all([api.getRun(runId), api.listRunRepos(runId)]);
      const methodLabel = run.method === 'github_sbom' ? 'GitHub Dependency Graph' : 'ORT';
      document.getElementById('run-summary').innerHTML = `
        <p><span class="tag ${runStatusTag(run.status)}">${run.status}</span>
           Stage: <strong>${run.stage}</strong>
           · Method: <span class="tag ${run.method === 'github_sbom' ? 'ok' : ''}">${methodLabel}</span></p>
        <p class="muted">Started ${run.started_at}${run.completed_at ? ` · completed ${run.completed_at}` : ''}
          · Orgs: ${escapeHtml((run.orgs || []).join(', '))}${(run.repos && run.repos.length) ? ` · Repos: <strong>${escapeHtml(run.repos.join(', '))}</strong>` : ''}</p>
        ${run.error ? `<pre class="log">${escapeHtml(run.error)}</pre>` : ''}
      `;
      renderRunActions(runId, run.status, repos);

      const isGhSbom = run.method === 'github_sbom';
      const repoTableHead = isGhSbom
        ? '<tr><th>Repo</th><th>SBOM</th><th>DT</th><th>Coverage</th><th></th></tr>'
        : '<tr><th>Repo</th><th>Manifests</th><th>Sanitize</th><th>ORT</th><th>DT</th><th>Coverage</th><th></th></tr>';

      document.getElementById('run-repos').innerHTML = repos.length
        ? `<table>
            <thead>${repoTableHead}</thead>
            <tbody>
              ${repos.map((r) => renderRepoRow(runId, r, isGhSbom)).join('')}
            </tbody>
          </table>
          <p class="muted stack-gap">${isGhSbom ? 'Click a row to inspect DT components.' : 'Click a row to inspect manifests (original vs sanitized) and DT components.'}</p>`
        : '<p class="muted">No repos yet.</p>';

      // Wire up drawer toggling on each row.
      document.querySelectorAll('[data-repo-row]').forEach((tr) => {
        tr.addEventListener('click', (ev) => {
          // Don't toggle when the click was on a link or action button.
          if (ev.target && (ev.target.tagName === 'A' || ev.target.tagName === 'BUTTON')) return;
          const { runId: rid, org, repo } = tr.dataset;
          openRepoDrawer(rid, org, repo);
        });
      });

      // If a drawer was open before the table was rebuilt (happens during
      // live polling), restore it now so the view doesn't jump closed.
      if (_drawerOpen.runId === runId && _drawerOpen.org && _drawerOpen.repo) {
        openRepoDrawer(runId, _drawerOpen.org, _drawerOpen.repo, /* restore= */ true);
      }

      if (isTerminal(run.status)) polling = false;
    } catch (err) {
      polling = false;
      document.getElementById('run-summary').innerHTML = `<pre class="log">${escapeHtml(err.message)}</pre>`;
    }
    if (polling) setTimeout(tick, 2000);
  }
  tick();
}

function renderRunActions(runId, status, repos) {
  const el = document.getElementById('run-actions');
  if (!el) return;
  const buttons = [];
  if (status === 'running' || status === 'queued') {
    buttons.push(actionButton('stop', 'Stop', 'secondary', async () => {
      await api.stopRun(runId);
    }));
  }
  if (status === 'failed' || status === 'partial' || status === 'stopped') {
    buttons.push(actionButton('continue', 'Continue', '', async () => {
      await api.continueRun(runId);
    }));
    const failedCount = (repos || []).filter((r) => r.ort_status === 'failed').length;
    if (failedCount > 0) {
      buttons.push(actionButton('retry-failed', `Retry failed (${failedCount})`, '', async () => {
        await api.retryFailed(runId);
        navigate(`/runs/${runId}`);
      }));
    }
  }
  if (isTerminal(status)) {
    buttons.push(actionButton('restart', 'Restart from scratch', 'secondary', async () => {
      const { run_id } = await api.restartRun(runId);
      window.location.href = `/runs/${run_id}`;
    }));
  }
  el.innerHTML = buttons.length ? '' : '<span class="muted">No actions available.</span>';
  for (const btn of buttons) el.appendChild(btn);
}

function actionButton(id, label, cls, onClick) {
  const btn = document.createElement('button');
  btn.id = `action-${id}`;
  btn.className = cls;
  btn.style.marginRight = '8px';
  btn.textContent = label;
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    try { await onClick(); } catch (err) { alert(err.message); }
    btn.disabled = false;
  });
  return btn;
}

function isTerminal(status) {
  return status === 'completed' || status === 'failed'
      || status === 'partial' || status === 'stopped';
}

function runStatusTag(status) {
  if (status === 'completed') return 'ok';
  if (status === 'failed') return 'fail';
  if (status === 'partial') return 'partial';
  if (status === 'stopped') return 'stopped';
  return 'running';
}

function stageTag(status) {
  if (status === 'completed' || status === 'ok') return 'ok';
  if (status === 'failed' || status === 'error') return 'fail';
  if (status === 'running' || status === 'in_progress') return 'running';
  return '';
}

// Tooltips for analyzer-issue tokens persisted by pipeline._classify_analyzer_log.
// The `kind` strings come straight from run_repos.analyzer_issue_kind so the
// frontend can pin a human-readable explanation without round-tripping to the
// server. Keep this in sync with _ANALYZER_LOG_PATTERNS in backend/pipeline.py.
const ANALYZER_ISSUE_TOOLTIPS = {
  python_inspector_recursion:
    'python-inspector hit RecursionError walking the resolved Poetry graph; one or more sub-projects silently dropped packages. Look for poetry_fallback_count > 0 to confirm the lockfile-based fallback rescued them.',
  python_resolver_failed:
    "ORT could not determine dependencies for at least one Python definition file (setup.py imports a missing module, README path mismatch, or python-inspector failed). See the .log file for the exact ERROR org.ossreviewtoolkit.plugins.packagemanagers.python.Pip line.",
  npm_yarn_workspace_alias:
    "npm refused a Yarn `npm:*` workspace alias and the registry got asked for `*@*`. Either replace the alias with a real version range or run a Yarn-native prelock.",
  npm_alias_unnamed:
    'NPM analyzer rejected an alias that did not include a name. Usually a malformed `dep@npm:` reference in package.json.',
  npm_version_not_found:
    "NPM resolver picked a version that doesn't exist in the registry (e.g. a yanked release). Often surfaces as ETARGET in prelock too.",
  package_json_malformed:
    'package.json has an invalid control character (raw newline / NUL inside a string literal). The sanitizer needs to escape these before npm sees them.',
  no_definition_files:
    'ORT found no manifests it knew how to analyse. Common causes: Go/Gradle disabled in settings.json, or pyproject.toml using only [tool.poetry] without a poetry.lock.',
  readme_missing:
    "setup.py tried to open('README').read() but the repo only has README.md. The mocker should symlink README -> README.md before ORT runs.",
};

function renderAnalyzerIssueBadges(r) {
  const raw = r.analyzer_issue_kind;
  if (!raw) return '';
  const kinds = String(raw).split(';').filter(Boolean);
  if (!kinds.length) return '';
  const fallbackNote = (r.poetry_fallback_count || 0) > 0
    ? ` <span class="tag ok" title="poetry_fallback parsed poetry.lock locally and merged ${r.poetry_fallback_count} component(s) into the BOM, rescuing the dropped Poetry sub-project.">+${r.poetry_fallback_count} fallback</span>`
    : '';
  const badges = kinds.map((kind) => {
    const tooltip = ANALYZER_ISSUE_TOOLTIPS[kind] || `Analyzer issue: ${kind}`;
    return `<span class="tag warn" title="${escapeHtml(tooltip)}">${escapeHtml(kind)}</span>`;
  }).join(' ');
  return ' ' + badges + fallbackNote;
}

function renderRepoRow(runId, r, isGhSbom = false) {
  // Coverage column shows a quick "DT vs declared" health check. The
  // numeric counts are advisory — populated post-ingest by
  // safe_upload_bom — so a missing value just renders as a dash.
  const dtCount = (r.dtrack_component_count == null) ? null : r.dtrack_component_count;
  const srcCount = (r.ort_package_count == null) ? null : r.ort_package_count;
  const srcLabel = isGhSbom ? 'GH' : 'ORT';
  let coverageBadge = '<span class="tag">—</span>';
  if (r.bom_overwrite_skipped) {
    coverageBadge = '<span class="tag warn" title="safe_upload_bom refused to overwrite a healthy DT project with an empty BOM.">overwrite refused</span>';
  } else if (dtCount != null && srcCount != null) {
    if (srcCount > 0 && dtCount === 0) {
      coverageBadge = `<span class="tag fail" title="${srcLabel} resolved ${srcCount} package(s) but DT shows 0 — ingest may have failed silently.">DT 0 / ${srcLabel} ${srcCount}</span>`;
    } else if (dtCount < srcCount * 0.75) {
      coverageBadge = `<span class="tag warn" title="DT count is &lt; 75% of ${srcLabel}'s package count.">DT ${dtCount} / ${srcLabel} ${srcCount}</span>`;
    } else {
      coverageBadge = `<span class="tag ok">DT ${dtCount} / ${srcLabel} ${srcCount}</span>`;
    }
  } else if (dtCount != null) {
    coverageBadge = `<span class="tag">DT ${dtCount}</span>`;
  } else if (srcCount != null) {
    coverageBadge = `<span class="tag">${srcLabel} ${srcCount}</span>`;
  }

  const sbomStatusCell = `
    <span class="tag ${stageTag(r.ort_status)}">${r.ort_status}</span>
    ${!isGhSbom && r.stale_for_seconds ? `<span class="tag warn" title="Log hasn't grown in ${Math.floor(r.stale_for_seconds / 60)}m ${r.stale_for_seconds % 60}s — could be slow registry fetches or a hung container.">⏰ no progress ${Math.floor(r.stale_for_seconds / 60)}m</span>` : ''}
    ${r.ort_status === 'completed' && r.ort_package_count === 0 && (isGhSbom || r.manifest_count > 0)
      ? `<span class="tag warn" title="${isGhSbom ? 'GitHub Dependency Graph returned 0 packages — dependency graph may be empty or newly enabled.' : 'ORT completed but resolved 0 packages. Check the .analyzer-result.json in the runs/ log dir.'}">0 packages</span>`
      : ''}
    ${!isGhSbom ? renderAnalyzerIssueBadges(r) : ''}
  `;

  const ortColumns = isGhSbom ? '' : `
      <td>${r.manifest_count}</td>
      <td><span class="tag ${stageTag(r.sanitize_status)}">${r.sanitize_status}</span></td>`;

  return `
    <tr data-repo-row data-run-id="${escapeHtml(runId)}" data-org="${escapeHtml(r.org)}" data-repo="${escapeHtml(r.repo)}">
      <td><span class="row-expander">&#9654;</span> ${escapeHtml(r.org)}/${escapeHtml(r.repo)}</td>
      ${ortColumns}
      <td>${sbomStatusCell}</td>
      <td>${r.dtrack_project_uuid ? '<span class="tag ok">ingested</span>' : '<span class="tag">—</span>'}</td>
      <td>${coverageBadge}</td>
      <td>
        ${r.error ? `<span class="muted" title="${escapeHtml(r.error)}">⚠</span>` : ''}
        ${r.ort_status === 'failed' ? `<button class="secondary btn-sm" data-retry-org="${escapeHtml(r.org)}" data-retry-repo="${escapeHtml(r.repo)}" data-retry-run="${escapeHtml(runId)}">Retry</button>` : ''}
      </td>
    </tr>
  `;
}

// Tracks which repo row is currently expanded.  Persisted across tick()
// rebuilds so live runs re-open the same drawer after each poll cycle.
const _drawerOpen = { runId: null, org: null, repo: null };

function _drawerRowId(org, repo) {
  return `drawer-${CSS.escape(org)}--${CSS.escape(repo)}`;
}

function _closeOpenDrawer() {
  if (!_drawerOpen.org) return;
  const existing = document.getElementById(_drawerRowId(_drawerOpen.org, _drawerOpen.repo));
  if (existing) existing.remove();
  // Clear the expanded indicator on the source row.
  const srcRow = document.querySelector(
    `tr[data-repo-row][data-org="${CSS.escape(_drawerOpen.org)}"][data-repo="${CSS.escape(_drawerOpen.repo)}"]`
  );
  if (srcRow) srcRow.removeAttribute('data-expanded');
  _drawerOpen.runId = null;
  _drawerOpen.org = null;
  _drawerOpen.repo = null;
}

async function openRepoDrawer(runId, org, repo, restore = false) {
  const isSame = _drawerOpen.runId === runId
               && _drawerOpen.org === org
               && _drawerOpen.repo === repo;

  // Toggle off when the same row is clicked again (but not during a poll restore).
  if (isSame && !restore) {
    _closeOpenDrawer();
    return;
  }

  // Close whichever drawer is currently open before opening the new one.
  _closeOpenDrawer();

  // Find the source row in the table.
  const srcRow = document.querySelector(
    `tr[data-repo-row][data-org="${CSS.escape(org)}"][data-repo="${CSS.escape(repo)}"]`
  );
  if (!srcRow) return;

  // Mark the row as expanded.
  srcRow.setAttribute('data-expanded', '');
  _drawerOpen.runId = runId;
  _drawerOpen.org = org;
  _drawerOpen.repo = repo;

  // Insert a loading placeholder row immediately after the source row.
  const drawerRow = document.createElement('tr');
  drawerRow.id = _drawerRowId(org, repo);
  drawerRow.className = 'drawer-row';
  const td = document.createElement('td');
  td.colSpan = 7;
  td.innerHTML = `<p class="muted">Loading manifests for ${escapeHtml(org)}/${escapeHtml(repo)}…</p>`;
  drawerRow.appendChild(td);
  srcRow.insertAdjacentElement('afterend', drawerRow);

  // Fetch data and fill in the drawer.
  let manifests = [];
  let dtComponents = null;
  try {
    const all = await api.listRunManifests(runId);
    manifests = (all || []).filter((m) => m.org === org && m.repo === repo);
  } catch (err) {
    td.innerHTML = `<pre class="log">${escapeHtml(err.message)}</pre>`;
    return;
  }
  try {
    dtComponents = await api.getRepoDtComponents(runId, org, repo);
  } catch (err) {
    dtComponents = { error: err.message };
  }

  // The row may have been removed while we awaited (e.g. run was stopped, page navigated away).
  if (!document.contains(drawerRow)) return;

  td.innerHTML = `
    <div class="drawer-section">
      <h3>${escapeHtml(org)}/${escapeHtml(repo)} — manifests &amp; coverage</h3>
      ${renderManifestsTable(runId, org, repo, manifests)}
    </div>
    <div class="drawer-section">
      <h3>Dependency-Track components</h3>
      ${renderDtPanel(dtComponents)}
    </div>
  `;
}

function renderManifestsTable(runId, org, repo, manifests) {
  if (!manifests.length) return '<p class="muted">No manifests recorded for this repo.</p>';
  const rows = manifests.map((m) => {
    const origCount = m.original_dep_count ?? '?';
    const sanCount = m.sanitized_dep_count ?? '?';
    const delta = (typeof m.original_dep_count === 'number' && typeof m.sanitized_dep_count === 'number')
      ? (m.original_dep_count - m.sanitized_dep_count)
      : null;
    const deltaStr = delta !== null && delta > 0
      ? ` <span class="muted">(-${delta} local/workspace deps stripped)</span>`
      : '';
    return `
      <tr>
        <td><code>${escapeHtml(m.filepath)}</code></td>
        <td>${escapeHtml(m.manifest_type)}</td>
        <td>${m.sanitized ? '<span class="tag ok">sanitized</span>' : '<span class="tag">raw</span>'}</td>
        <td>${origCount}</td>
        <td>${sanCount}${deltaStr}</td>
        <td><a href="#" data-diff-run="${escapeHtml(runId)}" data-diff-org="${escapeHtml(org)}" data-diff-repo="${escapeHtml(repo)}" data-diff-path="${escapeHtml(m.filepath)}">diff</a></td>
      </tr>`;
  }).join('');
  return `
    <table>
      <thead><tr><th>Path</th><th>Type</th><th>Status</th><th>Orig deps</th><th>Sanitized deps</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div id="manifest-diff-${escapeHtml(org)}-${escapeHtml(repo)}" class="gap-above"></div>
  `;
}

function renderDtPanel(body) {
  if (!body) return '<p class="muted">No data.</p>';
  if (body.error) return `<pre class="log">${escapeHtml(body.error)}</pre>`;
  const cov = body.coverage_ratio == null ? '?' : body.coverage_ratio;
  const head = `<p class="muted">DT components: <strong>${body.dt_component_count ?? '?'}</strong>
    · Sanitized declared: <strong>${body.sanitized_dep_total ?? '?'}</strong>
    · Coverage ratio: <strong>${cov}</strong>
    ${body.bom_overwrite_skipped ? ' · <span class="tag warn">overwrite refused</span>' : ''}
    ${body.live_error ? ` · <span class="tag fail" title="${escapeHtml(body.live_error)}">DT lookup failed</span>` : ''}</p>`;
  if (!body.components || !body.components.length) {
    return head + '<p class="muted">No components returned.</p>';
  }
  return head + `
    <table>
      <thead><tr><th>Group</th><th>Name</th><th>Version</th><th>purl</th></tr></thead>
      <tbody>
        ${body.components.slice(0, 200).map((c) => `
          <tr>
            <td>${escapeHtml(c.group)}</td>
            <td>${escapeHtml(c.name)}</td>
            <td>${escapeHtml(c.version)}</td>
            <td><code class="muted">${escapeHtml(c.purl)}</code></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    ${body.components.length > 200 ? `<p class="muted">… ${body.components.length - 200} more not shown.</p>` : ''}
  `;
}

// Wire up "diff" links inside the drawer.  Event-delegated on document so
// the handler works even after the drawer row is rebuilt by a poll tick.
document.addEventListener('click', async (ev) => {
  const a = ev.target.closest('[data-diff-path]');
  if (!a) return;
  ev.preventDefault();
  const { diffRun, diffOrg, diffRepo, diffPath } = a.dataset;
  // The diff output div is scoped per-repo so multiple open drawers
  // (future) don't clobber each other.
  const outId = `manifest-diff-${escapeHtml(diffOrg)}-${escapeHtml(diffRepo)}`;
  const out = document.getElementById(outId);
  if (!out) return;
  out.innerHTML = `<p class="muted">Loading diff for <code>${escapeHtml(diffPath)}</code>…</p>`;
  try {
    const body = await api.getRunManifest(diffRun, diffOrg, diffRepo, diffPath);
    out.innerHTML = `
      <h4 class="diff-heading"><code>${escapeHtml(diffPath)}</code></h4>
      <p class="muted diff-meta">Original: ${body.original_dep_count ?? '?'} dep(s) · Sanitized: ${body.sanitized_dep_count ?? '?'} dep(s)</p>
      <div class="drawer-diff">
        <div>
          <h5>Original</h5>
          <pre class="log">${escapeHtml(body.original || '(not stored)')}</pre>
        </div>
        <div>
          <h5>Sanitized (in sandbox)</h5>
          <pre class="log">${escapeHtml(body.sanitized || '(not stored)')}</pre>
        </div>
      </div>`;
  } catch (err) {
    out.innerHTML = `<pre class="log">${escapeHtml(err.message)}</pre>`;
  }
});

// Per-repo retry button — event-delegated so it survives table rebuilds.
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-retry-org]');
  if (!btn) return;
  ev.stopPropagation();
  btn.disabled = true;
  // dataset converts data-retry-org → retryOrg, data-retry-repo → retryRepo, etc.
  const { retryOrg: org, retryRepo: repo, retryRun: runId } = btn.dataset;
  try {
    await api.retryRepo(runId, org, repo);
    navigate(`/runs/${runId}`);
  } catch (err) {
    btn.disabled = false;
    alert(`Retry failed: ${err.message}`);
  }
});

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
