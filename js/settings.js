import { api } from '/js/api.js';

// Small inline glyph marking a write-only secret field. Plain text, not an
// image — safe under the page's img-less CSP.
const LOCK_ICON = '<span class="secret-icon" title="Secret — masked, write-only">🔒</span>';

const AUTH_LABEL = {
  app: 'own GitHub App',
  enterprise: 'enterprise app',
  pat: 'PAT (deprecated)',
  none: 'none',
};

// Fixed reasons the setup callback can redirect back with (?gh_app_error=<reason>).
const SETUP_ERRORS = {
  state: 'The setup link was unknown, already used or expired. Start again.',
  exchange: 'GitHub did not hand over the new app. The code is single-use and expires after an hour: start again.',
  store: 'LDE could not store the new app\'s private key. Check the server log, then start again.',
  exists: 'That org already has its own GitHub App in LDE, so the new one was not saved. Delete the unused app on GitHub.',
  config: 'The GitHub config is broken, so the new app was not saved. Fix it (see the card), then delete the unused app on GitHub and start again.',
};

function createAppHtml(open = false) {
  return `<details id="gh-app-create"${open ? ' open' : ''}>
    <summary>Create a GitHub App for an org not listed yet</summary>
    <p class="muted hint">GitHub creates a private, read-only app (Contents and Metadata) owned by the org, with no webhook, and LDE adds the org with scan on. LDE stores the app's private key on the server; the key never reaches this page. Only an owner of the org can create it. Several orgs in one GitHub Enterprise? You can instead add one enterprise-owned app by hand (docs/github-app.md).</p>
    <p><label>Org (blank = your personal account)<br>
       <input id="ga-org" type="text" maxlength="39" autocomplete="off" placeholder="my-org"></label></p>
    <p><label>App name (must be unique on GitHub; blank picks one)<br>
       <input id="ga-name" type="text" maxlength="34" autocomplete="off" placeholder="LDE my-org"></label></p>
    <p><button id="ga-create" type="button">Create GitHub App on GitHub</button></p>
    <div id="ga-status" class="status-msg" role="status"></div>
  </details>`;
}

// Show a status or error message under the control that caused it. textContent
// only: messages are server text, never HTML. Inside an org table, the message
// lives in its own full-width row, shown only while it has text.
function showStatus(el, text, isError = false) {
  el.textContent = text;
  el.classList.toggle('is-error', isError);
  const row = el.closest('.gh-msg-row');
  if (row) row.hidden = !text;
}

function rowStatus(tr) {
  return tr.nextElementSibling.querySelector('.gh-row-status');
}

// Start GitHub's manifest flow: LDE returns the manifest, the browser form-posts it to github.com.
async function createApp(org, name, statusEl) {
  showStatus(statusEl, 'Preparing…');
  try {
    const r = await api.ghAppManifest({ org, name });
    if (typeof r.action !== 'string' || !r.action.startsWith('https://github.com/')) {
      throw new Error('unexpected setup URL');
    }
    // Built with the DOM, not innerHTML: the manifest is posted as an opaque value.
    const form = document.createElement('form');
    form.method = 'post';
    form.action = r.action;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'manifest';
    input.value = r.manifest;
    form.append(input);
    document.body.append(form);
    form.submit();
  } catch (err) {
    showStatus(statusEl, `Failed: ${err.message}`, true);
  }
}

function wireCreateApp() {
  const btn = document.getElementById('ga-create');
  if (btn) {
    btn.addEventListener('click', () => createApp(
      document.getElementById('ga-org').value.trim(),
      document.getElementById('ga-name').value.trim(),
      document.getElementById('ga-status')));
  }
  for (const el of document.querySelectorAll('.ga-create-org')) {
    el.addEventListener('click', () => createApp(el.dataset.org, '', rowStatus(el.closest('tr'))));
  }
}

function setupResultHtml() {
  const params = new URLSearchParams(window.location.search);
  const reason = params.get('gh_app_error');
  const created = params.get('gh_app') === 'created';
  const installed = params.get('setup_action') === 'install';
  if (reason || created || installed) {
    window.history.replaceState(null, '', window.location.pathname);
  }
  if (reason) {
    return `<p><span class="tag fail">GitHub App setup failed</span> ${escapeHtml(SETUP_ERRORS[reason] || 'Unknown error. Check the server log.')}</p>`;
  }
  if (installed) return '<p><span class="tag ok">installed</span> GitHub App installed. LDE picks up a new install within five minutes.</p>';
  if (created) return '<p><span class="tag ok">created</span> GitHub App created. Install it on its org.</p>';
  return '';
}

let setupResult = '';

// install_url is built server-side from a validated slug; check the scheme here too.
function safeInstallUrl(app) {
  return (typeof app.install_url === 'string' && app.install_url.startsWith('https://github.com/apps/'))
    ? app.install_url : '';
}

function authOptions(row, enterprise) {
  const kinds = ['pat', 'none'];
  if (enterprise || row.auth === 'enterprise') kinds.unshift('enterprise');
  if (row.auth === 'app') kinds.unshift('app');  // an app is only ever created, never picked
  return kinds.map((k) => `<option value="${k}"${k === row.auth ? ' selected' : ''}>${escapeHtml(AUTH_LABEL[k])}</option>`).join('');
}

function orgRowHtml(row, enterprise) {
  const org = escapeHtml(row.org);
  const cls = !row.ok ? 'fail' : row.auth === 'pat' ? 'warn' : 'ok';
  const status = `<span class="tag ${cls}">${row.ok ? 'ok' : row.auth === 'none' ? 'not set up' : 'failed'}</span><span class="gh-msg">${escapeHtml(row.message)}${row.user ? ` <span class="muted">as ${escapeHtml(row.user)}</span>` : ''}</span>`;
  const url = (row.auth === 'app' || row.auth === 'enterprise') ? safeInstallUrl(row) : '';
  const manage = url ? `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Manage on GitHub</a>` : '';
  const create = row.auth !== 'app'
    ? `<button type="button" class="secondary ga-create-org" data-org="${org}">Create app for ${org}</button>`
    : '';
  const tokenPlaceholder = row.token_hint ? `${row.token_hint} (saved)` : 'github_pat_…';
  return `<tr class="gh-org-row" data-org="${org}" data-auth="${escapeHtml(row.auth)}">
    <td class="gh-org">${org}</td>
    <td class="gh-auth-cell" data-label="Auth"><select class="gh-auth" aria-label="Auth for ${org}">${authOptions(row, enterprise)}</select>
        <input class="gh-token" type="password" autocomplete="off" aria-label="PAT for ${org}" title="Type a new token to replace the saved one" placeholder="${escapeHtml(tokenPlaceholder)}"${row.auth === 'pat' ? '' : ' hidden'}></td>
    <td class="gh-scan-cell" data-label="Scan"><input class="gh-scan" type="checkbox" aria-label="Scan ${org} by default"${row.scan ? ' checked' : ''}></td>
    <td class="gh-status-cell" data-label="Status">${status}</td>
    <td class="gh-actions"><div class="gh-actions-inner"><button type="button" class="gh-save">Save</button>
        <button type="button" class="secondary gh-remove">Remove</button>
        ${manage} ${create}</div></td>
  </tr>
  <tr class="gh-msg-row" hidden><td colspan="5"><div class="status-msg gh-row-status" role="status"></div></td></tr>`;
}

function enterpriseHtml(ent) {
  if (!ent) return '';
  const tag = ent.ok ? '<span class="tag ok">enterprise app</span>' : '<span class="tag fail">enterprise app</span>';
  const url = ent.ok ? safeInstallUrl(ent) : '';
  const manage = url ? ` · <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Manage on GitHub</a>` : '';
  return `<p>${tag} ${escapeHtml(ent.name || `App ${ent.app_id}`)} <span class="muted">for enterprise ${escapeHtml(ent.enterprise)}</span>${manage} ${ent.ok ? '' : escapeHtml(ent.message)}</p>`;
}

const SOURCE_LABEL = {
  secret: 'the lde/github secret',
  file: '"github" in .settings.json',
  legacy: 'the old settings keys (saving any org moves them)',
};

async function saveOrgRow(tr, btn) {
  const out = rowStatus(tr);
  const auth = tr.querySelector('.gh-auth').value;
  // Leaving the org's own app drops its App ID and key from LDE; getting it back
  // means creating a new app. Ask for a second click.
  if (tr.dataset.auth === 'app' && auth !== 'app' && !btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = 'Click again: this drops the org\'s app';
    return;
  }
  const body = { auth, scan: tr.querySelector('.gh-scan').checked };
  const token = tr.querySelector('.gh-token').value.trim();
  if (auth === 'pat' && token) body.token = token;
  showStatus(out, 'Saving…');
  try {
    await api.putGithubOrg(tr.dataset.org, body);
    await refreshGhStatus();
  } catch (err) {
    showStatus(out, `Failed: ${err.message}`, true);
  }
}

async function removeOrgRow(tr, btn) {
  if (!btn.dataset.armed) {
    btn.dataset.armed = '1';
    btn.textContent = 'Click again to remove';
    return;
  }
  const out = rowStatus(tr);
  try {
    await api.deleteGithubOrg(tr.dataset.org);
    await refreshGhStatus();
  } catch (err) {
    showStatus(out, `Failed: ${err.message}`, true);
  }
}

function wireOrgTable() {
  for (const tr of document.querySelectorAll('.gh-org-row')) {
    const select = tr.querySelector('.gh-auth');
    select.addEventListener('change', () => {
      tr.querySelector('.gh-token').hidden = select.value !== 'pat';
    });
    const save = tr.querySelector('.gh-save');
    save.addEventListener('click', () => saveOrgRow(tr, save));
    const rm = tr.querySelector('.gh-remove');
    rm.addEventListener('click', () => removeOrgRow(tr, rm));
  }
  const add = document.getElementById('gh-add-org');
  if (add) {
    add.addEventListener('click', async () => {
      const input = document.getElementById('gh-new-org');
      const out = document.getElementById('gh-add-status');
      const org = input.value.trim();
      if (!org) return;
      showStatus(out, 'Adding…');
      try {
        await api.putGithubOrg(org, {});
        await refreshGhStatus();
      } catch (err) {
        showStatus(out, `Failed: ${err.message}`, true);
      }
    });
  }
  const refresh = document.getElementById('gh-refresh');
  if (refresh) refresh.addEventListener('click', () => refreshGhStatus());
}

async function refreshGhStatus() {
  const ghEl = document.getElementById('gh-status');
  try {
    renderGhStatusCard(await api.ghStatus());
  } catch (err) {
    if (ghEl) ghEl.innerHTML = `<p><span class="tag fail">error</span> ${escapeHtml(err.message)}</p>`;
  }
}

function renderGhStatusCard(gh) {
  const ghEl = document.getElementById('gh-status');
  if (!ghEl) return;
  const notice = gh.notice ? `<div class="callout warn"><span class="tag warn">notice</span> ${escapeHtml(gh.notice)}</div>` : '';
  const refresh = '<button id="gh-refresh" type="button" class="secondary">Check again</button>';
  if (gh.config_error) {
    ghEl.innerHTML = `${setupResult}${notice}
      <p><span class="tag fail">GitHub config broken</span> ${escapeHtml(gh.config_error)}</p>
      <p class="muted hint">Every GitHub call fails until this is fixed in ${gh.source === 'secret' ? 'the lde/github secret' : '.settings.json'} (docs/github-app.md). ${refresh}</p>`;
    wireOrgTable();
    return;
  }
  const orgs = gh.orgs || [];
  const overall = !gh.installed
    ? '<span class="tag fail">not configured</span>'
    : gh.logged_in ? '<span class="tag ok">authenticated</span>'
      : '<span class="tag fail">authentication incomplete</span>';
  const source = SOURCE_LABEL[gh.source] ? `<span class="muted">Orgs are stored in ${escapeHtml(SOURCE_LABEL[gh.source])}.</span>` : '';
  const table = orgs.length
    ? `<div class="table-scroll"><table class="data-table gh-org-table">
        <thead><tr><th>Org</th><th>Auth</th><th>Scan</th><th>Status</th><th></th></tr></thead>
        <tbody>${orgs.map((o) => orgRowHtml(o, gh.enterprise_app)).join('')}</tbody>
      </table></div>`
    : `<p class="muted">${escapeHtml(gh.raw || '')}</p>`;
  ghEl.innerHTML = `${setupResult}${notice}
    <div class="gh-toolbar">${overall} ${refresh} ${source}</div>
    ${enterpriseHtml(gh.enterprise_app)}
    ${table}
    <p class="muted hint"><strong>Scan</strong> puts the org in runs that name no orgs. <strong>Create app for &lt;org&gt;</strong> makes a private read-only app owned by that org and switches the org to it. PATs are deprecated: one fine-grained token per org, write-only.</p>
    <p class="gh-add"><input id="gh-new-org" type="text" maxlength="39" autocomplete="off" aria-label="New org name" placeholder="org name">
       <button id="gh-add-org" type="button" class="secondary">Add org</button></p>
    <div id="gh-add-status" class="status-msg" role="status"></div>
    ${createAppHtml(!orgs.length)}
  `;
  wireOrgTable();
  wireCreateApp();
}

export async function renderSettings(root) {
  setupResult = setupResultHtml() || setupResult;
  root.innerHTML = `
    <div class="card">
      <h2>GitHub auth</h2>
      <div id="gh-status">Loading…</div>
    </div>
    <div class="card">
      <h2>Settings</h2>
      <div id="settings-form">Loading…</div>
    </div>
  `;

  // The status card checks every org against GitHub, which can be slow: load it in
  // the background so it never blocks the form.
  refreshGhStatus();

  let settings;
  try {
    settings = await api.getSettings();
  } catch (err) {
    document.getElementById('settings-form').innerHTML =
      `<p><span class="tag fail">error</span> Could not load settings: ${escapeHtml(err.message)}</p>`;
    return;
  }
  const formEl = document.getElementById('settings-form');
  formEl.innerHTML = `
    <p><label>Dependency-Track API URL (used for API calls)<br>
       <input id="s-dturl" type="text" value="${escapeHtml(settings.dtrack_url || '')}"></label></p>
    <p><label>Dependency-Track UI URL (used for deep links in Package Search)<br>
       <input id="s-dtuiurl" type="text" value="${escapeHtml(settings.dtrack_ui_url || '')}"></label></p>
    <p><label>${LOCK_ICON} Dependency-Track API key (masked, write-only)<br>
       <input id="s-dtkey" type="password" placeholder="${escapeHtml(settings.dtrack_api_key || '')}"></label></p>
    <p><button id="test-dtkey" type="button">Test DT API key</button>
       <span id="dtkey-status" class="muted"></span>
       <br><span class="muted hint">Tests the saved key against the saved API URL — Save first if you just changed either.</span></p>
    <p><label>${LOCK_ICON} Gemini API key — used for URL-based package extraction (masked, write-only)<br>
       <input id="s-gemini" type="password" placeholder="${escapeHtml(settings.gemini_api_key || '')}"></label></p>
    <p><button id="test-gemini" type="button">Test Gemini key</button>
       <span id="gemini-status" class="muted"></span>
       <br><span class="muted hint">Free metadata lookup against the saved key and model — no generation call, no cost. Save first if you just changed either.</span></p>
    <p><label>Gemini model<br>
       <input id="s-gemini-model" type="text" list="gemini-model-suggestions"
              value="${escapeHtml(settings.gemini_model || '')}"
              placeholder="gemini-3.8-flash"></label>
       <datalist id="gemini-model-suggestions">
         <option value="gemini-3.8-flash"></option>
         <option value="gemini-3.1-pro-preview"></option>
         <option value="gemini-2.5-pro"></option>
         <option value="gemini-2.5-flash"></option>
       </datalist>
       <br><span class="muted hint">Passed to the Gemini generateContent API. Takes effect on the next extract. Override with LDE_GEMINI_MODEL.</span></p>
    <p class="muted"><strong>ORT is deprecated.</strong> The Ingest Dependencies form no longer offers it; these two settings only affect local <code>POST /api/runs</code> calls with <code>"method": "ort"</code>.</p>
    <p><label>ORT image tag<br>
       <input id="s-ort" type="text" value="${escapeHtml(settings.ort_image || '')}"></label></p>
    <p><label>ORT egress network name<br>
       <input id="s-net" type="text" value="${escapeHtml(settings.ort_egress_network || '')}"></label></p>
    <p><button id="save">Save</button> <span id="save-status" class="muted"></span></p>
  `;

  document.getElementById('test-gemini').addEventListener('click', async () => {
    const status = document.getElementById('gemini-status');
    status.innerHTML = 'Testing…';
    try {
      const r = await api.geminiStatus();
      if (r.ok) {
        const warn = r.supports_generate ? '' : ' <span class="tag warn">no generateContent support</span>';
        status.innerHTML = `<span class="tag ok">valid</span> ${escapeHtml(r.message)}${warn}`;
      } else {
        status.innerHTML = `<span class="tag fail">failed</span> ${escapeHtml(r.message)}`;
      }
    } catch (err) {
      status.innerHTML = `<span class="tag fail">error</span> ${escapeHtml(err.message)}`;
    }
  });

  document.getElementById('test-dtkey').addEventListener('click', async () => {
    const status = document.getElementById('dtkey-status');
    status.innerHTML = 'Testing…';
    try {
      const r = await api.dtrackStatus();
      if (r.ok) {
        const perms = (r.permissions || []).length
          ? ` <span class="muted">(${escapeHtml((r.permissions || []).join(', '))})</span>`
          : '';
        status.innerHTML = `<span class="tag ok">valid</span> ${escapeHtml(r.message)}${perms}`;
      } else {
        status.innerHTML = `<span class="tag fail">failed</span> ${escapeHtml(r.message)}`;
      }
    } catch (err) {
      status.innerHTML = `<span class="tag fail">error</span> ${escapeHtml(err.message)}`;
    }
  });

  document.getElementById('save').addEventListener('click', async () => {
    const patch = {
      dtrack_url: document.getElementById('s-dturl').value.trim(),
      dtrack_ui_url: document.getElementById('s-dtuiurl').value.trim(),
      ort_image: document.getElementById('s-ort').value.trim(),
      ort_egress_network: document.getElementById('s-net').value.trim(),
    };
    const newKey = document.getElementById('s-dtkey').value;
    if (newKey) patch.dtrack_api_key = newKey;
    const newGeminiKey = document.getElementById('s-gemini').value;
    if (newGeminiKey) patch.gemini_api_key = newGeminiKey;
    const geminiModel = document.getElementById('s-gemini-model').value.trim();
    if (geminiModel) patch.gemini_model = geminiModel;
    const status = document.getElementById('save-status');
    status.textContent = 'Saving…';
    try {
      await api.putSettings(patch);
      await renderSettings(root);
      document.getElementById('save-status').textContent = 'Saved.';
    } catch (err) {
      status.textContent = `Failed: ${err.message}`;
    }
  });
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
