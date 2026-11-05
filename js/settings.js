import { api } from '/js/api.js';

// Small inline glyph marking a write-only secret field. Plain text, not an
// image — safe under the page's img-less CSP.
const LOCK_ICON = '<span class="secret-icon" title="Secret — masked, write-only">🔒</span>';

const KEY_SOURCE_LABEL = {
  file: 'loaded from github_app_private_key_path',
  secrets_manager: 'loaded from the lde/github-app secret',
};

// Fixed reasons the setup callback can redirect back with (?gh_app_error=<reason>).
const SETUP_ERRORS = {
  state: 'The setup link was unknown, already used or expired. Start again.',
  exchange: 'GitHub did not hand over the new app. The code is single-use and expires after an hour: start again.',
  store: 'LDE could not store the new app\'s private key. Check the server log, then start again.',
  exists: 'That org already has a GitHub App in LDE, so the new one was not saved. Delete the unused app on GitHub.',
  config: 'The GitHub App configuration is broken, so the new app was not saved. Fix it (see the card), then delete the unused app on GitHub and start again.',
};

function createAppHtml() {
  return `<details id="gh-app-create">
    <summary>Create a GitHub App for another org</summary>
    <p class="muted hint">GitHub creates a private, read-only app (Contents and Metadata) owned by the org, with no webhook. LDE stores its private key on the server; the key never reaches this page. Only an owner of the org can create it. Several orgs in one GitHub Enterprise? You can instead add one enterprise-owned app by hand (docs/github-app.md).</p>
    <p><label>Org (blank = your personal account)<br>
       <input id="ga-org" type="text" maxlength="39" autocomplete="off" placeholder="my-org"></label></p>
    <p><label>App name (must be unique on GitHub; blank picks one)<br>
       <input id="ga-name" type="text" maxlength="34" autocomplete="off" placeholder="LDE my-org"></label></p>
    <p><button id="ga-create" type="button">Create GitHub App on GitHub</button>
       <span id="ga-status" class="muted"></span></p>
  </details>`;
}

// Start GitHub's manifest flow: LDE returns the manifest, the browser form-posts it to github.com.
async function createApp(org, name, statusEl) {
  statusEl.textContent = 'Preparing…';
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
    statusEl.textContent = `Failed: ${err.message}`;
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
    el.addEventListener('click', () => createApp(el.dataset.org, '', el.nextElementSibling));
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

function appRowHtml(app) {
  const tag = app.ok ? '<span class="tag ok">app</span>' : '<span class="tag fail">app</span>';
  const name = app.name || app.slug || `App ${app.app_id}`;
  const owner = app.owner ? ` <span class="muted">owned by ${escapeHtml(app.owner)}</span>` : '';
  const src = KEY_SOURCE_LABEL[app.key_source] ? ` <span class="muted">(key ${KEY_SOURCE_LABEL[app.key_source]})</span>` : '';
  const url = app.ok ? safeInstallUrl(app) : '';
  const manage = url ? ` · <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Manage on GitHub</a>` : '';
  const msg = app.ok ? '' : ` ${escapeHtml(app.message)}`;
  return `<li>${tag} ${escapeHtml(name)}${owner}${src}${manage}${msg}</li>`;
}

function renderGhStatusCard(gh) {
  const ghEl = document.getElementById('gh-status');
  if (!ghEl) return;
  const notice = gh.notice ? `<p><span class="tag warn">deprecated config</span> ${escapeHtml(gh.notice)}</p>` : '';
  if (!gh.installed) {
    ghEl.innerHTML = `${setupResult}${notice}
      <p><span class="tag fail">not configured</span> ${escapeHtml(gh.raw || '')}</p>
      ${createAppHtml().replace('<details id="gh-app-create">', '<details id="gh-app-create" open>').replace('for another org', 'for your org')}
    `;
    wireCreateApp();
    return;
  }
  const apps = gh.apps || [];
  const appsError = gh.apps_error
    ? `<p><span class="tag fail">GitHub App config</span> ${escapeHtml(gh.apps_error)}</p>` : '';
  const appList = apps.length
    ? `<p><strong>GitHub Apps</strong></p><ul class="gh-orgs">${apps.map(appRowHtml).join('')}</ul>`
    : '<p><span class="tag warn">no GitHub App</span> Using PATs only (deprecated).</p>';
  const rows = (gh.accounts || []).map((a) => {
    const label = a.org === '*' ? 'all other orgs (*)' : a.org;
    const via = a.via === 'app' ? (a.app ? `app: ${a.app}` : 'app') : a.via === 'pat' ? 'PAT' : 'none';
    const cls = !a.ok ? 'fail' : a.via === 'pat' ? 'warn' : 'ok';
    // An org without an app gets its own private app through the manifest flow.
    const create = (a.org !== '*' && a.via !== 'app' && !gh.apps_error)
      ? ` <button type="button" class="secondary ga-create-org" data-org="${escapeHtml(a.org)}">Create app for ${escapeHtml(a.org)}</button><span class="muted"></span>`
      : '';
    return `<li><span class="tag ${cls}">${escapeHtml(via)}</span> ${escapeHtml(label)}${a.user ? ` <span class="muted">as ${escapeHtml(a.user)}</span>` : ''}${create}</li>`;
  }).join('');
  const overall = gh.logged_in
    ? '<span class="tag ok">authenticated</span>'
    : '<span class="tag fail">authentication incomplete</span>';
  ghEl.innerHTML = `${setupResult}${notice}
    <p>${overall}</p>
    ${appsError}
    ${appList}
    ${rows ? `<p><strong>Orgs</strong></p><ul class="gh-orgs">${rows}</ul>` : ''}
    <pre class="log">${escapeHtml(gh.raw)}</pre>
    ${gh.apps_error ? '' : createAppHtml()}
  `;
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

  // The status card checks the app and every org against GitHub, which can be slow:
  // load it in the background so it never blocks the form.
  api.ghStatus().then(renderGhStatusCard).catch((err) => {
    const ghEl = document.getElementById('gh-status');
    if (ghEl) ghEl.innerHTML = `<p><span class="tag fail">error</span> ${escapeHtml(err.message)}</p>`;
  });

  let settings;
  try {
    settings = await api.getSettings();
  } catch (err) {
    document.getElementById('settings-form').innerHTML =
      `<p><span class="tag fail">error</span> Could not load settings: ${escapeHtml(err.message)}</p>`;
    return;
  }
  const formEl = document.getElementById('settings-form');
  const patCount = Object.keys(settings.github_pats || {}).length;
  formEl.innerHTML = `
    <div id="app-section">
      <p><button id="test-gh" type="button">Test GitHub Apps</button>
         <span id="gh-test-status" class="muted"></span>
         <br><span class="muted hint">Checks every GitHub App and which app or PAT covers each org, and refreshes the card above. Apps are created from the card; an app added by hand goes in <code>github_apps</code> in <code>.settings.json</code> or the <code>lde/github-app</code> secret (docs/github-app.md).</span></p>
    </div>
    <details id="pat-section"${patCount ? ' open' : ''}>
      <summary>Legacy PATs (deprecated, ${patCount} saved)</summary>
      <p>${LOCK_ICON} Used only for orgs the GitHub App is not installed on — one fine-grained token per org (masked, write-only)</p>
      <div id="pat-rows">${Object.entries(settings.github_pats || {}).map(([org, masked]) => patRowHtml(org, masked)).join('')}</div>
      <p><button id="pat-add" type="button" class="secondary">Add org</button>
         <button id="pat-add-all" type="button" class="secondary">Add token for all other orgs</button>
         <span class="muted hint">The <code>*</code> row is used for any org without its own row and without the GitHub App. Leave a saved row's token blank to keep it; type to replace it.</span></p>
    </details>
    <p><label>Default orgs (comma separated)<br>
       <input id="s-orgs" type="text" value="${(settings.default_orgs || []).join(',')}"></label></p>
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

  const patRows = document.getElementById('pat-rows');
  document.getElementById('pat-add').addEventListener('click', () => {
    patRows.insertAdjacentHTML('beforeend', patRowHtml('', ''));
    patRows.lastElementChild.querySelector('.pat-org').focus();
  });
  document.getElementById('pat-add-all').addEventListener('click', () => {
    const existing = [...patRows.querySelectorAll('.pat-org')].find((el) => el.value.trim() === '*');
    if (existing) {
      existing.closest('.pat-row').querySelector('.pat-token').focus();
      return;
    }
    patRows.insertAdjacentHTML('beforeend', patRowHtml('*', '', true));
    patRows.lastElementChild.querySelector('.pat-token').focus();
  });
  patRows.addEventListener('click', async (ev) => {
    const row = ev.target.closest('.pat-row');
    if (!row) return;
    if (ev.target.classList.contains('pat-remove')) {
      if (row.dataset.saved) {
        row.classList.toggle('removed');
        ev.target.textContent = row.classList.contains('removed') ? 'Undo' : 'Remove';
      } else {
        row.remove();
      }
    }
  });

  document.getElementById('test-gh').addEventListener('click', async () => {
    const status = document.getElementById('gh-test-status');
    status.innerHTML = 'Testing…';
    try {
      const r = await api.ghStatus();
      renderGhStatusCard(r);
      const summary = escapeHtml(r.raw).replace(/\n/g, ' · ');
      if (r.installed && r.logged_in) {
        status.innerHTML = `<span class="tag ok">authenticated</span> ${summary}`;
      } else {
        status.innerHTML = `<span class="tag fail">${r.installed ? 'failed' : 'not configured'}</span> ${summary}`;
      }
    } catch (err) {
      status.innerHTML = `<span class="tag fail">error</span> ${escapeHtml(err.message)}`;
    }
  });

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
      default_orgs: document.getElementById('s-orgs').value.split(',').map((s) => s.trim()).filter(Boolean),
      dtrack_url: document.getElementById('s-dturl').value.trim(),
      dtrack_ui_url: document.getElementById('s-dtuiurl').value.trim(),
      ort_image: document.getElementById('s-ort').value.trim(),
      ort_egress_network: document.getElementById('s-net').value.trim(),
    };
    const pats = {};
    const incomplete = [];
    for (const row of patRows.querySelectorAll('.pat-row')) {
      const org = row.querySelector('.pat-org').value.trim();
      const token = row.querySelector('.pat-token').value.trim();
      if (row.classList.contains('removed')) {
        if (org) pats[org] = '';
      } else if (token && !org) {
        incomplete.push('a token has no org name');
      } else if (org && !token && !row.dataset.saved) {
        incomplete.push(`${org} has no token`);
      } else if (org && token) {
        pats[org] = token;
      }
    }
    if (incomplete.length) {
      // textContent, not innerHTML: org names are user input.
      document.getElementById('save-status').textContent =
        `Not saved: ${incomplete.join('; ')}. Fill in both fields or remove the row.`;
      return;
    }
    if (Object.keys(pats).length) patch.github_pats = pats;
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

function patRowHtml(org, masked, isNew = false) {
  const saved = Boolean(org) && !isNew;
  const title = org === '*' ? ' title="Used for any org without its own row"' : '';
  return `<div class="pat-row"${saved ? ' data-saved="1"' : ''}>
    <input class="pat-org" type="text" aria-label="GitHub org" placeholder="org name" autocomplete="off" value="${escapeHtml(org)}"${title}${org ? ' readonly' : ''}>
    <input class="pat-token" type="password" aria-label="${escapeHtml(org ? `Token for ${org}` : 'GitHub token')}" autocomplete="off" placeholder="${escapeHtml(saved ? `${masked} (saved — type to replace)` : 'github_pat_…')}">
    <button type="button" class="secondary pat-remove">Remove</button>
  </div>`;
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
