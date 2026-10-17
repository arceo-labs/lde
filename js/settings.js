import { api } from '/js/api.js';

// Small inline glyph marking a write-only secret field. Plain text, not an
// image — safe under the page's img-less CSP.
const LOCK_ICON = '<span class="secret-icon" title="Secret — masked, write-only">🔒</span>';

function renderGhStatusCard(gh) {
  const ghEl = document.getElementById('gh-status');
  if (!ghEl) return;
  if (!gh.installed) {
    ghEl.innerHTML = `
      <p><span class="tag fail">no PAT configured</span></p>
      <p class="muted">${escapeHtml(gh.raw || 'Add a GitHub Personal Access Token in the Settings form below.')}</p>
    `;
  } else if (!gh.logged_in) {
    ghEl.innerHTML = `
      <p><span class="tag fail">authentication failed</span></p>
      <p class="muted">${escapeHtml(gh.raw)}</p>
    `;
  } else {
    ghEl.innerHTML = `
      <p><span class="tag ok">authenticated</span></p>
      <pre class="log">${escapeHtml(gh.raw)}</pre>
      <p class="muted">For SSO-protected orgs, ensure the PAT is authorized for each org in your GitHub settings (Settings → Applications → Authorized OAuth Apps / Personal access tokens).</p>
    `;
  }
}

export async function renderSettings(root) {
  root.innerHTML = `
    <div class="card">
      <h2>GitHub PAT auth</h2>
      <div id="gh-status">Loading…</div>
    </div>
    <div class="card">
      <h2>Settings</h2>
      <div id="settings-form">Loading…</div>
    </div>
  `;

  const gh = await api.ghStatus();
  renderGhStatusCard(gh);

  const settings = await api.getSettings();
  const formEl = document.getElementById('settings-form');
  formEl.innerHTML = `
    <p><label>${LOCK_ICON} GitHub PAT (masked, write-only — paste new value to update)<br>
       <input id="s-ghpat" type="password" placeholder="${escapeHtml(settings.github_pat || '')}"></label></p>
    <p><button id="test-ghpat" type="button">Test PAT</button>
       <span id="ghpat-status" class="muted"></span>
       <br><span class="muted hint">Tests the saved PAT against GitHub and refreshes the card above — Save first if you just changed it.</span></p>
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

  document.getElementById('test-ghpat').addEventListener('click', async () => {
    const status = document.getElementById('ghpat-status');
    status.innerHTML = 'Testing…';
    try {
      const r = await api.ghStatus();
      renderGhStatusCard(r);
      if (r.installed && r.logged_in) {
        status.innerHTML = `<span class="tag ok">authenticated</span> ${escapeHtml(r.raw)}`;
      } else {
        status.innerHTML = `<span class="tag fail">${r.installed ? 'failed' : 'not configured'}</span> ${escapeHtml(r.raw)}`;
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
    const newPat = document.getElementById('s-ghpat').value;
    if (newPat) patch.github_pat = newPat;
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
      status.textContent = 'Saved.';
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
