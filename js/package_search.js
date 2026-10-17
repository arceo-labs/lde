import { api } from '/js/api.js';

// Fallback prompt for when in-app Gemini extraction hits token/time limits.
// Copied verbatim to the clipboard; keep every blank line exactly as specified.
const FALLBACK_EXTRACT_PROMPT = `You are a security researcher reviewing a software vulnerability advisory or blog post.
Your task is to extract the names of affected npm and PyPI packages mentioned in the text.

STRICT SCOPE — only include:
- npm packages (JavaScript/Node.js, published to npmjs.com)
- PyPI packages (Python, published to pypi.org)

DO NOT include:
- IP addresses, domain names, URLs, file hashes, or any other network indicators
- Operating system packages (apt, rpm, brew, etc.)
- Maven, NuGet, RubyGems, Go modules, Cargo, or any other ecosystem
- CVE identifiers, version ranges, or standalone version numbers
- Generic tool names, binary names, or framework names that are not package manager entries
- Invented or hallucinated package names

Return ONLY newline delimited. Each line has exactly this format: the exact package name as it appears on npm or PyPI
                (e.g. "async-waterfall", "@babel/core", "requests", "pillow")
Sort them in alphabetical order.

If no qualifying packages are mentioned, return "No Packages Found"
Return an alphabetically sorted, newline delimited list of packages only — no markdown fences, no commentary.
`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function setHtml(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function hideEl(el) {
  if (!el) return;
  el.hidden = true;
  el.classList.add('hidden');
}

function showEl(el) {
  if (!el) return;
  el.hidden = false;
  el.classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Results rendering with pagination
// ---------------------------------------------------------------------------

const PAGE_SIZE = 25;
let _allResults = [];
let _currentPage = 0;

function renderResultsPage(page) {
  const results = _allResults;
  const totalPages = Math.ceil(results.length / PAGE_SIZE);
  const start = page * PAGE_SIZE;
  const pageItems = results.slice(start, start + PAGE_SIZE);

  const rows = [];
  let pageMatches = 0;

  for (const r of pageItems) {
    if (r.error) {
      rows.push(`<tr>
        <td><code>${escapeHtml(r.query)}</code></td>
        <td colspan="4" class="muted">Error: ${escapeHtml(r.error)}</td>
      </tr>`);
      continue;
    }
    if (!r.matches || r.matches.length === 0) {
      rows.push(`<tr>
        <td><code>${escapeHtml(r.query)}</code></td>
        <td colspan="4" class="muted">Not found</td>
      </tr>`);
      continue;
    }
    pageMatches += r.matches.length;
    for (let i = 0; i < r.matches.length; i++) {
      const m = r.matches[i];
      const projectLabel = m.project_version
        ? `${escapeHtml(m.project)}/${escapeHtml(m.project_version)}`
        : escapeHtml(m.project);
      const projectHref = m.project_link
        ? `<a href="${escapeHtml(m.project_link)}" target="_blank" rel="noopener noreferrer">${projectLabel} ↗</a>`
        : `<span>${projectLabel}</span>`;
      const graphLink = m.dep_graph_link
        ? `<a href="${escapeHtml(m.dep_graph_link)}" target="_blank" rel="noopener noreferrer" title="Dep graph (may be slow for large projects)">graph ↗</a>`
        : '';
      rows.push(`<tr>
        ${i === 0 ? `<td rowspan="${r.matches.length}"><code>${escapeHtml(r.query)}</code></td>` : ''}
        <td>${projectHref}</td>
        <td><code>${escapeHtml(m.component_version || '—')}</code></td>
        <td><code class="muted purl-cell">${escapeHtml(m.purl || '—')}</code></td>
        <td>${graphLink}</td>
      </tr>`);
    }
  }

  const totalFound = results.filter((r) => r.matches && r.matches.length > 0).length;
  const totalMatches = results.reduce((n, r) => n + (r.matches ? r.matches.length : 0), 0);
  const summary = `${totalFound} of ${results.length} package${results.length !== 1 ? 's' : ''} found`
    + (totalMatches > totalFound ? `, ${totalMatches} total project matches` : '');

  const pager = totalPages > 1 ? `
    <div class="pager">
      <button id="pg-prev" ${page === 0 ? 'disabled' : ''}>← Prev</button>
      <span class="muted">Page ${page + 1} of ${totalPages}
        &nbsp;(${escapeHtml(String(start + 1))}–${escapeHtml(String(Math.min(start + PAGE_SIZE, results.length)))} of ${results.length})</span>
      <button id="pg-next" ${page >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
    </div>` : '';

  setHtml('ps-results', `
    <p class="muted gap-below">${escapeHtml(summary)}</p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr>
          <th>Package queried</th>
          <th>Project / version</th>
          <th>Component version</th>
          <th>PURL</th>
          <th>Dep graph</th>
        </tr></thead>
        <tbody>${rows.join('')}</tbody>
      </table>
    </div>${pager}`);

  if (totalPages > 1) {
    document.getElementById('pg-prev')?.addEventListener('click', () => {
      _currentPage = Math.max(0, _currentPage - 1);
      renderResultsPage(_currentPage);
      document.getElementById('results-card')?.scrollIntoView({ behavior: 'smooth' });
    });
    document.getElementById('pg-next')?.addEventListener('click', () => {
      _currentPage = Math.min(totalPages - 1, _currentPage + 1);
      renderResultsPage(_currentPage);
      document.getElementById('results-card')?.scrollIntoView({ behavior: 'smooth' });
    });
  }
}

// ---------------------------------------------------------------------------
// Paste-list search (batched to avoid ALB 504 on large lists)
// ---------------------------------------------------------------------------

const BATCH_SIZE = 50;
// Overall ceiling across all batches. Each batch (<=50) is well under the
// server's per-request _MAX_PACKAGES, so without this check an arbitrarily
// large paste could still issue unlimited sequential DT searches.
const MAX_PACKAGES_TOTAL = 5000;

async function runSearch(packages) {
  showEl(document.getElementById('results-card'));
  _allResults = [];
  _currentPage = 0;

  if (packages.length > MAX_PACKAGES_TOTAL) {
    setHtml('ps-results',
      `<p class="tag fail">Too many packages (${packages.length}). ` +
      `Max ${MAX_PACKAGES_TOTAL} per paste-list search.</p>`);
    return;
  }

  if (packages.length <= BATCH_SIZE) {
    setHtml('ps-results', `<p class="muted">Searching ${packages.length} package${packages.length !== 1 ? 's' : ''}…</p>`);
    try {
      const data = await api.searchPackages(packages);
      _allResults = data.results || [];
      _currentPage = 0;
      if (_allResults.length === 0) {
        setHtml('ps-results', '<p class="muted">No results.</p>');
      } else {
        renderResultsPage(0);
      }
    } catch (err) {
      setHtml('ps-results', `<p class="tag fail">Search failed: ${escapeHtml(err.message)}</p>`);
    }
    return;
  }

  const batches = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    batches.push(packages.slice(i, i + BATCH_SIZE));
  }

  let completed = 0;
  let errors = 0;

  for (const batch of batches) {
    completed++;
    setHtml('ps-results',
      `<p class="muted">Searching batch ${completed} of ${batches.length} ` +
      `(${_allResults.length} results so far)…</p>`);
    try {
      const data = await api.searchPackages(batch);
      _allResults = _allResults.concat(data.results || []);
    } catch (err) {
      errors++;
      for (const pkg of batch) {
        _allResults.push({ query: pkg, error: `Batch failed: ${err.message}`, matches: [] });
      }
    }
  }

  _currentPage = 0;
  if (_allResults.length === 0) {
    setHtml('ps-results', '<p class="muted">No results.</p>');
  } else {
    if (errors > 0) {
      const warning = `<p class="tag fail gap-below">${errors} of ${batches.length} batch${batches.length !== 1 ? 'es' : ''} failed</p>`;
      renderResultsPage(0);
      document.getElementById('ps-results').insertAdjacentHTML('afterbegin', warning);
    } else {
      renderResultsPage(0);
    }
  }
}

// ---------------------------------------------------------------------------
// URL extraction — populates the paste-list textarea
// ---------------------------------------------------------------------------

function updatePkgCount(extracted = false) {
  const ta = document.getElementById('pkg-textarea');
  const el = document.getElementById('pkg-count');
  if (!ta || !el) return;
  const n = ta.value.split('\n').filter((s) => s.trim()).length;
  if (n === 0) {
    el.replaceChildren();
    return;
  }
  const num = document.createElement('strong');
  num.className = 'pkg-count-num';
  num.textContent = String(n);
  const rest = ` package${n !== 1 ? 's' : ''}${extracted ? ' extracted — review the list and click Search' : ''}`;
  el.replaceChildren(num, document.createTextNode(rest));
}

async function pollExtractTask(taskId) {
  setHtml('url-status', '<span class="muted">Extracting… (fetching page)</span>');
  for (let i = 0; i < 90; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    let task;
    try {
      task = await api.getTask(taskId);
    } catch {
      setHtml('url-status', '<span class="tag fail">Poll error — check server logs</span>');
      return;
    }
    if (task.status === 'completed') {
      const names = task.result || [];
      if (!names.length) {
        setHtml('url-status', '<span class="muted">No npm/PyPI packages found in article.</span>');
        return;
      }
      // Populate the textarea and switch to the list tab.
      const ta = document.getElementById('pkg-textarea');
      if (ta) ta.value = names.join('\n');
      document.getElementById('tab-list').click();
      setHtml('url-status', '');
      updatePkgCount(true);
      return;
    }
    if (task.status === 'failed') {
      setHtml('url-status',
        `<span class="tag fail">Extraction failed: ${escapeHtml(task.error || 'unknown')}</span>`);
      return;
    }
    const stageLabels = { fetching: 'fetching page', parsing: 'parsing HTML', gemini: 'asking Gemini', done: 'done' };
    const stage = stageLabels[task.stage] || task.stage || '…';
    setHtml('url-status', `<span class="muted">Stage: ${escapeHtml(stage)}</span>`);
  }
  setHtml('url-status', '<span class="tag fail">Timed out waiting for extraction</span>');
}

// ---------------------------------------------------------------------------
// Main render entry point
// ---------------------------------------------------------------------------

export async function renderPackageSearch(root) {
  root.innerHTML = `
    <div class="card">
      <h2>Package Search</h2>
      <p class="muted">Search Dependency-Track to find which repos contain a given package.</p>

      <div class="toolbar-row">
        <button id="tab-list" class="tab-btn active">Paste package list</button>
        <button id="tab-url" class="tab-btn">Extract from URL / Upload</button>
      </div>

      <!-- Paste list panel -->
      <div id="panel-list">
        <p class="muted">One package name per line. Names are matched against DT's component index.</p>
        <textarea id="pkg-textarea" rows="8" placeholder="async-waterfall&#10;lodash&#10;@wordpress/scripts"></textarea>
        <p class="stack-gap">
          <button id="search-btn" class="primary">Search</button>
          <span id="pkg-count" class="muted"></span>
        </p>
      </div>

      <!-- URL extraction panel -->
      <div id="panel-url" class="hidden" hidden>
        <p class="muted">Paste a URL to a security advisory or blog post, or upload a saved HTML/text file. Gemini will extract npm/PyPI package names.</p>
        <div class="toolbar-row compact">
          <input id="url-input" class="grow" type="text" placeholder="https://example.com/security-advisory">
          <button id="extract-btn" class="primary">Extract from URL</button>
          <button id="upload-btn" type="button">Upload file</button>
          <button id="copy-fallback-prompt" type="button">Copy fallback prompt</button>
        </div>
        <input id="file-input" class="visually-hidden" type="file" accept=".html,.htm,.mhtml,.mht,.eml,.txt,.md,.csv,.json" hidden>
        <p class="stack-gap" id="url-status"></p>
      </div>
    </div>

    <div class="card hidden" id="results-card" hidden>
      <h2>Results</h2>
      <div id="ps-results"></div>
    </div>
  `;

  // Tab switching
  document.getElementById('tab-list').addEventListener('click', () => {
    showEl(document.getElementById('panel-list'));
    hideEl(document.getElementById('panel-url'));
    document.getElementById('tab-list').classList.add('active');
    document.getElementById('tab-url').classList.remove('active');
  });
  document.getElementById('tab-url').addEventListener('click', () => {
    hideEl(document.getElementById('panel-list'));
    showEl(document.getElementById('panel-url'));
    document.getElementById('tab-list').classList.remove('active');
    document.getElementById('tab-url').classList.add('active');
  });

  document.getElementById('pkg-textarea').addEventListener('input', () => updatePkgCount());

  // Paste-list search
  document.getElementById('search-btn').addEventListener('click', async () => {
    const raw = document.getElementById('pkg-textarea').value;
    const packages = raw.split('\n').map((s) => s.trim()).filter(Boolean);
    if (!packages.length) return;
    await runSearch(packages);
  });

  // URL extraction
  document.getElementById('extract-btn').addEventListener('click', async () => {
    const url = document.getElementById('url-input').value.trim();
    if (!url) return;
    setHtml('url-status', '<span class="muted">Submitting…</span>');
    try {
      const data = await api.extractPackages(url);
      await pollExtractTask(data.task_id);
    } catch (err) {
      setHtml('url-status', `<span class="tag fail">${escapeHtml(err.message)}</span>`);
    }
  });

  // File upload
  document.getElementById('upload-btn').addEventListener('click', () => {
    document.getElementById('file-input').click();
  });
  document.getElementById('file-input').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    e.target.value = '';  // reset so same file can be re-uploaded
    setHtml('url-status', `<span class="muted">Reading ${escapeHtml(file.name)}…</span>`);
    let text;
    try {
      text = await file.text();
    } catch (err) {
      setHtml('url-status', `<span class="tag fail">Could not read file: ${escapeHtml(err.message)}</span>`);
      return;
    }
    setHtml('url-status', `<span class="muted">Submitting ${escapeHtml(file.name)}…</span>`);
    try {
      const data = await api.extractPackagesFromText(text, file.name);
      await pollExtractTask(data.task_id);
    } catch (err) {
      setHtml('url-status', `<span class="tag fail">${escapeHtml(err.message)}</span>`);
    }
  });

  document.getElementById('copy-fallback-prompt').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(FALLBACK_EXTRACT_PROMPT);
      document.getElementById('fallback-prompt-box')?.remove();
      setHtml('url-status', '<span class="tag ok">Fallback prompt copied</span>');
    } catch (err) {
      showFallbackPromptBox();
      setHtml('url-status', '<span class="muted">Clipboard unavailable — copy from the box below</span>');
    }
  });
}

function showFallbackPromptBox() {
  if (document.getElementById('fallback-prompt-box')) return;
  const panel = document.getElementById('panel-url');
  if (!panel) return;
  const box = document.createElement('div');
  box.id = 'fallback-prompt-box';
  box.className = 'fallback-prompt-box';
  const hint = document.createElement('p');
  hint.className = 'muted';
  hint.textContent = 'Clipboard unavailable — copy from this box:';
  const ta = document.createElement('textarea');
  ta.id = 'fallback-prompt-ta';
  ta.readOnly = true;
  ta.rows = 16;
  ta.value = FALLBACK_EXTRACT_PROMPT;
  box.appendChild(hint);
  box.appendChild(ta);
  panel.appendChild(box);
}
