async function request(method, path, body) {
  const opts = { method, headers: {} };
  // The server refuses POST/PUT without a JSON Content-Type (CSRF guard),
  // including body-less calls such as stop and restart.
  if (method !== 'GET') opts.headers['Content-Type'] = 'application/json';
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (!res.ok) {
    const message = (data && data.error) || `HTTP ${res.status}`;
    throw new Error(message);
  }
  return data;
}

export const api = {
  getSettings: () => request('GET', '/api/settings'),
  putSettings: (patch) => request('PUT', '/api/settings', patch),
  ghStatus: () => request('GET', '/api/gh-status'),
  dtrackStatus: () => request('GET', '/api/dtrack-status'),
  geminiStatus: () => request('GET', '/api/gemini-status'),

  listRuns: () => request('GET', '/api/runs'),
  createRun: (orgs, repos, method, opts = {}) => request('POST', '/api/runs', {
    orgs,
    repos: repos || [],
    method: method || 'github_sbom',
    use_default: opts.useDefault !== false,
    branch: opts.branch || '',
  }),

  getRun: (id) => request('GET', `/api/runs/${id}`),
  listRunRepos: (id) => request('GET', `/api/runs/${id}/repos`),
  stopRun: (id) => request('POST', `/api/runs/${id}/stop`, {}),
  continueRun: (id) => request('POST', `/api/runs/${id}/continue`, {}),
  restartRun: (id) => request('POST', `/api/runs/${id}/restart`, {}),
  retryFailed: (id) => request('POST', `/api/runs/${id}/retry-failed`, {}),
  retryRepo: (id, org, repo) =>
    request('POST', `/api/runs/${id}/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo)}/retry`, {}),
  getRepoLog: (id, org, repo) =>
    request('GET', `/api/runs/${id}/logs/${encodeURIComponent(org)}/${encodeURIComponent(repo)}`),

  // Inspection / data-quality APIs.
  listRunManifests: (id) => request('GET', `/api/runs/${id}/manifests`),
  getRunManifest: (id, org, repo, filepath) => {
    // base64url-encode the filepath because manifest paths legitimately
    // contain `/` (e.g. packages/core/package.json). The server
    // realpath-validates the decoded path against the run sandbox.
    const b64 = btoa(filepath).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return request('GET',
      `/api/runs/${id}/manifests/${encodeURIComponent(org)}/${encodeURIComponent(repo)}/${b64}`);
  },
  getRepoDtComponents: (id, org, repo) =>
    request('GET', `/api/runs/${id}/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo)}/dtrack-components`),
  getRunCoverage: (id) => request('GET', `/api/runs/${id}/coverage`),
  searchDtrack: (q) => request('GET', `/api/dtrack/search?q=${encodeURIComponent(q)}`),
  searchPackages: (packages) => request('POST', '/api/dtrack/package-search', { packages }),
  extractPackages: (url) => request('POST', '/api/extract-packages', { url }),
  extractPackagesFromText: (text, filename) =>
    request('POST', '/api/extract-packages', { text, filename }),

  getTask: (id) => request('GET', `/api/tasks/${id}`),
};
