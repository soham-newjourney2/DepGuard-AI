export class ApiError extends Error {
  constructor(status, { code = 'E_HTTP', message = 'Request failed', hint = '' } = {}) {
    super(message);
    Object.assign(this, { status, code, hint });
  }
}

export async function api(path, { method = 'GET', body, headers = {}, signal } = {}) {
  const init = { method, signal, headers: { Accept: 'application/json', ...headers } };
  if (body instanceof FormData) init.body = body;
  else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }
  let res;
  try {
    res = await fetch(`/api${path}`, init);
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError(0, { code: 'E_OFFLINE', message: 'API unreachable.', hint: 'Check that the server is running.' });
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data?.error ?? { message: res.statusText });
  return data;
}

export function uploadZip(file, project) {
  const body = new FormData();
  body.append('file', file, file.name);
  if (project) body.append('project', project);
  return api('/jobs', { method: 'POST', body });
}

export const startDemo = (sample) => api(`/jobs/demo/${encodeURIComponent(sample)}`, { method: 'POST' });

export const importGithub = (repo, project) => api('/jobs/github', { method: 'POST', body: { repo, project } });

export const scanUrl = (url) => api('/jobs/url', { method: 'POST', body: { url } });

export function launch(source, project) {
  if (source.kind === 'demo') return startDemo(source.sample);
  if (source.kind === 'github') return importGithub(source.repo, project);
  if (source.kind === 'url') return scanUrl(source.url);
  return uploadZip(source.file, project);
}
