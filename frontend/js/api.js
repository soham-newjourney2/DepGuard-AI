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
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data?.error ?? { message: res.statusText });
  return data;
}
