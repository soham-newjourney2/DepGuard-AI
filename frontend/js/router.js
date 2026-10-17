const routes = [];
let current = null;

export function route(pattern, view) {
  const keys = [];
  const source = pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([^/]+)'));
  routes.push({ re: new RegExp(`^${source}/?$`), keys, view });
}

export function match(path) {
  for (const r of routes) {
    const m = r.re.exec(path);
    if (m) return { view: r.view, params: Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])) };
  }
  return null;
}

export function start(outlet, fallback) {
  const render = () => {
    const path = location.hash.replace(/^#/, '') || '/';
    const found = match(path) ?? { view: fallback, params: {} };
    current?.destroy?.();
    current = found.view(found.params);
    outlet.replaceChildren(current.el);
    window.scrollTo(0, 0);
    document.dispatchEvent(new CustomEvent('route', { detail: { path } }));
  };
  window.addEventListener('hashchange', render);
  render();
}

export const go = (path) => { location.hash = path; };
