import { api } from './api.js';
import { h, icon } from './dom.js';
import { pill } from './components/pill.js';
import { route, start } from './router.js';
import * as store from './store.js';
import { landing } from './views/landing.js';

const ICONS = {
  brand: ['M12 3l8 3.2v6.1c0 5-3.4 8.8-8 10.5-4.6-1.7-8-5.5-8-10.5V6.2z', 'M12 10.2a2.3 2.3 0 1 0 0 4.6 2.3 2.3 0 0 0 0-4.6z'],
  scan: ['M4 8V5a1 1 0 0 1 1-1h3', 'M16 4h3a1 1 0 0 1 1 1v3', 'M20 16v3a1 1 0 0 1-1 1h-3', 'M8 20H5a1 1 0 0 1-1-1v-3', 'M4 12h16'],
  findings: ['M8 6h12', 'M8 12h12', 'M8 18h12', 'M4 6h.01', 'M4 12h.01', 'M4 18h.01'],
  graph: ['M6 6.5a2.5 2.5 0 1 0 0-.01', 'M18 6.5a2.5 2.5 0 1 0 0-.01', 'M12 18.5a2.5 2.5 0 1 0 0-.01', 'M7.8 8.2 10.6 16', 'M16.2 8.2 13.4 16', 'M8.5 6h7'],
  report: ['M7 3h7l4 4v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z', 'M14 3v4h4', 'M9 13l2 2 4-4'],
};

const NAV = [
  { key: 'scan', label: 'New scan', href: '#/' },
  { key: 'findings', label: 'Findings' },
  { key: 'graph', label: 'Graph' },
  { key: 'report', label: 'Report' },
];

function rail() {
  return h('nav', { class: 'rail', 'aria-label': 'Primary' },
    h('a', { class: 'rail__brand', href: '#/', 'aria-label': 'DepGuard AI home' }, icon(ICONS.brand, 26)),
    NAV.map((n) => n.href
      ? h('a', { class: 'rail__item', href: n.href, title: n.label, 'aria-label': n.label, dataset: { nav: n.key } }, icon(ICONS[n.key]))
      : h('span', { class: 'rail__item', role: 'link', 'aria-disabled': 'true', title: `${n.label} — run a scan first`,
        'aria-label': `${n.label} (run a scan first)`, dataset: { nav: n.key } }, icon(ICONS[n.key]))));
}

function healthPills(target) {
  const loading = () => target.replaceChildren(pill('Scanner'), pill('AI'), pill('Verify'));
  loading();
  api('/health')
    .then((hl) => {
      store.set({ health: hl });
      const aiState = hl.ai === 'anthropic' ? 'ok' : hl.ai === 'off' ? 'off' : 'warn';
      target.replaceChildren(
        pill('Scanner', hl.scanner, 'ok', `Advisory source: ${hl.scanner}`),
        pill('AI', hl.ai, aiState, hl.ai === 'template' ? 'Deterministic template explanations (no API key)' : ''),
        pill('Verify', hl.verify_mode, hl.verify_mode === 'off' ? 'off' : 'ok', `Verification mode: ${hl.verify_mode}`));
    })
    .catch((err) => target.replaceChildren(pill('API', 'offline', 'err', err.hint || err.message)));
}

function notFound() {
  return {
    el: h('div', { class: 'container' },
      h('div', { class: 'empty' },
        h('p', { class: 'empty__title' }, 'Nothing at this address.'),
        h('p', { class: 'empty__copy' }, 'The page you followed does not exist or has expired.'),
        h('a', { class: 'btn btn--ghost', href: '#/' }, 'Start a new scan'))),
  };
}

function boot() {
  const pills = h('div', { class: 'pills', 'aria-label': 'Service status' });
  const crumb = h('span', { 'aria-current': 'page' }, 'New scan');
  const outlet = h('main', { class: 'outlet', id: 'main' });
  const shell = h('div', { class: 'shell' },
    rail(),
    h('header', { class: 'topbar' },
      h('div', { class: 'crumbs' }, h('span', { class: 'crumbs__root' }, 'DepGuard'), h('span', { class: 'crumbs__sep' }, '/'), crumb),
      pills),
    outlet);
  document.getElementById('app').replaceChildren(shell);

  for (const ev of ['dragover', 'drop']) window.addEventListener(ev, (e) => e.preventDefault());

  document.addEventListener('route', ({ detail }) => {
    const active = detail.path === '/' ? 'scan' : detail.path.split('/')[1];
    for (const a of shell.querySelectorAll('[data-nav]')) {
      if (a.dataset.nav === active) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    crumb.textContent = detail.path === '/' ? 'New scan' : 'Not found';
  });

  route('/', landing);
  healthPills(pills);
  start(outlet, notFound);
}

boot();
