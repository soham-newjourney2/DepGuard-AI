import { api, startDemo } from './api.js';
import { h, icon } from './dom.js';
import { pill } from './components/pill.js';
import { commandPalette, isOpen, shortcutSheet } from './components/palette.js';
import { toast } from './components/toast.js';
import * as theme from './theme.js';
import { go, route, start } from './router.js';
import * as store from './store.js';
import { landing } from './views/landing.js';
import { pipeline } from './views/pipeline.js';
import { findings } from './views/findings.js';
import { graph } from './views/graph.js';
import { fix } from './views/fix.js';
import { verify } from './views/verify.js';
import { report } from './views/report.js';
import { plan } from './views/plan.js';
import { shortId } from './format.js';

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
      : h('a', { class: 'rail__item', role: 'link', 'aria-disabled': 'true', title: `${n.label} — run a scan first`,
        'aria-label': `${n.label} (run a scan first)`, dataset: { nav: n.key } }, icon(ICONS[n.key]))));
}

function syncJobNav(shell, job) {
  if (job?.status !== 'ready') return;
  for (const [key, label] of [['findings', 'Findings'], ['graph', 'Graph'], ['report', 'Report']]) {
    const link = shell.querySelector(`[data-nav="${key}"]`);
    link.href = `#/jobs/${job.id}/${key}`;
    link.removeAttribute('aria-disabled');
    link.title = label;
    link.setAttribute('aria-label', label);
  }
}

function healthPills(target) {
  const loading = () => target.replaceChildren(pill('Scanner'), pill('AI'), pill('Verify'));
  loading();
  api('/health')
    .then((hl) => {
      store.set({ health: hl });
      const aiState = hl.ai === 'anthropic' ? 'ok' : hl.ai === 'off' ? 'off' : 'warn';
      target.replaceChildren(
        ...(hl.local_only ? [pill('Mode', 'local-only', 'warn', 'Only scanner calls leave this machine: AI, registry, GitHub import and verification are off')] : []),
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

function commands() {
  const job = store.get().job;
  const ready = job?.status === 'ready';
  const list = [
    { group: 'Go to', label: 'New scan', run: () => go('/') },
    { group: 'Action', label: 'Try the demo project', keywords: 'sample vuln', run: async () => {
      try {
        const { job_id } = await startDemo('vuln-demo');
        store.set({ lastSource: { kind: 'demo', sample: 'vuln-demo' } });
        go(`/jobs/${job_id}`);
      } catch (err) {
        toast(`${err.code || 'Error'} · ${err.message}`, { kind: 'err' });
      }
    } },
  ];
  if (ready) {
    list.push(
      { group: 'Go to', label: 'Scan progress', run: () => go(`/jobs/${job.id}`) },
      { group: 'Go to', label: 'Findings', hint: 'f', run: () => go(`/jobs/${job.id}/findings`) },
      { group: 'Go to', label: 'Dependency graph', hint: 'g', run: () => go(`/jobs/${job.id}/graph`) },
      { group: 'Go to', label: 'Report', run: () => go(`/jobs/${job.id}/report`) },
      { group: 'Action', label: 'Plan all fixes', keywords: 'batch', run: () => go(`/jobs/${job.id}/plan`) },
      { group: 'Download', label: 'SBOM (CycloneDX)', run: () => { location.href = `/api/jobs/${job.id}/sbom?download=1`; } },
      { group: 'Download', label: 'Report (HTML)', run: () => { location.href = `/api/jobs/${job.id}/report?format=html&download=1`; } },
    );
  }
  list.push(
    { group: 'View', label: `Switch to ${theme.current() === 'light' ? 'dark' : 'light'} theme`, keywords: 'theme appearance', run: () => toast(`${theme.toggle() === 'light' ? 'Light' : 'Dark'} theme`) },
    { group: 'Help', label: 'Keyboard shortcuts', hint: '?', run: shortcutSheet },
  );
  return list;
}

function onGlobalKey(e) {
  const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement
    || e.target instanceof HTMLSelectElement;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (!isOpen()) commandPalette(commands);
  } else if (e.key === '?' && !typing && !isOpen()) {
    e.preventDefault();
    shortcutSheet();
  }
}

function boot() {
  theme.restore();
  document.addEventListener('keydown', onGlobalKey);
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
    const job = detail.path.match(/^\/jobs\/([^/]+)(?:\/(findings|graph|fix|verify|report|plan))?/);
    const active = job?.[2] ? (['fix', 'verify', 'plan'].includes(job[2]) ? 'findings' : job[2]) : detail.path === '/' || job ? 'scan' : detail.path.split('/')[1];
    for (const a of shell.querySelectorAll('[data-nav]')) {
      if (a.dataset.nav === active) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    crumb.textContent = detail.path === '/' ? 'New scan' : job ? `Job ${shortId(job[1])}${job[2] ? ` · ${{ graph: 'Graph', findings: 'Findings', fix: 'Fix', verify: 'Verify', report: 'Report', plan: 'Plan' }[job[2]]}` : ''}` : 'Not found';
  });

  route('/', landing);
  route('/jobs/:id', pipeline);
  route('/jobs/:id/findings', findings);
  route('/jobs/:id/graph', graph);
  route('/jobs/:id/fix/:fid', fix);
  route('/jobs/:id/verify/:pid', verify);
  route('/jobs/:id/report', report);
  route('/jobs/:id/plan', plan);
  store.subscribe((st) => syncJobNav(shell, st.job));
  healthPills(pills);
  start(outlet, notFound);
}

boot();
