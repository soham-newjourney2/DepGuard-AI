import { api } from '../api.js';
import { diffView } from '../components/diff.js';
import { confirmModal } from '../components/modal.js';
import { toast } from '../components/toast.js';
import { fill, h } from '../dom.js';
import { shortId } from '../format.js';
import { go } from '../router.js';
import * as store from '../store.js';

const LABELS = {
  'direct-bump': 'Direct upgrade',
  'parent-bump': 'Upgrade the parent',
  override: 'npm override',
  'lock-update': 'Lockfile update',
  none: 'No safe upgrade',
  remove: 'Remove the package',
};
const BLURB = {
  'direct-bump': 'Change the version you declare in package.json.',
  'parent-bump': 'Upgrade the direct dependency that pulls the vulnerable package in.',
  override: 'Force the fixed version under its parent with npm "overrides".',
  'lock-update': 'Move the transitive package to the fixed version with your package manager.',
  none: 'No published version is outside the affected range.',
  remove: 'OSV lists this package as malicious: remove it and rotate secrets; upgrading is not a fix.',
};

function blurb(p) {
  if (p.strategy === 'direct-bump' && p.stack) return `Change the version your ${p.stack} project pins.`;
  return BLURB[p.strategy] || '';
}

export function commandBox(cmd) {
  const code = h('code', null, cmd);
  const btn = h('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, 'Copy');
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      toast('Command copied');
    } catch {
      toast('Copy failed — select the text instead', { kind: 'err' });
    }
  });
  return h('section', { class: 'panel cmdbox', 'aria-label': 'Command' },
    h('div', { class: 'cmdbox__head' }, h('h3', { class: 'dsec__title' }, 'Run in your project'), btn),
    h('pre', { class: 'cmdbox__pre' }, code));
}

export function steps() {
  return h('ol', { class: 'runlist' },
    h('li', null, 'Copy the project into a disposable workspace and apply the package.json change shown in the diff.'),
    h('li', null, h('code', null, 'npm install --package-lock-only --ignore-scripts'), ' — resolves the new lockfile. Network on, install scripts off.'),
    h('li', null, h('code', null, 'npm ci --ignore-scripts'), ' then ', h('code', null, 'npm test --if-present'),
      ' — your own test script only; nothing user-supplied.'),
    h('li', null, 'Rescan the new lockfile with OSV and compare before/after.'),
    h('p', { class: 'runlist__note' }, 'Verification ran on this machine with install scripts disabled (bundled sample only).'));
}

function changeChip(c) {
  return h('span', { class: 'change', dataset: { jump: c.jump } },
    h('span', { class: 'change__pkg' }, c.pkg), ' ', c.from, ' → ', h('strong', null, c.to), h('span', { class: 'change__jump' }, c.jump));
}

function card(p, selected, onSelect) {
  const el = h('button', { class: 'scard', type: 'button', role: 'radio', 'aria-checked': String(selected), dataset: { strategy: p.strategy } },
    h('span', { class: 'scard__top' },
      h('span', { class: 'scard__kind' }, LABELS[p.strategy]),
      h('span', { class: 'conf', dataset: { level: p.confidence } }, p.confidence === 'n/a' ? 'no fix' : `${p.confidence} confidence`)),
    h('span', { class: 'scard__title' }, p.title),
    h('span', { class: 'scard__blurb' }, blurb(p)),
    p.changes.length ? h('span', { class: 'scard__changes' }, p.changes.slice(0, 4).map(changeChip)) : null,
    h('span', { class: 'scard__foot' },
      p.resolves.length ? h('span', { class: 'chip chip--ok' }, `resolves ${p.resolves.length} advisor${p.resolves.length === 1 ? 'y' : 'ies'}`) : null,
      p.warnings.length ? h('span', { class: 'chip chip--warn' }, `${p.warnings.length} warning${p.warnings.length === 1 ? '' : 's'}`) : null));
  el.addEventListener('click', () => onSelect(p.pid));
  return el;
}

export function fix({ id, fid }) {
  const state = { items: [], sel: null, finding: null };
  const title = h('h1', { class: 'fhead__title' }, 'Fix proposal');
  const meta = h('p', { class: 'fhead__meta' });
  const cards = h('div', { class: 'scards', role: 'radiogroup', 'aria-label': 'Fix strategies' }, h('div', { class: 'skeleton scard--skel' }), h('div', { class: 'skeleton scard--skel' }));
  const detail = h('div', { class: 'fixdetail' });
  const el = h('div', { class: 'fixview' },
    h('div', { class: 'container fwrap' },
      h('header', { class: 'fhead' },
        h('a', { class: 'backlink', href: `#/jobs/${id}/findings` }, '← Findings'),
        h('span', { class: 'eyebrow' }, `Job ${shortId(id)}`), title, meta),
      h('section', { class: 'fixgrid' }, cards, detail)));

  function select(pid) {
    state.sel = pid;
    const p = state.items.find((x) => x.pid === pid);
    cards.replaceChildren(...state.items.map((x) => card(x, x.pid === pid, select)));
    renderDetail(p);
  }

  function renderDetail(p) {
    const mode = store.get().health?.verify_mode ?? 'auto';
    const canVerify = p.strategy !== 'none' && mode !== 'off' && p.verifiable !== false;
    const started = p.status && p.status !== 'proposed';
    const approve = started
      ? h('a', { class: 'btn btn--primary', href: `#/jobs/${id}/verify/${p.pid}` }, 'View verification')
      : p.verifiable === false
        ? null
        : h('button', { class: 'btn btn--primary', type: 'button', disabled: !canVerify }, 'Approve & verify');
    if (!started && approve) approve.addEventListener('click', () => onApprove(p));
    fill(detail,
      p.command ? commandBox(p.command) : null,
      p.diff ? diffView(p.diff) : p.command ? null : h('section', { class: 'panel card' },
        h('h2', { class: 'card__title' }, 'Nothing safe to apply automatically.'),
        h('p', { class: 'card__hint' }, 'DepGuard will not invent a replacement package. These are the honest options:')),
      p.warnings.length ? h('section', { class: 'warnbox', 'aria-label': 'Warnings' },
        h('h3', { class: 'dsec__title' }, 'Warnings'),
        h('ul', null, p.warnings.map((w) => h('li', null, w)))) : null,
      p.resolves.length ? h('p', { class: 'resolves' }, 'Resolves ', p.resolves.map((r) => h('code', { class: 'ver' }, r))) : null,
      h('div', { class: 'fixactions' },
        approve,
        p.diff ? h('a', { class: 'btn btn--ghost', href: `/api/jobs/${id}/patch?pid=${p.pid}`, download: `depguard-${p.pid}.patch` }, 'Download .patch') : null,
        p.verifiable === false && p.strategy !== 'none' ? h('span', { class: 'muted' }, 'Verification covers the bundled npm demos; run your own tests after applying this.') : null,
        mode === 'off' ? h('span', { class: 'muted' }, 'Verification is turned off on this server.') : null));
  }

  async function onApprove(p) {
    const ok = await confirmModal({
      title: `Approve “${p.title}”?`,
      body: [h('p', null, 'Nothing changes in your repository. DepGuard will run exactly this:'), steps()],
      confirmLabel: 'Approve & run verification',
    });
    if (!ok) return;
    try {
      await api(`/jobs/${id}/proposals/${p.pid}/approve`, { method: 'POST', body: { confirm: true } });
      go(`/jobs/${id}/verify/${p.pid}`);
    } catch (err) {
      toast(`${err.code || 'Error'} · ${err.message}`, { kind: 'err', timeout: 6000 });
    }
  }

  Promise.all([api(`/jobs/${id}/findings/${fid}`), api(`/jobs/${id}/findings/${fid}/proposal`, { method: 'POST' })])
    .then(([f, data]) => {
      state.finding = f;
      title.textContent = `Fix ${f.package.name}@${f.package.version}`;
      meta.replaceChildren(`${f.advisory.id} · ${f.advisory.summary}`);
      state.items = data.items;
      select(state.items[0].pid);
    })
    .catch((err) => {
      cards.replaceChildren();
      detail.replaceChildren(h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message), err.hint ? h('p', { class: 'card__hint' }, err.hint) : null));
    });

  return { el };
}
