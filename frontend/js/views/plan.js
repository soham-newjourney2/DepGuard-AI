import { api } from '../api.js';
import { diffView } from '../components/diff.js';
import { confirmModal } from '../components/modal.js';
import { toast } from '../components/toast.js';
import { fill, h } from '../dom.js';
import { shortId } from '../format.js';
import { go } from '../router.js';
import * as store from '../store.js';
import { commandBox, steps } from './fix.js';

const GROUPS = [
  ['included', 'Included', 'ok'],
  ['merged', 'Merged into another change', ''],
  ['conflict', 'Conflicts', 'err'],
  ['no_fix', 'No safe upgrade', 'warn'],
];

function group(items, [key, label, kind]) {
  const rows = items.filter((i) => i.status === key);
  if (!rows.length) return null;
  return h('section', { class: 'pgroup', dataset: { status: key } },
    h('h3', { class: 'dsec__title' }, `${label} (${rows.length})`),
    h('ul', { class: 'rlist' }, rows.map((i) => h('li', { class: 'rlist__item pitem', dataset: { sev: i.severity } },
      h('span', { class: 'sev', dataset: { sev: i.severity } }, h('span', { class: 'sev__dot' }), i.severity),
      h('code', { class: 'rlist__pkg' }, i.package),
      h('span', { class: 'rlist__adv' }, i.advisory),
      h('span', { class: ['rlist__sum', kind && `pnote--${kind}`] }, i.note || i.title || '')))));
}

export function plan({ id }) {
  const meta = h('p', { class: 'fhead__meta' }, 'Planning every finding…');
  const left = h('div', { class: 'pgroups' }, h('div', { class: 'skeleton scard--skel' }));
  const right = h('div', { class: 'fixdetail' });
  const el = h('div', { class: 'planview' }, h('div', { class: 'container fwrap' },
    h('header', { class: 'fhead' }, h('a', { class: 'backlink', href: `#/jobs/${id}/findings` }, '← Findings'),
      h('span', { class: 'eyebrow' }, `Job ${shortId(id)} · batch`), h('h1', { class: 'fhead__title' }, 'Batch fix plan'), meta),
    h('section', { class: 'fixgrid' }, left, right)));

  async function approve(p) {
    const mode = store.get().health?.verify_mode ?? 'auto';
    const ok = await confirmModal({
      title: `Approve “${p.title}”?`,
      body: [h('p', null, 'All included changes are applied together in one disposable workspace:'), steps(mode)],
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

  api(`/jobs/${id}/plan`, { method: 'POST' })
    .then((p) => {
      meta.textContent = `${p.title} · ${p.confidence} confidence · ${p.conflicts.length} conflict${p.conflicts.length === 1 ? '' : 's'}`;
      fill(left, GROUPS.map((g) => group(p.items, g)));
      const started = p.status && p.status !== 'proposed';
      const verifiable = p.verifiable !== false;
      const action = !verifiable ? null : started
        ? h('a', { class: 'btn btn--primary', href: `#/jobs/${id}/verify/${p.pid}` }, 'View verification')
        : h('button', { class: 'btn btn--primary', type: 'button', onclick: () => approve(p) }, 'Approve & verify all');
      fill(right,
        p.command ? commandBox(p.command) : null,
        p.diff ? diffView(p.diff) : null,
        p.warnings.length ? h('section', { class: 'warnbox' }, h('h3', { class: 'dsec__title' }, 'Warnings'),
          h('ul', null, p.warnings.slice(0, 12).map((w) => h('li', null, w)))) : null,
        h('div', { class: 'fixactions' }, action,
          p.diff ? h('a', { class: 'btn btn--ghost', href: `/api/jobs/${id}/patch?pid=${p.pid}`, download: '' }, 'Download .patch') : null));
    })
    .catch((err) => {
      fill(left);
      fill(right, h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message), err.hint ? h('p', { class: 'card__hint' }, err.hint) : null));
    });

  return { el };
}
