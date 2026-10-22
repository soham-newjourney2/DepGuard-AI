import { api } from '../api.js';
import { drawer } from '../components/drawer.js';
import { countUp } from '../components/kpi.js';
import { fill, h } from '../dom.js';
import { shortId } from '../format.js';
import * as store from '../store.js';

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
export const KINDS = [
  ['malware', 'Malware', 'Packages OSV lists as malicious (MAL- records). Remove them and rotate secrets.'],
  ['integrity', 'Lockfile integrity', 'Packages fetched from git, plain HTTP or a non-registry URL, or pinned without a strong hash.'],
  ['typosquat', 'Typosquat look-alikes', 'Names one keystroke away from a popular package. A signal to double-check, not a verdict.'],
  ['secret', 'Secrets in the code', 'Credentials committed to the project. Values are never stored or shown, only where they are.'],
];
const SIGNALS = 'Static checks of the uploaded files: signals, not verdicts. Only OSV MAL- records are called malicious; nothing here was installed or run.';
const EMPTY = 'No supply-chain signals. These checks are static and cannot prove the dependencies are safe.';

function bars(items) {
  const n = items.length || 1;
  const by = SEVS.map((s) => [s, items.filter((r) => r.severity === s).length]).filter(([, c]) => c);
  return h('div', { class: 'sevbar', role: 'img', 'aria-label': by.map(([s, c]) => `${c} ${s}`).join(', ') },
    by.map(([s, c]) => h('span', { class: 'sevbar__seg', dataset: { sev: s }, style: { flexGrow: String(c / n) }, title: `${c} ${s}` })));
}

function tiles(counts) {
  return h('section', { class: 'kpistrip rkstrip', 'aria-label': 'Risk signal counts' }, KINDS.map(([key, label]) => {
    const value = counts.by_kind[key] || 0;
    const v = h('span', { class: 'kpistrip__v' }, '0');
    countUp(v, value);
    return h('a', { class: 'kpistrip__cell', href: `#risk-${key}`, dataset: { kind: key, zero: String(!value) } }, v, h('span', { class: 'kpistrip__k' }, label));
  }));
}

const where = (r) => (r.location ? `${r.location.file}${r.location.line ? `:${r.location.line}` : ''}` : r.package || '');

function row(r, i, onOpen) {
  const b = h('button', { class: 'rkrow', type: 'button', dataset: { id: r.id, sev: r.severity, kind: r.kind }, style: { '--i': String(Math.min(i, 20)) } },
    h('span', { class: 'sev', dataset: { sev: r.severity } }, h('span', { class: 'sev__dot' }), r.severity),
    h('span', { class: 'rkrow__title' }, r.title),
    h('code', { class: 'rkrow__where' }, where(r)),
    h('span', { class: `chip ${r.confidence === 'high' ? '' : 'chip--dim'}`, title: 'Confidence in this signal' }, `${r.confidence} confidence`));
  b.addEventListener('click', () => onOpen(r));
  return h('li', null, b);
}

export function riskDetail(r) {
  return h('article', { class: 'detail rkdetail', dataset: { sev: r.severity } },
    h('header', { class: 'detail__head' },
      h('div', { class: 'detail__chips' },
        r.kind === 'malware' ? h('span', { class: 'xbadge' }, 'Malware') : null,
        h('span', { class: 'sev', dataset: { sev: r.severity } }, h('span', { class: 'sev__dot' }), r.severity),
        h('span', { class: 'chip' }, KINDS.find(([k]) => k === r.kind)[1]),
        h('span', { class: 'chip chip--dim' }, `${r.confidence} confidence`)),
      h('h2', { class: 'detail__title', id: 'detail-title' }, r.title),
      r.package ? h('p', { class: 'detail__pkg' }, r.package) : null,
      r.location ? h('p', { class: 'detail__vector' }, where(r)) : null),
    h('section', { class: 'dsec' }, h('h3', { class: 'dsec__title' }, 'What to do'), h('p', null, r.recommendation)),
    h('section', { class: 'dsec' }, h('h3', { class: 'dsec__title' }, 'Evidence'),
      h('ul', { class: 'rkev' }, r.evidence.map((e) => h('li', null, e)))),
    h('p', { class: 'muted' }, SIGNALS));
}

export function risks({ id }) {
  const body = h('div', { class: 'rbody' }, h('div', { class: 'skeleton skeleton--kpi' }));
  const dr = drawer({ label: 'Risk detail' });
  const el = h('div', { class: 'risksview' }, h('div', { class: 'container fwrap' },
    h('header', { class: 'fhead' }, h('a', { class: 'backlink', href: `#/jobs/${id}/findings` }, '← Findings'),
      h('span', { class: 'eyebrow' }, `Job ${shortId(id)} · supply chain`),
      h('h1', { class: 'fhead__title' }, 'Supply chain & hygiene'), h('p', { class: 'fhead__meta' }, SIGNALS)),
    body), dr.scrim, dr.el);

  const onKey = (e) => { if (e.key === 'Escape' && dr.isOpen()) dr.hide(); };
  document.addEventListener('keydown', onKey);

  api(`/jobs/${id}/risks`)
    .then((data) => {
      store.set({ job: { id, status: 'ready' } });
      if (!data.total) {
        fill(body, tiles(data.counts), h('section', { class: 'panel card card--ready clean' },
          h('div', { class: 'card__head' }, h('span', { class: 'chip chip--ok' }, 'NO SIGNALS')),
          h('p', { class: 'card__title' }, EMPTY)));
        return;
      }
      let i = 0;
      fill(body, tiles(data.counts), KINDS.map(([key, label, copy]) => {
        const items = data.items.filter((r) => r.kind === key);
        if (!items.length) return null;
        return h('section', { class: 'rsec rkgroup', id: `risk-${key}`, dataset: { kind: key } },
          h('div', { class: 'rkgroup__head' }, h('h2', { class: 'rsec__title' }, `${label} `, h('span', { class: 'rsec__n' }, String(items.length))), bars(items)),
          h('p', { class: 'muted' }, copy),
          h('ol', { class: 'rklist' }, items.map((r) => row(r, i++, (x) => dr.show(riskDetail(x))))));
      }));
    })
    .catch((err) => {
      body.replaceChildren(h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message), err.hint ? h('p', { class: 'card__hint' }, err.hint) : null));
    });

  return { el, destroy() { document.removeEventListener('keydown', onKey); } };
}
