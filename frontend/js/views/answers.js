import { api } from '../api.js';
import { countUp } from '../components/kpi.js';
import { fill, h } from '../dom.js';
import { shortId, stamp } from '../format.js';
import * as store from '../store.js';

const ORDER = { missed: 0, extra: 1, matched: 2 };
const SEV = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const STATUS = { matched: ['Matched', 'ok'], missed: ['Missed', 'err'], extra: ['Extra', 'warn'] };

export const toolList = (tools) => tools.map((t) => `${t.name} ${t.version}`).join(' + ');
export const keyCopy = (key) => `Answer key built with ${toolList(key.tools)} on ${stamp(key.generated_at)}. Advisories published after that date appear as “new since answer key”.`;

function tiles(t) {
  const cells = [
    ['matched', 'Matched', t.matched, 'In the answer key and found by DepGuard'],
    ['missed', 'Missed', t.missed, 'In the answer key, not found by DepGuard'],
    ['extra', 'Extra', t.extra, 'Found by DepGuard, not in the answer key'],
  ];
  const found = h('span', { class: 'kpistrip__v' }, t.found_pct === null ? '—' : '0');
  if (t.found_pct !== null) countUp(found, t.found_pct);
  return h('section', { class: 'kpistrip akstrip', 'aria-label': 'Answer key totals' },
    cells.map(([key, label, value, title]) => {
      const v = h('span', { class: 'kpistrip__v' }, '0');
      countUp(v, value);
      return h('div', { class: 'kpistrip__cell', dataset: { status: key, zero: String(!value) }, title }, v, h('span', { class: 'kpistrip__k' }, label));
    }),
    h('div', { class: 'kpistrip__cell', dataset: { status: 'found' }, title: 'Matched ÷ answer-key entries' },
      h('span', { class: 'akstrip__pct' }, found, t.found_pct === null ? null : h('small', null, '%')),
      h('span', { class: 'kpistrip__k' }, 'Found')));
}

function side(r, present, empty, label, id = r.advisory) {
  if (!present) return h('div', { class: 'akrow__side akrow__side--empty', dataset: { label } }, empty);
  return h('div', { class: 'akrow__side', dataset: { label } },
    h('span', { class: 'sev', dataset: { sev: r.severity || 'unknown' } }, h('span', { class: 'sev__dot' })),
    h('code', { class: 'akrow__adv' }, id),
    h('code', { class: 'akrow__pkg' }, r.package));
}

function row(r, i) {
  const [label, kind] = STATUS[r.status];
  return h('li', { class: 'akrow', dataset: { status: r.status }, style: { '--i': String(Math.min(i, 24)) } },
    side(r, r.status !== 'missed', 'not found', 'DepGuard', r.scan_advisory),
    h('span', { class: 'akrow__mid' }, h('span', { class: `chip chip--${kind}` }, label)),
    side(r, r.status !== 'extra', 'not in key', 'Key'),
    r.note ? h('p', { class: 'akrow__note' }, r.note) : null);
}

function riskRow(r, i) {
  const [label, kind] = STATUS[r.status];
  const cell = (text, empty, lab) => (text
    ? h('div', { class: 'akrow__side', dataset: { label: lab } }, h('span', { class: 'chip chip--dim' }, r.kind), h('span', { class: 'akrow__pkg' }, text))
    : h('div', { class: 'akrow__side akrow__side--empty', dataset: { label: lab } }, empty));
  return h('li', { class: 'akrow', dataset: { status: r.status }, style: { '--i': String(Math.min(i, 24)) } },
    cell(r.signal, 'not found', 'DepGuard'),
    h('span', { class: 'akrow__mid' }, h('span', { class: `chip chip--${kind}` }, label)),
    cell(r.planted && `${r.where} · ${r.planted}`, 'not planted', 'Planted'));
}

function riskSection(risks) {
  const t = risks.totals;
  return h('section', { class: 'akgrid akrisks', 'aria-label': 'Planted supply-chain signals beside DepGuard’s risks' },
    h('h2', { class: 'rsec__title' }, 'Supply-chain signals ', h('span', { class: 'rsec__n' }, `${t.matched}/${t.planted} planted found`)),
    h('p', { class: 'muted' }, 'These signals were planted by design in the demo; DepGuard’s static checks should find each one.'),
    h('div', { class: 'akgrid__head' }, h('span', null, 'DepGuard · risk signal'), h('span'), h('span', null, 'Planted by design')),
    h('ol', { class: 'akgrid__rows' }, risks.rows.map(riskRow)));
}

export function comparison(body) {
  const rows = [...body.rows].sort((a, b) => ORDER[a.status] - ORDER[b.status]
    || (SEV[a.severity] ?? 4) - (SEV[b.severity] ?? 4) || a.advisory.localeCompare(b.advisory));
  return [
    tiles(body.totals),
    h('section', { class: 'akgrid', 'aria-label': 'DepGuard live scan beside the answer key' },
      h('div', { class: 'akgrid__head' },
        h('span', null, 'DepGuard · live scan'), h('span'),
        h('span', null, `Answer key · ${toolList(body.key.tools)}`)),
      rows.length ? h('ol', { class: 'akgrid__rows' }, rows.map(row))
        : h('p', { class: 'muted' }, 'Neither DepGuard nor the reference tools reported an advisory.')),
    body.risks ? riskSection(body.risks) : null,
  ];
}

export function answers({ id }) {
  const body = h('div', { class: 'rbody' }, h('div', { class: 'skeleton skeleton--kpi' }));
  const lede = h('p', { class: 'fhead__meta' });
  const el = h('div', { class: 'answersview' }, h('div', { class: 'container fwrap' },
    h('header', { class: 'fhead' }, h('a', { class: 'backlink', href: `#/jobs/${id}/findings` }, '← Findings'),
      h('span', { class: 'eyebrow' }, `Job ${shortId(id)} · answer key`),
      h('h1', { class: 'fhead__title' }, 'Answer key'), lede),
    body));

  api(`/jobs/${id}/answer-key`)
    .then((r) => {
      store.set({ job: { id, status: 'ready' } });
      if (r.key) lede.textContent = keyCopy(r.key);
      if (!r.available) {
        fill(body, h('section', { class: 'panel card', role: 'status' },
          h('div', { class: 'card__head' }, h('span', { class: 'chip chip--warn' }, 'NO COMPARISON')),
          h('h2', { class: 'card__title' }, r.reason)));
        return;
      }
      fill(body, comparison(r));
    })
    .catch((err) => {
      body.replaceChildren(h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message), err.hint ? h('p', { class: 'card__hint' }, err.hint) : null));
    });

  return { el };
}
