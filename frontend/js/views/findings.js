import { api } from '../api.js';
import { drawer } from '../components/drawer.js';
import { explainPanel } from '../components/explain.js';
import { gauge } from '../components/gauge.js';
import { countUp } from '../components/kpi.js';
import { pathchain } from '../components/pathchain.js';
import { h, icon } from '../dom.js';
import { policyChip, shortId, stamp } from '../format.js';
import { md } from '../md.js';
import { go } from '../router.js';
import * as store from '../store.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];
const SCOPES = ['prod', 'dev', 'optional', 'peer'];
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const SEARCH = ['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z', 'M20 20l-4-4'];
const NO_FINDINGS = (ts) => `OSV reported no known advisories for these packages at ${ts}. This is not proof the project is secure.`;
const SORTERS = {
  priority: null,
  severity: (a, b) => SEV_RANK[a.advisory.severity.label] - SEV_RANK[b.advisory.severity.label]
    || (b.advisory.severity.score ?? 0) - (a.advisory.severity.score ?? 0) || a.package.name.localeCompare(b.package.name),
  name: (a, b) => a.package.name.localeCompare(b.package.name) || a.package.version.localeCompare(b.package.version),
};

const sevChip = (sev) => h('span', { class: 'sev', dataset: { sev: sev.label } },
  h('span', { class: 'sev__dot', 'aria-hidden': 'true' }), sev.label,
  sev.score != null ? h('span', { class: 'sev__score' }, sev.score.toFixed(1)) : null);

function kpiStrip(summary) {
  const sev = summary.by_severity || {};
  const cells = SEVERITIES.filter((s) => s !== 'unknown' || sev.unknown)
    .map((s) => ({ key: s, label: s, value: sev[s] || 0 }));
  cells.push({ key: 'fixnow', label: 'Fix now', value: summary.by_band?.P1 || 0 });
  return h('section', { class: 'kpistrip', 'aria-label': 'Finding counts' }, cells.map((c) => {
    const v = h('span', { class: 'kpistrip__v' }, '0');
    countUp(v, c.value);
    return h('div', { class: 'kpistrip__cell', dataset: { sev: c.key, zero: String(!c.value) } },
      v, h('span', { class: 'kpistrip__k' }, c.label));
  }));
}

function chipGroup(label, options, active, onToggle) {
  return h('div', { class: 'chips', role: 'group', 'aria-label': label },
    h('span', { class: 'chips__label' }, label),
    options.map(([value, text]) => {
      const b = h('button', { class: 'fchip', type: 'button', 'aria-pressed': String(active(value)), dataset: { value } }, text);
      b.addEventListener('click', () => onToggle(value));
      return b;
    }));
}

function row(item, i, onOpen) {
  const p = item.priority;
  const b = h('button', { class: 'frow', type: 'button', dataset: { id: item.id, sev: item.advisory.severity.label },
    style: { '--i': String(Math.min(i, 20)) } },
  h('span', { class: 'frow__bar', 'aria-hidden': 'true' }),
  h('span', { class: 'frow__sev' }, sevChip(item.advisory.severity)),
  h('span', { class: 'frow__pkg' },
    h('span', { class: 'frow__name' }, `${item.package.name}@${item.package.version}`,
      item.package.ecosystem && item.package.ecosystem !== 'npm' ? h('span', { class: 'eco-badge' }, item.package.ecosystem) : null),
    h('span', { class: 'frow__meta' }, item.direct ? 'direct' : `depth ${item.depth ?? '?'}`, ' · ', `${item.path_count} path${item.path_count === 1 ? '' : 's'}`)),
  h('span', { class: 'frow__adv' },
    h('span', { class: 'frow__id' }, item.advisory.id),
    h('span', { class: 'frow__summary' }, item.advisory.summary)),
  h('span', { class: 'frow__path' }, pathchain(item.path, { compact: true })),
  h('span', { class: 'frow__scope' }, h('span', { class: 'scope', dataset: { scope: item.scope } }, item.scope)),
  h('span', { class: 'frow__fix' }, item.fix_available ? h('span', { class: 'chip chip--ok' }, 'fix') : h('span', { class: 'chip chip--warn' }, 'no fix')),
  h('span', { class: 'frow__prio' }, gauge(p.score, p.band, 36), h('span', { class: 'frow__band', dataset: { band: p.band } }, p.band_label)));
  b.addEventListener('click', () => onOpen(item.id));
  return h('li', null, b);
}

function section(title, ...children) {
  return h('section', { class: 'dsec' }, h('h3', { class: 'dsec__title' }, title), ...children);
}

export function detail(f, { graphHref = '', jobId = '' } = {}) {
  const adv = f.advisory;
  const p = f.priority;
  const sevSrc = adv.severity.source ? ` · ${adv.severity.source}` : '';
  const more = f.path_count - f.paths.length;
  const cached = f.scan.source === 'cache';
  const hitFixes = new Set(f.affected_ranges.filter((r) => r.contains && r.fixed).map((r) => r.fixed));
  return h('article', { class: 'detail', dataset: { sev: adv.severity.label } },
    h('header', { class: 'detail__head' },
      h('div', { class: 'detail__chips' }, sevChip(adv.severity), h('span', { class: 'chip' }, adv.id),
        adv.aliases.slice(0, 3).map((a) => h('span', { class: 'chip chip--dim' }, a)),
        graphHref ? h('a', { class: 'detail__graph', href: graphHref }, 'Show in graph →') : null),
      h('h2', { class: 'detail__title', id: 'detail-title' }, adv.summary),
      h('p', { class: 'detail__pkg' }, `${f.package.name}@${f.package.version}`, h('span', null, ` · ${f.scope} · ${f.direct ? 'direct' : `depth ${f.depth ?? '?'}`}`)),
      adv.severity.vector ? h('p', { class: 'detail__vector' }, adv.severity.vector, sevSrc) : null,
      jobId ? h('div', { class: 'detail__actions' },
        h('a', { class: 'btn btn--primary btn--sm', href: `#/jobs/${jobId}/fix/${f.id}` }, 'Propose a fix')) : null),
    jobId ? explainPanel(jobId, f.id) : null,
    section('Priority',
      h('div', { class: 'prio' }, gauge(p.score, p.band, 72),
        h('div', null, h('p', { class: 'prio__band', dataset: { band: p.band } }, `${p.band} · ${p.band_label}`),
          h('p', { class: 'prio__note' }, 'Transparent score: every point below cites its evidence.'))),
      h('ul', { class: 'signals' }, p.signals.map((s) => h('li', { class: 'signal', dataset: { zero: String(!s.points) } },
        h('span', { class: 'signal__pts' }, `+${s.points}`), h('span', null, `${s.label}: ${s.value}`),
        s.eid ? h('button', { class: 'signal__eid', type: 'button', 'aria-label': `Show evidence ${s.eid}`,
          onclick: () => document.getElementById(`ev-${s.eid}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' }) }, s.eid) : null))),
      p.flags.length ? h('p', { class: 'note note--warn' }, p.flags.map((fl) => h('span', { class: 'chip chip--warn' }, fl))) : null),
    section(`Dependency path${f.paths.length === 1 ? '' : 's'}`,
      h('div', { class: 'paths' }, f.paths.map((path) => pathchain(path))),
      more > 0 ? h('p', { class: 'muted' }, `and ${more} more path${more === 1 ? '' : 's'}`) : null),
    section('Affected ranges',
      h('ul', { class: 'ranges' }, f.affected_ranges.map((r) => h('li', { class: ['range', r.contains && 'is-hit'] },
        h('code', null, r.text), r.contains ? h('span', { class: 'chip chip--err' }, `includes ${f.package.version}`) : null))),
      h('p', { class: 'fixline' }, f.fix_available
        ? ['Fixed in ', f.fixed_versions.map((v) => h('code', { class: ['ver', !hitFixes.has(v) && 'ver--dim'], title: hitFixes.has(v) ? 'Fix for the installed range' : 'Fix for another release line' }, v))]
        : h('span', { class: 'chip chip--warn' }, 'No fixed version published'))),
    section('Evidence',
      h('ol', { class: 'evidence' }, f.evidence.map((e) => h('li', { class: 'ev', id: `ev-${e.eid}` },
        h('span', { class: 'ev__id' }, e.eid),
        h('div', null, h('p', null, e.text), h('p', { class: 'ev__src' }, h('span', { class: 'ev__label', dataset: { label: e.label } }, e.label), ` · ${e.kind} · ${e.source}`))))),
      h('p', { class: 'muted' }, '“Confirmed” means the lockfile version falls inside the advisory range: presence, not proof of exploitability.')),
    adv.details ? section('Advisory details', h('div', { class: 'details' }, md(adv.details))) : null,
    adv.refs.length ? section('References', h('ul', { class: 'refs' }, adv.refs.map((r) => h('li', null,
      h('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer nofollow' }, r.url), h('span', { class: 'muted' }, ` ${r.type.toLowerCase()}`))))) : null,
    h('footer', { class: 'detail__foot' },
      `Scanned with ${f.scan.scanner} (${f.scan.version}) at ${stamp(f.scan.ts)}`,
      cached ? h('span', { class: 'chip chip--warn' }, `Cached scan from ${stamp(f.scan.ts)} — live scanner unavailable.`) : null));
}

export function findings({ id }) {
  const state = { items: [], q: '', sort: 'priority', sev: new Set(), scope: new Set(), direct: null, fix: null, sel: -1, openId: null };
  const head = h('header', { class: 'fhead' }, h('span', { class: 'eyebrow' }, `Job ${shortId(id)}`), h('h1', { class: 'fhead__title' }, 'Findings'), h('p', { class: 'fhead__meta' }));
  const kpis = h('div', { class: 'skeleton skeleton--kpi' });
  const search = h('input', { class: 'search__input', type: 'search', placeholder: 'Search package, advisory, CVE…', 'aria-label': 'Search findings', autocomplete: 'off' });
  const toolbar = h('div', { class: 'toolbar' });
  const list = h('ol', { class: 'ftable', 'aria-label': 'Findings', 'aria-busy': 'true' },
    Array.from({ length: 6 }, () => h('li', { class: 'skeleton frow--skel', 'aria-hidden': 'true' })));
  const count = h('p', { class: 'fcount', role: 'status' });
  const body = h('div', { class: 'fbody' }, list);
  const dr = drawer({ label: 'Finding detail', onClose: () => { state.openId = null; focusSel(); } });
  const el = h('div', { class: 'findings' },
    h('div', { class: 'container fwrap' }, head, kpis,
      h('div', { class: 'fcontrols' }, h('label', { class: 'search' }, icon(SEARCH, 16), search, h('kbd', null, '/')), toolbar, count),
      body),
    dr.scrim, dr.el);

  const visible = () => {
    const q = state.q.trim().toLowerCase();
    const out = state.items.filter((f) => (!state.sev.size || state.sev.has(f.advisory.severity.label))
      && (!state.scope.size || state.scope.has(f.scope))
      && (state.direct === null || f.direct === state.direct)
      && (state.fix === null || f.fix_available === state.fix)
      && (!q || [f.package.name, f.advisory.id, ...f.advisory.aliases, f.advisory.summary].join(' ').toLowerCase().includes(q)));
    return SORTERS[state.sort] ? [...out].sort(SORTERS[state.sort]) : out;
  };

  function renderToolbar() {
    const toggle = (set) => (v) => { set.has(v) ? set.delete(v) : set.add(v); render(); };
    const tri = (key) => (v) => { state[key] = state[key] === v ? null : v; render(); };
    const present = new Set(state.items.map((f) => f.advisory.severity.label));
    const scopes = new Set(state.items.map((f) => f.scope));
    toolbar.replaceChildren(
      chipGroup('Severity', SEVERITIES.filter((s) => present.has(s)).map((s) => [s, s]), (v) => state.sev.has(v), toggle(state.sev)),
      chipGroup('Scope', SCOPES.filter((s) => scopes.has(s)).map((s) => [s, s]), (v) => state.scope.has(v), toggle(state.scope)),
      chipGroup('Depth', [[true, 'direct'], [false, 'transitive']], (v) => state.direct === v, tri('direct')),
      chipGroup('Fix', [[true, 'fix available'], [false, 'no fix']], (v) => state.fix === v, tri('fix')),
      h('label', { class: 'sort' }, 'Sort ', (() => {
        const sel = h('select', { 'aria-label': 'Sort findings' }, [['priority', 'Priority'], ['severity', 'Severity'], ['name', 'Name']]
          .map(([v, t]) => h('option', { value: v, selected: state.sort === v }, t)));
        sel.addEventListener('change', () => { state.sort = sel.value; render(); });
        return sel;
      })()));
  }

  function render() {
    renderToolbar();
    const rows = visible();
    state.sel = Math.min(state.sel, rows.length - 1);
    count.textContent = `${rows.length} of ${state.items.length} shown`;
    if (!rows.length) {
      list.replaceChildren(h('li', { class: 'fempty' }, h('p', { class: 'fempty__title' }, 'No findings match these filters.'),
        h('button', { class: 'btn btn--ghost', type: 'button', onclick: clearFilters }, 'Clear filters')));
      return;
    }
    list.removeAttribute('aria-busy');
    list.replaceChildren(...rows.map((f, i) => row(f, i, open)));
    markSel();
  }

  function clearFilters() {
    Object.assign(state, { q: '', sev: new Set(), scope: new Set(), direct: null, fix: null });
    search.value = '';
    render();
  }

  function markSel() {
    list.querySelectorAll('.frow').forEach((b, i) => b.classList.toggle('is-sel', i === state.sel));
  }

  function focusSel() {
    list.querySelectorAll('.frow')[state.sel]?.focus({ preventScroll: false });
  }

  async function open(fid) {
    const rows = [...list.querySelectorAll('.frow')];
    state.sel = rows.findIndex((b) => b.dataset.id === fid);
    markSel();
    state.openId = fid;
    dr.show(h('div', { class: 'skeleton skeleton--detail' }));
    try {
      const f = await api(`/jobs/${id}/findings/${fid}`);
      if (state.openId === fid) dr.show(detail(f, { graphHref: `#/jobs/${id}/graph?focus=${f.id}`, jobId: id }));
    } catch (err) {
      dr.show(h('p', { class: 'note note--warn' }, `${err.code || 'Error'} · ${err.message}`));
    }
  }

  function onKey(e) {
    const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement;
    if (e.key === 'Escape') {
      if (dr.isOpen()) dr.hide();
      else if (typing) e.target.blur();
      return;
    }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    const rows = list.querySelectorAll('.frow');
    if (e.key === 'g') {
      go(`/jobs/${id}/graph`);
    } else if (e.key === '/') {
      e.preventDefault();
      search.focus();
    } else if ((e.key === 'j' || e.key === 'k') && rows.length) {
      e.preventDefault();
      state.sel = Math.max(0, Math.min(rows.length - 1, state.sel + (e.key === 'j' ? 1 : -1)));
      markSel();
      rows[state.sel].focus();
      if (dr.isOpen()) open(rows[state.sel].dataset.id);
    }
  }

  search.addEventListener('input', () => { state.q = search.value; render(); });
  document.addEventListener('keydown', onKey);

  api(`/jobs/${id}`).then((job) => {
    store.set({ job });
    head.querySelector('.eyebrow').textContent = `Job ${shortId(id)} · ${job.filename || 'project'}${job.summary?.language ? ` · ${job.summary.language}` : ''}`;
  }).catch(() => {});

  api(`/jobs/${id}/findings?sort=priority`)
    .then((data) => {
      state.items = data.items;
      const sm = data.summary || {};
      const scan = sm.scan || {};
      head.querySelector('.fhead__title').textContent = `${data.total} finding${data.total === 1 ? '' : 's'}`;
      const meta = [`${sm.packages ?? '?'} packages · scanned with ${scan.scanner} at ${stamp(scan.ts)}`];
      if (sm.policy) meta.push(policyChip(h, sm.policy));
      meta.push(h('a', { class: 'btn btn--ghost btn--sm', href: `#/jobs/${id}/plan` }, 'Plan all fixes'));
      if (scan.source === 'cache') meta.push(h('span', { class: 'chip chip--warn' }, `Cached scan from ${stamp(scan.ts)} — live scanner unavailable.`));
      head.querySelector('.fhead__meta').replaceChildren(...meta);
      kpis.replaceWith(kpiStrip(sm));
      if (!data.total) {
        el.querySelector('.fcontrols').hidden = true;
        body.replaceChildren(h('section', { class: 'panel card card--ready clean' },
          h('div', { class: 'card__head' }, h('span', { class: 'chip chip--ok' }, 'NO KNOWN ADVISORIES')),
          h('p', { class: 'card__title' }, NO_FINDINGS(stamp(scan.ts)))));
        return;
      }
      render();
    })
    .catch((err) => {
      kpis.remove();
      el.querySelector('.fcontrols').hidden = true;
      body.replaceChildren(h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message),
        err.hint ? h('p', { class: 'card__hint' }, err.hint) : null,
        h('div', { class: 'card__actions' }, h('a', { class: 'btn btn--ghost', href: `#/jobs/${id}` }, 'Back to scan'))));
    });

  return {
    el,
    destroy() {
      document.removeEventListener('keydown', onKey);
    },
  };
}
