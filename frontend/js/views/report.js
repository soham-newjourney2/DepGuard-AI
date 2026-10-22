import { api } from '../api.js';
import { comparison, keyCopy } from './answers.js';
import { KINDS } from './risks.js';
import { diffView } from '../components/diff.js';
import { countUp } from '../components/kpi.js';
import { fill, h } from '../dom.js';
import { describePolicy, shortId, stamp } from '../format.js';
import * as store from '../store.js';

const SEV = ['critical', 'high', 'medium', 'low', 'unknown'];
const SECTIONS = [
  ['resolved', 'Resolved', 'ok', 'No longer matched after the change.'],
  ['still_present', 'Still present', '', 'Residual risk: these advisories still match.'],
  ['newly_detected', 'Newly detected', 'err', 'Matched only after the change.'],
  ['unable_to_verify', 'Unable to verify', 'warn', 'Targeted by the fix, but verification could not run.'],
];
const MODES = { 'demo-local': 'Local · bundled sample', mock: 'Simulated (test mode)' };

const bySeverity = (items) => SEV.map((s) => [s, items.filter((i) => i.severity === s).length]).filter(([, n]) => n);

function bars(items) {
  const total = items.length || 1;
  return h('div', { class: 'sevbar', role: 'img', 'aria-label': bySeverity(items).map(([s, n]) => `${n} ${s}`).join(', ') || 'none' },
    bySeverity(items).map(([s, n]) => h('span', { class: 'sevbar__seg', dataset: { sev: s }, style: { flexGrow: String(n / total) }, title: `${n} ${s}` })));
}

function side(label, items, value) {
  const v = h('span', { class: 'split__v' }, '0');
  countUp(v, value);
  return h('div', { class: 'split__side' }, h('span', { class: 'split__k' }, label), v, bars(items),
    h('ul', { class: 'split__legend' }, bySeverity(items).map(([s, n]) => h('li', { dataset: { sev: s } }, h('i'), `${n} ${s}`))));
}

function rows(items) {
  return h('ul', { class: 'rlist' }, items.map((i) => h('li', { class: 'rlist__item', dataset: { sev: i.severity } },
    h('span', { class: 'sev', dataset: { sev: i.severity } }, h('span', { class: 'sev__dot' }), i.severity),
    h('code', { class: 'rlist__pkg' }, `${i.package}@${i.version}`,
      i.versions_after && !i.versions_after.includes(i.version) ? h('span', { class: 'rlist__moved' }, ` still matched at ${i.versions_after.join(', ')}`) : null),
    h('span', { class: 'rlist__adv' }, i.advisory),
    h('span', { class: 'rlist__sum' }, i.summary))));
}

function sealEl(seal) {
  return h('div', { class: 'seal', dataset: { kind: seal.kind }, role: 'status' },
    h('span', { class: 'seal__ring', 'aria-hidden': 'true' }),
    h('span', { class: 'seal__label' }, seal.label),
    seal.mode ? h('span', { class: 'seal__mode' }, MODES[seal.mode] || seal.mode) : null);
}

function testsCard(r) {
  const t = r.tests;
  let text = 'No verification has run for this job.';
  let kind = '';
  if (t.status === 'passed' && t.present) { text = 'Tests exited 0. Passing tests are evidence, not a guarantee of no regressions.'; kind = 'ok'; }
  else if (t.status === 'passed') { text = 'No test script: nothing beyond dependency resolution was exercised.'; kind = 'warn'; }
  else if (t.status) { text = `Tests ${t.status} (exit ${t.exit_code ?? '—'}).`; kind = 'err'; }
  return h('section', { class: ['panel', 'card', 'rtests', kind && `rtests--${kind}`] },
    h('div', { class: 'card__head' }, h('span', { class: 'card__eyebrow' }, 'TEST RESULT · reported separately from the scan')),
    h('p', { class: 'rtests__text' }, text));
}

function audit(r) {
  const a = r.audit;
  const scanLine = (s) => (s && s.scanner ? `${s.scanner}${s.version ? ` (${s.version})` : ''} · ${stamp(s.ts)} · ${s.source}` : '—');
  return h('section', { class: 'rsec' }, h('h2', { class: 'rsec__title' }, 'Audit trail'),
    h('dl', { class: 'audit' },
      h('dt', null, 'Scan before'), h('dd', null, scanLine(a.scan_before)),
      h('dt', null, 'Scan after'), h('dd', null, scanLine(a.scan_after)),
      h('dt', null, 'Explanations'), h('dd', null, a.ai.model ? `${a.ai.provider} · ${a.ai.model}` : a.ai.provider),
      a.commands.length ? [h('dt', null, 'Commands'), h('dd', null, h('ol', { class: 'audit__cmds' }, a.commands.map((c) => h('li', null, h('code', null, c)))))] : null,
      a.stages.length ? [h('dt', null, 'Stages'), h('dd', null, a.stages.map((s) => h('span', { class: 'xchip', dataset: { status: s.status } }, `${s.name} · exit ${s.exit_code ?? '—'} · ${s.duration_ms} ms`)))] : null),
    h('h3', { class: 'dsec__title' }, 'Limitations'),
    h('ul', { class: 'limits' }, a.limitations.map((l) => h('li', null, l))));
}

function risksSection(id, risks) {
  const n = risks.items.length;
  return h('section', { class: 'rsec rsec--risks', dataset: { kind: n ? 'warn' : 'ok' } },
    h('h2', { class: 'rsec__title' }, 'Supply-chain & hygiene ', h('span', { class: 'rsec__n' }, String(n))),
    h('p', { class: 'muted' }, 'Static signals, not verdicts. Only OSV MAL- records are called malicious; secret values are never stored or shown.'),
    n ? h('p', { class: 'akreport' }, KINDS.filter(([k]) => risks.counts.by_kind[k]).map(([k, label]) => h('span', { class: `chip ${k === 'malware' ? 'chip--err' : 'chip--warn'}` }, `${risks.counts.by_kind[k]} ${label.toLowerCase()}`)),
      h('a', { class: 'btn btn--ghost btn--sm', href: `#/jobs/${id}/risks` }, 'Open supply chain'))
      : h('p', { class: 'muted' }, 'No supply-chain signals.'));
}

function answerKey(id) {
  const sec = h('section', { class: 'rsec rsec--answers' }, h('h2', { class: 'rsec__title' }, 'Answer key'),
    h('div', { class: 'skeleton skeleton--kpi' }));
  api(`/jobs/${id}/answer-key`)
    .then((r) => fill(sec, h('h2', { class: 'rsec__title' }, 'Answer key'),
      r.key ? h('p', { class: 'muted' }, keyCopy(r.key)) : null,
      r.available ? comparison(r)[0] : h('p', { class: 'muted' }, r.reason),
      h('div', { class: 'akreport' }, h('a', { class: 'btn btn--ghost btn--sm', href: `#/jobs/${id}/answer-key` }, 'Open side by side'))))
    .catch((err) => fill(sec, h('h2', { class: 'rsec__title' }, 'Answer key'), h('p', { class: 'muted' }, err.message)));
  return sec;
}

export function report({ id, query = {} }) {
  const body = h('div', { class: 'rbody' }, h('div', { class: 'skeleton skeleton--kpi' }));
  const el = h('div', { class: 'reportview' }, h('div', { class: 'container fwrap' },
    h('header', { class: 'fhead' }, h('a', { class: 'backlink', href: `#/jobs/${id}/findings` }, '← Findings'),
      h('span', { class: 'eyebrow' }, `Job ${shortId(id)} · report`), h('h1', { class: 'fhead__title' }, 'Report')),
    body));
  const q = query.pid ? `&pid=${encodeURIComponent(query.pid)}` : '';

  api(`/jobs/${id}/report?format=json${q}`)
    .then((r) => {
      store.set({ job: { id, status: 'ready' } });
      el.querySelector('.fhead__title').textContent = `Report · ${r.project.filename}`;
      const c = r.classes;
      const before = [...c.resolved, ...c.still_present, ...c.unable_to_verify];
      const after = r.counts.after === null ? null : [...c.still_present, ...c.newly_detected];
      const base = `/api/jobs/${id}/report?download=1${q}`;
      fill(body, [
        h('section', { class: 'rhero' }, sealEl(r.seal),
          h('div', { class: 'split' }, side('Before', before, r.counts.before),
            h('span', { class: 'split__arrow', 'aria-hidden': 'true' }, '→'),
            after ? side('After', after, r.counts.after) : h('div', { class: 'split__side split__side--na' },
              h('span', { class: 'split__k' }, 'After'), h('span', { class: 'split__na' }, 'No verified rescan yet')))),
        h('div', { class: 'downloads' },
          h('a', { class: 'btn btn--ghost btn--sm', href: `${base}&format=json`, download: '' }, 'JSON'),
          h('a', { class: 'btn btn--ghost btn--sm', href: `${base}&format=md`, download: '' }, 'Markdown'),
          h('a', { class: 'btn btn--ghost btn--sm', href: `${base}&format=html`, download: '' }, 'HTML'),
          r.fix?.diff ? h('a', { class: 'btn btn--ghost btn--sm', href: `/api/jobs/${id}/patch?pid=${r.fix.pid}`, download: '' }, '.patch') : null,
          h('a', { class: 'btn btn--ghost btn--sm', href: `/api/jobs/${id}/sbom?download=1`, download: '' }, 'SBOM (CycloneDX)')),
        testsCard(r),
        r.project.source === 'demo' ? answerKey(id) : null,
        r.risks ? risksSection(id, r.risks) : null,
        r.policy ? h('section', { class: ['panel', 'card', 'rpolicy'], dataset: { status: (r.policy.after || r.policy.before).status } },
          h('div', { class: 'card__head' }, h('span', { class: 'card__eyebrow' }, `POLICY · ${r.policy.source}`)),
          h('p', null, describePolicy(r.policy.policy)),
          h('p', { class: 'rpolicy__line' },
            h('span', { class: `chip chip--${r.policy.before.status === 'fail' ? 'err' : 'ok'}` }, `Before ${r.policy.before.status.toUpperCase()} · ${r.policy.before.count}`),
            ' → ',
            r.policy.after ? h('span', { class: `chip chip--${r.policy.after.status === 'fail' ? 'err' : 'ok'}` }, `After ${r.policy.after.status.toUpperCase()} · ${r.policy.after.count}`)
              : h('span', { class: 'muted' }, 'after: not rescanned'))) : null,
        r.fix ? h('section', { class: 'rsec' }, h('h2', { class: 'rsec__title' }, `Fix · ${r.fix.title}`),
          h('p', { class: 'muted' }, `${r.fix.strategy} · ${r.fix.confidence} confidence · ${r.fix.status}`),
          r.fix.diff ? diffView(r.fix.diff) : null) : null,
        SECTIONS.map(([key, title, kind, copy]) => (c[key].length || key !== 'unable_to_verify'
          ? h('section', { class: ['rsec', `rsec--${key}`], dataset: { kind } },
            h('h2', { class: 'rsec__title' }, `${title} `, h('span', { class: 'rsec__n' }, String(c[key].length))),
            h('p', { class: 'muted' }, copy),
            c[key].length ? rows(c[key]) : h('p', { class: 'muted' }, 'None.'))
          : null)),
        audit(r)]);
    })
    .catch((err) => {
      body.replaceChildren(h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message), err.hint ? h('p', { class: 'card__hint' }, err.hint) : null));
    });

  return { el };
}
