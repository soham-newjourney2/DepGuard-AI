import { api } from '../api.js';
import { diffView } from '../components/diff.js';
import { terminal } from '../components/terminal.js';
import { h } from '../dom.js';
import { duration, shortId } from '../format.js';
import { follow } from '../sse.js';

const STAGES = [['approved', 'Approved'], ['resolve', 'Resolve'], ['test', 'Test'], ['rescan', 'Rescan'], ['result', 'Result']];
const FINAL = new Set(['verified', 'verify_failed', 'unable_to_verify']);
const ORDER = { approved: 0, resolving: 1, testing: 2, rescanning: 3 };
const MODE = { docker: 'Docker container', 'demo-local': 'Local · bundled sample', mock: 'Simulated (test mode)', off: 'Off', auto: 'Auto' };
const OUTCOME = {
  verified: ['ok', 'Verified', 'The advisory no longer matches and the tests exited 0.'],
  verify_failed: ['err', 'Verification failed', ''],
  unable_to_verify: ['warn', 'Unable to verify', ''],
};

function list(items, cls) {
  return h('ul', { class: ['vlist', cls] }, items.map((x) => h('li', null,
    h('code', null, x.package), ' ', h('span', { class: 'sev', dataset: { sev: x.severity } }, x.severity), ' ', h('span', { class: 'muted' }, x.advisory))));
}

function resultCard(r, jobId) {
  const [kind, title, copy] = OUTCOME[r.status];
  const c = r.comparison;
  const delta = r.tree_delta;
  const lock = h('details', { class: 'lockdiff' }, h('summary', null, 'package-lock.json diff'));
  lock.addEventListener('toggle', () => {
    if (lock.open && lock.childElementCount === 1 && r.lock_diff) {
      lock.append(diffView(r.lock_diff + '\n'));
      if (r.lock_diff_truncated) lock.append(h('p', { class: 'muted' }, 'Diff truncated; download the full lockfile from the report.'));
    }
  });
  return h('section', { class: ['panel', 'card', 'vresult', `vresult--${kind}`], role: kind === 'err' ? 'alert' : 'status' },
    h('div', { class: 'card__head' }, h('span', { class: `chip chip--${kind}` }, title.toUpperCase()), h('span', { class: 'card__eyebrow' }, MODE[r.mode] || r.mode || '')),
    h('h2', { class: 'card__title' }, r.reason || copy),
    c ? h('div', { class: 'kpis' },
      h('div', { class: 'kpi' }, h('span', { class: 'kpi__v' }, `${c.before} → ${c.after}`), h('span', { class: 'kpi__k' }, 'Findings')),
      h('div', { class: 'kpi' }, h('span', { class: 'kpi__v' }, c.target_resolved ? 'Yes' : 'No'), h('span', { class: 'kpi__k' }, 'Target resolved')),
      h('div', { class: 'kpi' }, h('span', { class: 'kpi__v' }, String(c.introduced.length)), h('span', { class: 'kpi__k' }, 'Introduced'))) : null,
    (r.labels || []).map((l) => h('p', { class: 'note' }, h('span', { class: 'chip' }, 'note'), ' ', l)),
    c && c.resolved.length ? h('div', { class: 'vsec' }, h('h3', { class: 'dsec__title' }, `Resolved (${c.resolved.length})`), list(c.resolved, 'vlist--ok')) : null,
    c && c.introduced.length ? h('div', { class: 'vsec' }, h('h3', { class: 'dsec__title' }, `Introduced (${c.introduced.length})`), list(c.introduced, 'vlist--err')) : null,
    c && c.residual.length ? h('div', { class: 'vsec' }, h('h3', { class: 'dsec__title' }, `Still present (${c.residual.length})`), list(c.residual, '')) : null,
    delta && delta.changed.length ? h('div', { class: 'vsec' }, h('h3', { class: 'dsec__title' }, `Tree changes (${delta.changed.length})`),
      h('div', { class: 'scard__changes' }, delta.changed.slice(0, 24).map((d) => h('span', { class: 'change' },
        h('span', { class: 'change__pkg' }, d.pkg), ' ', d.from.join(', '), ' → ', h('strong', null, d.to.join(', ')))))) : null,
    r.lock_diff ? lock : null,
    h('div', { class: 'card__actions' }, h('a', { class: 'btn btn--primary', href: `#/jobs/${jobId}/report?pid=${r.pid}` }, 'Open report')));
}

export function verify({ id, pid }) {
  const term = terminal();
  const title = h('h1', { class: 'fhead__title' }, 'Verification');
  const meta = h('p', { class: 'fhead__meta' });
  const rail = h('ol', { class: 'vrail', 'aria-label': 'Verification stages' },
    STAGES.map(([key, label], i) => h('li', { class: 'vstep', dataset: { stage: key, state: 'pending' } },
      h('span', { class: 'vstep__n' }, String(i + 1)), h('span', { class: 'vstep__label' }, label), h('span', { class: 'vstep__meta' }))));
  const outcome = h('div', { class: 'voutcome' });
  const el = h('div', { class: 'verifyview' },
    h('div', { class: 'container fwrap' },
      h('header', { class: 'fhead' }, h('a', { class: 'backlink', href: `#/jobs/${id}/findings` }, '← Findings'),
        h('span', { class: 'eyebrow' }, `Job ${shortId(id)} · ${pid}`), title, meta),
      h('div', { class: 'vwrap' }, rail, outcome, term.el)));
  let close = null;

  const step = (key) => rail.querySelector(`[data-stage="${key}"]`);
  function setStep(key, state, info = '') {
    const s = step(key);
    if (!s) return;
    s.dataset.state = state;
    if (info) s.querySelector('.vstep__meta').textContent = info;
  }

  function reach(status) {
    const n = ORDER[status];
    if (n === undefined) return;
    STAGES.slice(0, n).forEach(([k]) => { if (step(k).dataset.state !== 'failed') setStep(k, 'done'); });
    setStep(STAGES[n][0], 'active');
  }

  function stageDone(stage, status, exitCode, ms) {
    setStep(stage, status === 'passed' ? 'done' : 'failed', `exit ${exitCode ?? '—'} · ${duration(ms)}`);
    term.chip(stage, status, exitCode);
  }

  async function settle() {
    const r = await api(`/jobs/${id}/proposals/${pid}/verification`);
    render(r, true);
  }

  function render(r, live) {
    title.textContent = r.proposal?.title ? `Verify: ${r.proposal.title}` : 'Verification';
    meta.textContent = `${MODE[r.mode] || r.mode || 'pending'} · ${r.proposal?.strategy || ''}`;
    if (!live) {
      setStep('approved', 'done');
      for (const s of r.stages || []) {
        term.marker(`── ${s.name} ── exit ${s.exit_code ?? '—'} · ${duration(s.duration_ms)}`);
        for (const line of (s.log || '').split('\n')) term.line(line);
        stageDone(s.name, s.status, s.exit_code, s.duration_ms);
      }
    }
    if (FINAL.has(r.status)) {
      if (r.comparison) setStep('rescan', 'done');
      setStep('result', r.status === 'verified' ? 'done' : 'failed', OUTCOME[r.status][1]);
      term.stop(r.finished);
      outcome.replaceChildren(resultCard(r, id));
    }
  }

  function onEvent(e) {
    const d = e.data || {};
    if (e.type === 'status') {
      if (d.status === 'approved') { setStep('approved', 'done'); term.start(e.ts); }
      reach(d.status);
      if (d.status === 'rescanning') term.marker('── rescanning new lockfile with OSV ──');
    } else if (e.type === 'stage' && d.state === 'start') {
      term.marker(`── ${d.stage} ──`);
      setStep(d.stage, 'active');
    } else if (e.type === 'stage') {
      stageDone(d.stage, d.status, d.exit_code, d.duration_ms);
    } else if (e.type === 'log') {
      term.line(d.text);
    } else if (e.type === 'done' || e.type === 'error') {
      settle();
    }
  }

  api(`/jobs/${id}/proposals/${pid}/verification`)
    .then((r) => {
      if (FINAL.has(r.status) || r.status === 'proposed') {
        term.start(r.started);
        render(r, false);
        if (r.status === 'proposed') outcome.replaceChildren(h('p', { class: 'muted' }, 'This proposal has not been approved yet.'));
        return;
      }
      title.textContent = r.proposal?.title ? `Verify: ${r.proposal.title}` : 'Verification';
      term.start(r.started);
      close = follow(`/api/jobs/${id}/proposals/${pid}/events`, { onEvent, onLost: settle });
    })
    .catch((err) => {
      outcome.replaceChildren(h('section', { class: 'panel card card--error', role: 'alert' },
        h('div', { class: 'card__head' }, h('span', { class: 'chip chip--err' }, err.code || 'E_UNKNOWN')),
        h('h2', { class: 'card__title' }, err.message)));
    });

  return { el, destroy() { close?.(); term.stop(); } };
}
