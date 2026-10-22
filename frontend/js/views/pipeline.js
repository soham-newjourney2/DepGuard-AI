import { api, launch } from '../api.js';
import { kpi } from '../components/kpi.js';
import { toast } from '../components/toast.js';
import { h, s } from '../dom.js';
import { clock, duration, shortId } from '../format.js';
import { go } from '../router.js';
import { follow } from '../sse.js';
import * as store from '../store.js';

const STEPS = [
  ['queued', 'Queued', 'Job accepted'],
  ['extracting', 'Extract', 'Safe unzip and validation'],
  ['parsing', 'Parse', 'Lockfile to package list'],
  ['scanning', 'Scan', 'Known advisories (OSV)'],
  ['analyzing', 'Analyze', 'Paths, priority, evidence'],
  ['ready', 'Ready', 'Results available'],
];
const INDEX = Object.fromEntries(STEPS.map(([k], i) => [k, i]));

const check = () => s('svg', { class: 'step__check', viewBox: '0 0 16 16', 'aria-hidden': 'true' },
  s('path', { d: 'M3.5 8.5l3 3 6-7' }));

function stepRow([key, label, desc], i) {
  const time = h('span', { class: 'step__time' });
  const dur = h('span', { class: 'step__dur' });
  const el = h('li', { class: 'step', dataset: { step: key, state: 'pending' } },
    h('span', { class: 'step__sheen', 'aria-hidden': 'true' }),
    h('span', { class: 'step__mark' }, h('span', { class: 'step__num' }, String(i + 1).padStart(2, '0')), check()),
    h('span', { class: 'step__body' }, h('span', { class: 'step__label' }, label), h('span', { class: 'step__desc' }, desc)),
    h('span', { class: 'step__meta' }, time, dur));
  return { el, time, dur };
}

function retryButton() {
  const source = store.get().lastSource;
  if (!source) return null;
  const btn = h('button', { class: 'btn btn--primary', type: 'button' }, 'Retry');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    try {
      const { job_id } = await launch(source);
      go(`/jobs/${job_id}`);
    } catch (err) {
      toast(`${err.code || 'Error'} · ${err.message}`, { kind: 'err' });
      btn.disabled = false;
    }
  });
  return btn;
}

function commonPrefix(paths) {
  const parts = paths.map((p) => p.split('/'));
  const first = parts[0];
  let n = 0;
  while (n < first.length - 1 && parts.every((p) => p.length > n + 1 && p[n] === first[n])) n += 1;
  return n ? `${first.slice(0, n).join('/')}/` : '';
}

function projectPicker(options, jobId, current) {
  if (!options?.length) return null;
  const prefix = commonPrefix(options.map((o) => o.split('#')[0]));
  return h('div', { class: 'picker' }, h('p', { class: 'picker__label' }, prefix ? `Projects inside ${prefix}` : 'Projects found:'),
    h('div', { class: 'picker__list' }, options.map((opt) => {
      const [path, lang] = opt.split('#');
      const here = opt === current;
      const btn = h('button', { class: 'btn btn--ghost btn--sm picker__opt', type: 'button', disabled: here, 'aria-current': here ? 'true' : null },
        h('code', null, `${path.slice(prefix.length) || path}/`), h('span', { class: 'eco-badge' }, here ? 'analysed' : lang || 'Node.js'));
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
          const { job_id } = await api(`/jobs/${jobId}/project`, { method: 'POST', body: { project: opt } });
          go(`/jobs/${job_id}`);
        } catch (err) {
          toast(`${err.code || 'Error'} · ${err.message}`, { kind: 'err' });
          btn.disabled = false;
        }
      });
      return btn;
    })));
}

function warningNote(w, jobId) {
  if (w.code === 'W_MULTIPLE_PROJECTS' && w.options?.length) {
    return h('div', { class: 'note note--switch' }, h('p', null, h('span', { class: 'chip chip--warn' }, 'PROJECTS'), ' ', w.message),
      projectPicker(w.options, jobId, w.chosen));
  }
  return h('p', { class: 'note note--warn' }, h('span', { class: 'chip chip--warn' }, w.code), ' ', w.message);
}

function errorCard(error, jobId) {
  return h('section', { class: 'panel card card--error', role: 'alert' },
    h('div', { class: 'card__head' },
      h('span', { class: 'chip chip--err' }, error?.code || 'E_UNKNOWN'),
      h('span', { class: 'card__eyebrow' }, 'Scan stopped')),
    h('h2', { class: 'card__title' }, error?.message || 'The job failed.'),
    error?.hint ? h('p', { class: 'card__hint' }, error.hint) : null,
    projectPicker(error?.options, jobId),
    h('div', { class: 'card__actions' }, error?.options?.length ? null : retryButton(),
      h('a', { class: 'btn btn--ghost', href: '#/' }, 'Choose another file')));
}

function infoCard(title, copy) {
  return h('section', { class: 'panel card' },
    h('h2', { class: 'card__title' }, title),
    h('p', { class: 'card__hint' }, copy),
    h('div', { class: 'card__actions' }, h('a', { class: 'btn btn--ghost', href: '#/' }, 'Start a new scan')));
}

function readyCard(job) {
  const sm = job.summary || {};
  return h('section', { class: 'panel card card--ready' },
    h('div', { class: 'card__head' },
      h('span', { class: 'chip chip--ok' }, 'READY'),
      sm.language ? h('span', { class: 'eco-badge' }, sm.language) : null,
      h('span', { class: 'card__eyebrow' }, `Finished ${clock(job.updated_at)}`)),
    h('div', { class: 'kpis' },
      kpi('Findings', sm.findings ?? 0, 'Known advisories matched to installed versions'),
      kpi('Packages', sm.packages ?? 0, 'Installed packages listed in the lockfile'),
      kpi('Fix now', sm.by_band?.P1 ?? 0, 'Findings in priority band P1')),
    (job.warnings || []).map((w) => warningNote(w, job.id)),
    h('div', { class: 'card__actions' },
      sm.findings ? h('a', { class: 'btn btn--primary', href: `#/jobs/${job.id}/findings` }, `View ${sm.findings} finding${sm.findings === 1 ? '' : 's'}`)
        : h('a', { class: 'btn btn--primary', href: `#/jobs/${job.id}/findings` }, 'View result'),
      sm.risk_counts?.total ? h('a', { class: 'btn btn--ghost', href: `#/jobs/${job.id}/risks` }, `Supply chain · ${sm.risk_counts.total} signal${sm.risk_counts.total === 1 ? '' : 's'}`) : null,
      job.source === 'demo' ? h('a', { class: 'btn btn--ghost', href: `#/jobs/${job.id}/answer-key` }, 'Compare with answer key') : null,
      h('a', { class: 'btn btn--ghost', href: '#/' }, 'Scan another project')));
}

export function pipeline({ id }) {
  const rows = STEPS.map(stepRow);
  const title = h('h1', { class: 'job__title' }, 'Loading job…');
  const meta = h('p', { class: 'job__meta' });
  const logList = h('ol', { class: 'log__list', 'aria-live': 'polite' });
  const logCount = h('span', { class: 'log__count' }, '0');
  const outcome = h('div', { class: 'job__outcome' }, h('div', { class: 'skeleton outcome-skel', 'aria-hidden': 'true' }));
  const stepsEl = h('ol', { class: 'steps', 'aria-label': 'Scan progress' }, rows.map((r) => r.el));
  const el = h('div', { class: 'container job' },
    h('header', { class: 'job__head' },
      h('span', { class: 'eyebrow' }, `Job ${shortId(id)}`), title, meta),
    outcome,
    h('section', { class: 'panel job__rail' }, stepsEl),
    h('section', { class: 'panel log' },
      h('header', { class: 'log__head' }, h('span', null, 'Event log'), logCount),
      logList));

  let reached = -1, failed = false, finished = false, startedAt = null, timer = 0, close = null, stuck = true;
  const times = [];

  logList.addEventListener('scroll', () => {
    stuck = logList.scrollHeight - logList.scrollTop - logList.clientHeight < 24;
  });

  function render() {
    rows.forEach((r, i) => {
      let state = 'pending';
      if (i < reached) state = 'done';
      else if (i === reached) state = failed ? 'failed' : i === STEPS.length - 1 ? 'done' : 'active';
      r.el.dataset.state = state;
      if (state === 'active') r.el.setAttribute('aria-current', 'step');
      else r.el.removeAttribute('aria-current');
      r.time.textContent = times[i] ? clock(times[i]) : '';
    });
  }

  function tickElapsed() {
    if (!startedAt) return;
    const ms = Date.now() - new Date(startedAt).getTime();
    meta.textContent = `Started ${clock(startedAt)} · ${finished ? 'took' : 'elapsed'} ${duration(Math.max(0, ms))}`;
  }

  function addLog(ts, text, level = 'info') {
    logList.append(h('li', { class: ['log__line', `log__line--${level}`] },
      h('time', { datetime: ts }, clock(ts)), h('span', null, text)));
    logCount.textContent = String(logList.children.length);
    if (stuck) logList.scrollTop = logList.scrollHeight;
  }

  function finish() {
    finished = true;
    clearInterval(timer);
  }

  async function settle() {
    finish();
    try {
      const job = await api(`/jobs/${id}`);
      meta.textContent = `Started ${clock(job.created_at)} · took ${duration(new Date(job.updated_at) - new Date(job.created_at))}`;
      store.set({ job });
      if (job.status === 'ready') outcome.replaceChildren(readyCard(job));
      else if (job.status === 'failed') outcome.replaceChildren(errorCard(job.error, job.id));
      else if (job.status === 'expired') outcome.replaceChildren(infoCard('This job expired.', 'Uploaded files were deleted after the retention window.'));
    } catch (err) {
      outcome.replaceChildren(infoCard('Job not found.', err.hint || 'It may have expired or been deleted.'));
    }
  }

  function onEvent(e) {
    const d = e.data || {};
    if (d.snapshot && d.step in INDEX) reached = Math.max(reached, INDEX[d.step]);
    if (e.type === 'status' && d.status in INDEX) {
      const k = INDEX[d.status];
      if (!d.snapshot) times[k] ??= e.ts;
      if (k > reached) reached = k;
      render();
      if (d.status !== 'queued' && !d.snapshot) addLog(e.ts, `→ ${STEPS[k][1]}`, 'step');
    } else if (e.type === 'step' && d.step in INDEX) {
      rows[INDEX[d.step]].dur.textContent = duration(d.ms);
    } else if (e.type === 'log') {
      addLog(e.ts, d.message, d.level);
    } else if (e.type === 'error') {
      failed = true;
      render();
      addLog(e.ts, `${d.error?.code}: ${d.error?.message}`, 'err');
      settle();
    } else if (e.type === 'done') {
      settle();
    } else if (e.type === 'status' && d.status === 'expired') {
      failed = true;
      render();
      settle();
    } else if (e.type === 'status' && d.status === 'failed') {
      failed = true;
      render();
    }
  }

  api(`/jobs/${id}`)
    .then((job) => {
      store.set({ job });
      title.textContent = job.filename || 'Untitled project';
      startedAt = job.created_at;
      tickElapsed();
      timer = setInterval(tickElapsed, 250);
      close = follow(`/api/jobs/${id}/events`, { onEvent, onLost: settle });
    })
    .catch((err) => {
      title.textContent = 'Job not found';
      stepsEl.hidden = true;
      outcome.replaceChildren(infoCard('This job does not exist.', err.hint || 'It may have expired or been deleted.'));
    });

  return {
    el,
    destroy() {
      close?.();
      clearInterval(timer);
    },
  };
}
