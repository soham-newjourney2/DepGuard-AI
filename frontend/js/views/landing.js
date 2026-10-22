import { launch } from '../api.js';
import { toast } from '../components/toast.js';
import { h, icon, reducedMotion } from '../dom.js';
import { bytes } from '../format.js';
import { constellation } from '../fx/constellation.js';
import { go } from '../router.js';
import * as store from '../store.js';

const MB = 1024 * 1024;
const UPLOAD = ['M12 15V4', 'M7.5 8.5 12 4l4.5 4.5', 'M4 15v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3'];
const CHAIN = ['root', 'express@4.17.1', 'body-parser@1.19.0', 'qs@6.7.0'];

function typeOut(el, text) {
  clearInterval(el._typing);
  if (reducedMotion()) { el.textContent = text; return; }
  let i = 0;
  el.textContent = '';
  el._typing = setInterval(() => {
    el.textContent = text.slice(0, ++i);
    if (i >= text.length) clearInterval(el._typing);
  }, 22);
}

function chain(items) {
  return h('div', { class: 'chain', 'aria-label': items.join(' → ') },
    items.flatMap((item, i) => [
      i ? h('span', { class: 'chain__arrow', 'aria-hidden': 'true' }, '→') : null,
      h('span', { class: ['chain__chip', i === items.length - 1 && 'chain__chip--hot'] }, item),
    ]));
}

function dropZone() {
  const file = h('div', { class: 'drop__file', 'aria-live': 'polite' });
  const status = h('div', { class: 'drop__status', role: 'status' });
  const input = h('input', { type: 'file', accept: '.zip,application/zip', class: 'visually-hidden', tabindex: '-1',
    'aria-hidden': 'true', onchange: (e) => { pick(e.target.files[0]); e.target.value = ''; } });
  const choose = h('button', { class: 'btn btn--primary', type: 'button', onclick: () => input.click() }, 'Choose .zip');
  const demo = h('button', { class: 'btn btn--ghost', type: 'button', 'data-action': 'demo',
    onclick: () => begin({ kind: 'demo', sample: 'vuln-demo' }) }, 'Try the demo project');
  const messy = h('button', { class: 'btn btn--ghost', type: 'button', 'data-action': 'demo-2',
    onclick: () => begin({ kind: 'demo', sample: 'messy-demo' }) }, 'Messy demo (73 issues)');
  const pydemo = h('button', { class: 'btn btn--ghost', type: 'button', 'data-action': 'demo-py',
    onclick: () => begin({ kind: 'demo', sample: 'python-demo' }) }, 'Python demo');
  const scdemo = h('button', { class: 'btn btn--ghost', type: 'button', 'data-action': 'demo-sc',
    title: 'Scan-only project with planted malware, git, typosquat and secret signals',
    onclick: () => begin({ kind: 'demo', sample: 'supplychain-demo' }) }, 'Supply-chain demo');
  let depth = 0, busy = false;

  const zone = h('section', { class: 'drop', 'aria-label': 'Upload a project' },
    h('div', { class: 'drop__ring', 'aria-hidden': 'true' }),
    h('div', { class: 'drop__inner' },
      h('div', { class: 'drop__head' },
        h('div', { class: 'drop__icon' }, icon(UPLOAD, 22)),
        h('div', null,
          h('p', { class: 'drop__title' }, 'Drop a project .zip'),
          h('p', { class: 'drop__meta' }, `Any lockfile: npm, Python, Go, Rust, PHP, Ruby, .NET, Gradle · ≤ ${limitMb()} MB`))),
      h('div', { class: 'drop__actions' }, choose, demo, messy, pydemo, scdemo),
      file, status, input));

  function limitMb() {
    return store.get().health?.max_upload_mb ?? 15;
  }

  async function begin(source) {
    if (busy) return;
    busy = true;
    zone.classList.add('is-busy');
    choose.disabled = demo.disabled = messy.disabled = true;
    status.textContent = source.kind === 'demo' ? 'Preparing demo project…' : 'Uploading…';
    try {
      const { job_id } = await launch(source);
      store.set({ lastSource: source });
      go(`/jobs/${job_id}`);
    } catch (err) {
      status.textContent = '';
      toast(`${err.code ? `${err.code} · ` : ''}${err.message}${err.hint ? ` ${err.hint}` : ''}`, { kind: 'err', timeout: 6000 });
    } finally {
      busy = false;
      zone.classList.remove('is-busy');
      choose.disabled = demo.disabled = messy.disabled = false;
    }
  }

  function pick(f) {
    if (!f || busy) return;
    const limit = limitMb();
    if (!/\.zip$/i.test(f.name)) {
      toast(`${f.name} is not a .zip file.`, { kind: 'err' });
      return;
    }
    if (f.size > limit * MB) {
      toast(`${f.name} is ${bytes(f.size)}; the limit is ${limit} MB. Exclude node_modules and build output.`, { kind: 'err', timeout: 6000 });
      return;
    }
    typeOut(file, f.name);
    begin({ kind: 'file', file: f });
  }

  zone.addEventListener('dragenter', (e) => { e.preventDefault(); depth++; zone.classList.add('is-over'); });
  zone.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
  zone.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; zone.classList.remove('is-over'); } });
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    depth = 0;
    zone.classList.remove('is-over');
    pick(e.dataTransfer.files[0]);
  });
  return zone;
}

const REPO = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}(@[A-Za-z0-9._/-]{1,200})?$/;
const GITHUB = /^(?:(?:https?:\/\/)?(?:www\.)?github\.com\/|git@github\.com:)\S+$/i;
const KIND_LABEL = { github: 'GitHub repo', none: '' };

function classify(value) {
  const v = value.trim();
  if (!v) return 'none';
  if (REPO.test(v) || GITHUB.test(v)) return 'github';
  return 'invalid';
}

function githubForm() {
  const input = h('input', { class: 'gh__input', type: 'text', placeholder: 'github.com/owner/repo  ·  owner/repo@ref', 'aria-label': 'GitHub repository link', autocomplete: 'off', spellcheck: 'false' });
  const kind = h('span', { class: 'gh__kind', 'aria-live': 'polite' });
  const button = h('button', { class: 'btn btn--ghost btn--sm', type: 'submit' }, 'Scan');
  const form = h('form', { class: 'gh', 'aria-label': 'Scan a GitHub repository' },
    h('span', { class: 'gh__label' }, 'or paste a public GitHub repo'), input, kind, button);
  if (store.get().health?.local_only) form.hidden = true;
  input.addEventListener('input', () => {
    const k = classify(input.value);
    kind.textContent = KIND_LABEL[k] ?? 'Not recognised';
    kind.dataset.kind = k;
  });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = input.value.trim();
    const k = classify(value);
    if (k === 'none' || k === 'invalid') {
      toast('Paste a GitHub link (github.com/owner/repo) or owner/repo@ref.', { kind: 'err' });
      return;
    }
    button.disabled = true;
    try {
      const source = { kind: 'github', repo: value };
      const { job_id } = await launch(source);
      store.set({ lastSource: source });
      go(`/jobs/${job_id}`);
    } catch (err) {
      toast(`${err.code || 'Error'} · ${err.message}${err.hint ? ` ${err.hint}` : ''}`, { kind: 'err', timeout: 6000 });
    } finally {
      button.disabled = false;
    }
  });
  return form;
}

export function landing() {
  const canvas = h('canvas', { class: 'hero__fx', 'aria-hidden': 'true' });
  const el = h('div', { class: 'landing' },
    h('section', { class: 'hero' },
      canvas,
      h('div', { class: 'container' },
        h('div', { class: 'hero__copy' },
          h('span', { class: 'eyebrow' }, 'npm · Python · Go · Rust · PHP · Ruby · .NET · Java · OSV advisories'),
          h('h1', { class: 'hero__title' }, 'Know which dependency ', h('em', 'actually'), ' puts you at risk.'),
          h('p', { class: 'hero__lede' },
            'DepGuard traces the path from your project to each vulnerable package, proposes the smallest defensible fix, and proves it with a real install, your tests and a fresh rescan.'),
          dropZone(),
          githubForm(),
          h('p', { class: 'hero__note' }, 'Nothing you upload runs on the API server. Findings are evidence, not verdicts.')))),
    h('section', { class: 'how', 'aria-label': 'How it works' },
      h('div', { class: 'container' },
        h('article', { class: 'how__item' },
          h('span', { class: 'how__num' }, '01'),
          h('h2', { class: 'how__title' }, 'Trace'),
          h('p', { class: 'how__copy' }, 'See the exact chain that pulls a vulnerable package into your build — direct or five levels deep.'),
          chain(CHAIN)),
        h('article', { class: 'how__item' },
          h('span', { class: 'how__num' }, '02'),
          h('h2', { class: 'how__title' }, 'Fix'),
          h('p', { class: 'how__copy' }, 'Candidates ranked by the smallest version jump that resolves the advisory, with the diff up front.')),
        h('article', { class: 'how__item' },
          h('span', { class: 'how__num' }, '03'),
          h('h2', { class: 'how__title' }, 'Verify'),
          h('p', { class: 'how__copy' }, 'Approve, then watch a clean install, your tests and a fresh rescan — before anything ships.')))));

  const fx = constellation(canvas, { reduced: reducedMotion() });
  return { el, destroy: () => fx.destroy() };
}
