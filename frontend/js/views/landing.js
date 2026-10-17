import { h, icon, reducedMotion } from '../dom.js';
import { toast } from '../components/toast.js';
import { constellation } from '../fx/constellation.js';

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
  const input = h('input', { type: 'file', accept: '.zip,application/zip', class: 'visually-hidden', tabindex: '-1',
    'aria-hidden': 'true', onchange: (e) => pick(e.target.files[0]) });
  let depth = 0;

  function pick(f) {
    if (!f) return;
    typeOut(file, f.name);
    toast('Uploads are not enabled in this build yet.', { kind: 'warn' });
  }

  const zone = h('section', { class: 'drop', 'aria-label': 'Upload a project' },
    h('div', { class: 'drop__ring', 'aria-hidden': 'true' }),
    h('div', { class: 'drop__inner' },
      h('div', { class: 'drop__head' },
        h('div', { class: 'drop__icon' }, icon(UPLOAD, 22)),
        h('div', null,
          h('p', { class: 'drop__title' }, 'Drop a project .zip'),
          h('p', { class: 'drop__meta' }, 'package.json + package-lock.json (v2/v3) · ≤ 15 MB'))),
      h('div', { class: 'drop__actions' },
        h('button', { class: 'btn btn--primary', type: 'button', onclick: () => input.click() }, 'Choose .zip'),
        h('button', { class: 'btn btn--ghost', type: 'button', 'data-action': 'demo',
          onclick: () => toast('The demo project arrives with job intake.', { kind: 'warn' }) }, 'Try the demo project')),
      file, input));

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

export function landing() {
  const canvas = h('canvas', { class: 'hero__fx', 'aria-hidden': 'true' });
  const el = h('div', { class: 'landing' },
    h('section', { class: 'hero' },
      canvas,
      h('div', { class: 'container' },
        h('div', { class: 'hero__copy' },
          h('span', { class: 'eyebrow' }, 'npm · lockfile v2/v3 · OSV advisories'),
          h('h1', { class: 'hero__title' }, 'Know which dependency ', h('em', 'actually'), ' puts you at risk.'),
          h('p', { class: 'hero__lede' },
            'DepGuard traces the path from your project to each vulnerable package, proposes the smallest defensible fix, and proves it in an isolated container.'),
          dropZone(),
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
          h('p', { class: 'how__copy' }, 'Approve, then watch an isolated install, your tests and a fresh rescan — before anything ships.')))));

  const fx = constellation(canvas, { reduced: reducedMotion() });
  return { el, destroy: () => fx.destroy() };
}
