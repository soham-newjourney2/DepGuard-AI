import { ansiLine } from '../ansi.js';
import { h } from '../dom.js';
import { duration } from '../format.js';

const MAX_LINES = 4000;

export function terminal() {
  const body = h('div', { class: 'term__body', role: 'log', 'aria-live': 'polite', tabindex: '0' });
  const timer = h('span', { class: 'term__timer' }, '0 ms');
  const chips = h('span', { class: 'term__chips' });
  const jump = h('button', { class: 'term__jump', type: 'button', hidden: true }, 'Jump to latest ↓');
  const el = h('section', { class: 'term', 'aria-label': 'Verification log' },
    h('header', { class: 'term__head' },
      h('span', { class: 'term__dots', 'aria-hidden': 'true' }, h('i'), h('i'), h('i')),
      h('span', { class: 'term__title' }, 'verification'), chips, timer),
    body, jump);
  let follow = true, started = 0, tick = 0;
  const state = { fg: null, bold: false, dim: false };

  body.addEventListener('scroll', () => {
    follow = body.scrollHeight - body.scrollTop - body.clientHeight < 24;
    jump.hidden = follow;
  });
  jump.addEventListener('click', () => {
    follow = true;
    jump.hidden = true;
    body.scrollTop = body.scrollHeight;
  });

  function line(text, kind = '') {
    body.append(h('div', { class: ['term__line', kind && `term__line--${kind}`] }, ansiLine(text, state)));
    while (body.childElementCount > MAX_LINES) body.firstElementChild.remove();
    if (follow) body.scrollTop = body.scrollHeight;
  }

  return {
    el,
    line,
    marker(text) { line(text, 'marker'); },
    chip(stage, status, exitCode) {
      chips.querySelector(`[data-stage="${stage}"]`)?.remove();
      chips.append(h('span', { class: 'xchip', dataset: { stage, status } }, `${stage} · exit ${exitCode ?? '—'}`));
    },
    start(iso) {
      started = iso ? new Date(iso).getTime() : Date.now();
      clearInterval(tick);
      tick = setInterval(() => { timer.textContent = duration(Date.now() - started); }, 250);
    },
    stop(iso) {
      clearInterval(tick);
      if (started && iso) timer.textContent = duration(new Date(iso).getTime() - started);
    },
  };
}
