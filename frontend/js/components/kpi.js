import { h, reducedMotion } from '../dom.js';

export function countUp(el, to, ms = 700) {
  if (reducedMotion() || !Number.isFinite(to)) {
    el.textContent = String(to);
    return;
  }
  const t0 = performance.now();
  const tick = (t) => {
    const p = Math.min(1, (t - t0) / ms);
    el.textContent = String(Math.round(to * (1 - (1 - p) ** 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

export function kpi(label, value, hint = '') {
  const v = h('span', { class: 'kpi__v' }, '0');
  countUp(v, value);
  return h('div', { class: 'kpi', title: hint || null }, v, h('span', { class: 'kpi__k' }, label));
}
