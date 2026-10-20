import { s } from '../dom.js';

const R = 15.5;
const C = 2 * Math.PI * R;

export function gauge(score, band, size = 40) {
  const pct = Math.max(0, Math.min(100, score)) / 100;
  return s('svg', { class: 'gauge', dataset: { band }, width: size, height: size, viewBox: '0 0 36 36', role: 'img',
    'aria-label': `Priority ${score} of 100, ${band}` },
  s('circle', { class: 'gauge__track', cx: 18, cy: 18, r: R }),
  s('circle', { class: 'gauge__arc', cx: 18, cy: 18, r: R, 'stroke-dasharray': `${(C * pct).toFixed(2)} ${C.toFixed(2)}`,
    style: { '--len': (C * pct).toFixed(2) } }),
  s('text', { class: 'gauge__v', x: 18, y: 18, 'text-anchor': 'middle', 'dominant-baseline': 'central' }, String(score)));
}
