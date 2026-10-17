import { h } from '../dom.js';

let region = null;

export function toast(message, { kind = 'info', timeout = 4200 } = {}) {
  region ??= document.body.appendChild(h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }));
  const el = h('div', { class: ['toast', `toast--${kind}`] }, h('span', { class: 'toast__dot' }), h('span', message));
  region.append(el);
  requestAnimationFrame(() => el.classList.add('is-in'));
  setTimeout(() => {
    el.classList.remove('is-in');
    setTimeout(() => el.remove(), 320);
  }, timeout);
  return el;
}
