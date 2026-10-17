import { h } from '../dom.js';

export function pill(key, value = '', state = 'loading', title = '') {
  const v = h('span', { class: 'pill__v' }, value);
  const el = h('span', { class: 'pill', dataset: { state }, title: title || null },
    h('span', { class: 'pill__dot', 'aria-hidden': 'true' }),
    state === 'loading' ? null : [h('span', { class: 'pill__k' }, key), v]);
  if (state === 'loading') el.setAttribute('aria-label', `${key} loading`);
  return el;
}
