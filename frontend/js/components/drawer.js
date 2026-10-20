import { h, icon } from '../dom.js';

const CLOSE = ['M6 6l12 12', 'M18 6L6 18'];

export function drawer({ label = 'Details', onClose } = {}) {
  const body = h('div', { class: 'drawer__body' });
  const closeBtn = h('button', { class: 'drawer__close', type: 'button', 'aria-label': 'Close details' }, icon(CLOSE, 18));
  const el = h('aside', { class: 'drawer', role: 'dialog', 'aria-label': label, tabindex: '-1', hidden: true }, closeBtn, body);
  const scrim = h('div', { class: 'drawer__scrim', hidden: true, 'aria-hidden': 'true' });
  let open = false, timer = 0;

  function show(content) {
    clearTimeout(timer);
    body.replaceChildren(content);
    body.scrollTop = 0;
    el.hidden = scrim.hidden = false;
    requestAnimationFrame(() => {
      el.classList.add('is-open');
      scrim.classList.add('is-open');
    });
    if (!open) el.focus({ preventScroll: true });
    open = true;
  }

  function hide() {
    if (!open) return;
    open = false;
    el.classList.remove('is-open');
    scrim.classList.remove('is-open');
    timer = setTimeout(() => { el.hidden = scrim.hidden = true; }, 280);
    onClose?.();
  }

  closeBtn.addEventListener('click', hide);
  scrim.addEventListener('click', hide);
  return { el, scrim, show, hide, isOpen: () => open };
}
