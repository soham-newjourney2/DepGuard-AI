import { h } from '../dom.js';

const FOCUSABLE = 'button:not([disabled]), a[href], input:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function confirmModal({ title, body, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
  return new Promise((resolve) => {
    const previous = document.activeElement;
    const confirm = h('button', { class: ['btn', danger ? 'btn--danger' : 'btn--primary'], type: 'button' }, confirmLabel);
    const cancel = h('button', { class: 'btn btn--ghost', type: 'button' }, cancelLabel);
    const titleId = `modal-${Math.random().toString(36).slice(2)}`;
    const dialog = h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
      h('h2', { class: 'modal__title', id: titleId }, title),
      h('div', { class: 'modal__body' }, body),
      h('div', { class: 'modal__actions' }, cancel, confirm));
    const root = h('div', { class: 'modal-root' }, h('div', { class: 'modal__scrim' }), dialog);

    function close(result) {
      document.removeEventListener('keydown', onKey, true);
      root.classList.remove('is-open');
      setTimeout(() => root.remove(), 200);
      previous?.focus?.();
      resolve(result);
    }

    function onKey(e) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        close(false);
      } else if (e.key === 'Tab') {
        const items = [...dialog.querySelectorAll(FOCUSABLE)];
        const first = items[0], last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    }

    confirm.addEventListener('click', () => close(true));
    cancel.addEventListener('click', () => close(false));
    root.querySelector('.modal__scrim').addEventListener('click', () => close(false));
    document.addEventListener('keydown', onKey, true);
    document.body.append(root);
    requestAnimationFrame(() => root.classList.add('is-open'));
    cancel.focus();
  });
}
