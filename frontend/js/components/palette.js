import { h } from '../dom.js';

const SHORTCUTS = [
  ['Ctrl / ⌘ K', 'Command palette'],
  ['?', 'This shortcut sheet'],
  ['/', 'Search findings or the graph'],
  ['j / k', 'Next / previous finding'],
  ['Enter', 'Open the selected finding'],
  ['g', 'Graph (from findings)'],
  ['f', 'Findings (from the graph)'],
  ['Esc', 'Close drawer, dialog or palette'],
];

let open = null;

function overlay(label, content, onKey) {
  open?.close();
  const previous = document.activeElement;
  const panel = h('div', { class: 'palette', role: 'dialog', 'aria-modal': 'true', 'aria-label': label, tabindex: '-1' }, content);
  const root = h('div', { class: 'palette-root' }, h('div', { class: 'palette__scrim' }), panel);
  const close = () => {
    document.removeEventListener('keydown', handler, true);
    root.remove();
    open = null;
    previous?.focus?.();
  };
  const handler = (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (onKey) {
      onKey(e);
    } else if (e.key !== 'Tab') {
      e.stopPropagation();
    }
  };
  root.querySelector('.palette__scrim').addEventListener('click', close);
  document.addEventListener('keydown', handler, true);
  document.body.append(root);
  open = { close };
  return { root, close };
}

export function shortcutSheet() {
  overlay('Keyboard shortcuts', [
    h('h2', { class: 'palette__title' }, 'Keyboard shortcuts'),
    h('dl', { class: 'shortcuts' }, SHORTCUTS.map(([k, v]) => [h('dt', null, h('kbd', null, k)), h('dd', null, v)])),
  ]).root.querySelector('.palette').focus();
}

export function commandPalette(getCommands) {
  const input = h('input', { class: 'palette__input', type: 'text', placeholder: 'Type a command…', role: 'combobox',
    'aria-expanded': 'true', 'aria-controls': 'palette-list', 'aria-autocomplete': 'list', autocomplete: 'off', spellcheck: 'false' });
  const list = h('ul', { class: 'palette__list', id: 'palette-list', role: 'listbox', 'aria-label': 'Commands' });
  let items = [], sel = 0;

  function render() {
    const q = input.value.trim().toLowerCase();
    items = getCommands().filter((c) => !q || `${c.group} ${c.label} ${c.keywords || ''}`.toLowerCase().includes(q));
    sel = Math.min(sel, Math.max(0, items.length - 1));
    list.replaceChildren(...(items.length ? items.map((c, i) => h('li', {
      class: ['palette__item', i === sel && 'is-sel'], role: 'option', id: `pal-${i}`, 'aria-selected': String(i === sel),
      onclick: () => run(i), onmousemove: () => { if (sel !== i) { sel = i; render(); } },
    }, h('span', { class: 'palette__group' }, c.group), h('span', { class: 'palette__label' }, c.label),
    c.hint ? h('kbd', null, c.hint) : null)) : [h('li', { class: 'palette__empty' }, 'No matching command')]));
    input.setAttribute('aria-activedescendant', items.length ? `pal-${sel}` : '');
    list.querySelector('.is-sel')?.scrollIntoView({ block: 'nearest' });
  }

  function run(i) {
    const cmd = items[i];
    if (!cmd) return;
    ui.close();
    cmd.run();
  }

  const ui = overlay('Command palette', [input, list], (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = (sel + 1) % Math.max(1, items.length); render(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = (sel - 1 + items.length) % Math.max(1, items.length); render(); }
    else if (e.key === 'Enter') { e.preventDefault(); run(sel); }
  });
  input.addEventListener('input', () => { sel = 0; render(); });
  render();
  input.focus();
}

export const isOpen = () => open !== null;
