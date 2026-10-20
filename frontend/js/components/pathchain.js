import { h } from '../dom.js';

export function pathchain(path, { compact = false } = {}) {
  const items = compact && path.length > 4 ? [path[0], '…', ...path.slice(-2)] : path;
  return h('ol', { class: ['pathchain', compact && 'pathchain--compact'], 'aria-label': path.join(' → ') },
    items.map((node, i) => h('li', {
      class: ['pathchain__node', i === items.length - 1 && 'is-vuln', node === '…' && 'is-gap', i === 0 && 'is-root'],
      style: { '--i': String(i) },
      'aria-hidden': 'true',
    }, i ? h('span', { class: 'pathchain__link' }) : null, h('span', { class: 'pathchain__chip' }, node))));
}
