import { h } from './dom.js';

const MAX = 20000;
const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\[[^\]\n]+\]\((https?:\/\/[^)\s]+)\))/g;

export function inline(text) {
  const out = [];
  let last = 0;
  for (const m of text.matchAll(INLINE)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1]) out.push(h('code', m[1].slice(1, -1)));
    else if (m[2]) out.push(h('strong', m[2].slice(2, -2)));
    else if (m[3]) {
      const label = m[3].slice(1, m[3].indexOf(']('));
      out.push(h('a', { href: m[4], target: '_blank', rel: 'noopener noreferrer nofollow' }, label));
    }
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function md(source) {
  const lines = String(source || '').slice(0, MAX).replace(/\r\n?/g, '\n').split('\n');
  const root = h('div', { class: 'md' });
  let para = [], list = null, i = 0;

  const flush = () => {
    if (para.length) root.append(h('p', inline(para.join(' '))));
    para = [];
    list = null;
  };

  while (i < lines.length) {
    const line = lines[i];
    const fence = line.match(/^\s*```/);
    if (fence) {
      flush();
      const code = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
      root.append(h('pre', h('code', code.join('\n'))));
      i++;
      continue;
    }
    const head = line.match(/^(#{1,6})\s+(.*)$/);
    const item = line.match(/^\s*(?:[-*+]|(\d+)[.)])\s+(.*)$/);
    if (head) {
      flush();
      root.append(h(head[1].length <= 2 ? 'h4' : 'h5', inline(head[2])));
    } else if (item) {
      if (para.length) flush();
      const tag = item[1] ? 'ol' : 'ul';
      if (!list || list.tagName.toLowerCase() !== tag) {
        list = h(tag);
        root.append(list);
      }
      list.append(h('li', inline(item[2])));
    } else if (!line.trim()) {
      flush();
    } else {
      list = null;
      para.push(line.trim());
    }
    i++;
  }
  flush();
  return root;
}
