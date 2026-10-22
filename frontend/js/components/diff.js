import { h } from '../dom.js';

const HUNK = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$/;

function parseDiff(text) {
  const rows = [];
  let a = 0, b = 0;
  for (const line of text.replace(/\n$/, '').split('\n')) {
    if (line.startsWith('--- ') || line.startsWith('+++ ')) {
      rows.push({ type: 'file', text: line });
      continue;
    }
    const m = HUNK.exec(line);
    if (m) {
      a = Number(m[1]);
      b = Number(m[2]);
      rows.push({ type: 'hunk', text: line });
    } else if (line.startsWith('-')) rows.push({ type: 'del', a: a++, text: line.slice(1) });
    else if (line.startsWith('+')) rows.push({ type: 'add', b: b++, text: line.slice(1) });
    else rows.push({ type: 'ctx', a: a++, b: b++, text: line.slice(1) });
  }
  return rows;
}

function split(text, other) {
  let start = 0;
  while (start < text.length && start < other.length && text[start] === other[start]) start++;
  let end = 0;
  while (end < text.length - start && end < other.length - start
    && text[text.length - 1 - end] === other[other.length - 1 - end]) end++;
  return [text.slice(0, start), text.slice(start, text.length - end), text.slice(text.length - end)];
}

function code(text, other) {
  if (other == null) return h('code', null, text);
  const [pre, mid, post] = split(text, other);
  return h('code', null, pre, mid ? h('mark', null, mid) : null, post);
}

export function diffView(text) {
  const rows = parseDiff(text);
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].type !== 'del') continue;
    let j = i;
    while (rows[j]?.type === 'del') j++;
    let k = j;
    while (rows[k]?.type === 'add') k++;
    const dels = j - i, adds = k - j;
    if (dels === adds) for (let n = 0; n < dels; n++) {
      rows[i + n].pair = rows[j + n].text;
      rows[j + n].pair = rows[i + n].text;
    }
    i = k - 1;
  }
  const added = rows.filter((r) => r.type === 'add').length;
  const removed = rows.filter((r) => r.type === 'del').length;
  const file = rows.find((r) => r.type === 'file' && r.text.startsWith('+++'))?.text.slice(6) || 'package.json';
  const sign = (t) => (t === 'add' ? '+' : t === 'del' ? '−' : ' ');
  const tr = (r) => (r.type === 'hunk'
    ? h('tr', { class: 'diff__hunk' }, h('td', { colspan: 3 }, r.text))
    : h('tr', { class: `diff__row diff__row--${r.type}` },
      h('td', { class: 'diff__ln' }, r.a ?? ''),
      h('td', { class: 'diff__ln' }, r.b ?? ''),
      h('td', { class: 'diff__code' },
        h('span', { class: 'diff__sign', 'aria-hidden': 'true' }, sign(r.type)), code(r.text, r.pair))));
  return h('figure', { class: 'diff', 'aria-label': `Diff of ${file}` },
    h('figcaption', { class: 'diff__head' }, h('span', { class: 'diff__file' }, file),
      h('span', { class: 'diff__stat' }, h('span', { class: 'diff__add' }, `+${added}`), ' ',
        h('span', { class: 'diff__del' }, `−${removed}`))),
    h('div', { class: 'diff__scroll' },
      h('table', { class: 'diff__table' }, h('tbody', null, rows.filter((r) => r.type !== 'file').map(tr)))));
}
