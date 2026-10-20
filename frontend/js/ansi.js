import { h } from './dom.js';

const ESC = /\x1b\[([0-9;]*)([A-Za-z])/g;
const COLORS = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'];

function apply(state, codes) {
  for (const raw of codes.length ? codes : ['0']) {
    const n = Number(raw || 0);
    if (n === 0) Object.assign(state, { fg: null, bold: false, dim: false });
    else if (n === 1) state.bold = true;
    else if (n === 2) state.dim = true;
    else if (n === 22) state.bold = state.dim = false;
    else if (n === 39) state.fg = null;
    else if (n >= 30 && n <= 37) state.fg = COLORS[n - 30];
    else if (n >= 90 && n <= 97) state.fg = `bright-${COLORS[n - 90]}`;
  }
}

export function ansiLine(text, state = { fg: null, bold: false, dim: false }) {
  const parts = [];
  let last = 0;
  const push = (chunk) => {
    if (!chunk) return;
    const cls = [state.fg && `ansi-${state.fg}`, state.bold && 'ansi-bold', state.dim && 'ansi-dim'].filter(Boolean);
    parts.push(cls.length ? h('span', { class: cls }, chunk) : chunk);
  };
  for (const m of text.matchAll(ESC)) {
    push(text.slice(last, m.index));
    if (m[2] === 'm') apply(state, m[1].split(';').filter((x) => x !== ''));
    last = m.index + m[0].length;
  }
  push(text.slice(last).replace(/\x1b\[?[0-9;]*[A-Za-z]?/g, ''));
  return parts;
}
