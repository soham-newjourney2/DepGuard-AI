import { cssVar } from '../dom.js';

const COUNT = 120;
const IGNITE_EVERY = 4000;
const STEP = 150;
const HOLD = 1300;
const FADE = 900;

function rng(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildTree(rand) {
  const nodes = [{ parent: -1, depth: 0, angle: 0, len: 0 }];
  for (let i = 1; i < COUNT; i++) {
    const pick = Math.floor(rand() ** 1.35 * nodes.length);
    const p = nodes[Math.min(pick, nodes.length - 1)].depth >= 5 ? 0 : pick;
    const parent = nodes[p];
    const angle = parent.depth === 0 ? rand() * Math.PI * 2 : parent.angle + (rand() - 0.5) * 1.2;
    nodes.push({ parent: p, depth: parent.depth + 1, angle, len: 0.055 + rand() * 0.05 });
  }
  for (const n of nodes) {
    n.phase = rand() * Math.PI * 2;
    n.speed = 0.00025 + rand() * 0.0003;
    n.amp = 3 + rand() * 6;
  }
  return nodes;
}

function pathToRoot(nodes, i) {
  const path = [];
  for (let k = i; k !== -1; k = nodes[k].parent) path.push(k);
  return path;
}

export function constellation(canvas, { reduced = false, seed = 7 } = {}) {
  const ctx = canvas.getContext('2d');
  const rand = rng(seed);
  const nodes = buildTree(rand);
  const deep = nodes.map((n, i) => i).filter((i) => nodes[i].depth >= 3);
  const colors = { hot: cssVar('--sev-critical') || '#FF3B5C', accent: cssVar('--accent') || '#C8FF4D',
    edge: cssVar('--edge') || 'rgba(255,255,255,0.1)', node: cssVar('--text-2') || '#6B7486' };
  let w = 0, hgt = 0, dpr = 1, raf = 0, visible = true;
  let burst = null;
  let lastIgnite = -Infinity;

  function layout() {
    const rect = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = rect.width;
    hgt = rect.height;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(hgt * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const scale = Math.max(w, hgt);
    const narrow = w < 760;
    nodes[0].bx = w * (narrow ? 0.62 : 0.7);
    nodes[0].by = hgt * (narrow ? 0.32 : 0.46);
    for (let i = 1; i < nodes.length; i++) {
      const n = nodes[i], p = nodes[n.parent];
      n.bx = p.bx + Math.cos(n.angle) * n.len * scale;
      n.by = p.by + Math.sin(n.angle) * n.len * scale;
    }
  }

  function ignite(t) {
    const target = deep[Math.floor(rand() * deep.length)];
    burst = { path: pathToRoot(nodes, target), t0: t };
    lastIgnite = t;
  }

  function draw(t) {
    ctx.clearRect(0, 0, w, hgt);
    for (const n of nodes) {
      n.x = n.bx + Math.sin(t * n.speed + n.phase) * n.amp;
      n.y = n.by + Math.cos(t * n.speed * 0.8 + n.phase) * n.amp;
    }

    ctx.beginPath();
    for (let i = 1; i < nodes.length; i++) {
      const n = nodes[i], p = nodes[n.parent];
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(n.x, n.y);
    }
    ctx.strokeStyle = colors.edge;
    ctx.lineWidth = 1;
    ctx.stroke();

    ctx.fillStyle = colors.node;
    ctx.beginPath();
    for (const n of nodes) {
      const r = n.depth === 0 ? 3.2 : Math.max(1.1, 2.4 - n.depth * 0.25);
      ctx.moveTo(n.x + r, n.y);
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    }
    ctx.fill();

    if (burst) drawBurst(t);
  }

  function drawBurst(t) {
    const { path, t0 } = burst;
    const elapsed = t - t0;
    const full = path.length * STEP;
    const fade = elapsed > full + HOLD ? 1 - (elapsed - full - HOLD) / FADE : 1;
    if (fade <= 0) { burst = null; return; }
    const lit = Math.min(path.length, Math.floor(elapsed / STEP) + 1);

    ctx.save();
    ctx.globalAlpha = fade;
    ctx.lineCap = 'round';
    ctx.shadowColor = colors.hot;
    ctx.shadowBlur = 12;
    ctx.strokeStyle = colors.hot;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    for (let k = 1; k < lit; k++) {
      const a = nodes[path[k - 1]], b = nodes[path[k]];
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
    }
    ctx.stroke();

    for (let k = 0; k < lit; k++) {
      const n = nodes[path[k]];
      const isTarget = k === 0;
      const isRoot = k === path.length - 1;
      const pulse = isTarget ? 1 + Math.sin(elapsed / 120) * 0.25 : 1;
      ctx.fillStyle = isRoot ? colors.accent : colors.hot;
      ctx.shadowColor = ctx.fillStyle;
      ctx.shadowBlur = isTarget ? 22 : 10;
      ctx.beginPath();
      ctx.arc(n.x, n.y, (isTarget ? 4.2 : isRoot ? 4 : 2.6) * pulse, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  }

  function frame(t) {
    raf = requestAnimationFrame(frame);
    if (!visible) return;
    if (t - lastIgnite > IGNITE_EVERY) ignite(t);
    draw(t);
  }

  function staticFrame() {
    const path = pathToRoot(nodes, deep[0]);
    burst = { path, t0: -path.length * STEP };
    draw(0);
    burst = null;
  }

  const ro = new ResizeObserver(() => { layout(); if (reduced) staticFrame(); });
  ro.observe(canvas);
  const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting && !document.hidden; });
  io.observe(canvas);
  const onVis = () => { visible = !document.hidden; };
  document.addEventListener('visibilitychange', onVis);

  layout();
  if (reduced) staticFrame();
  else raf = requestAnimationFrame(frame);

  return {
    destroy() {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      document.removeEventListener('visibilitychange', onVis);
    },
  };
}
