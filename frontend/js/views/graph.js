import { api } from '../api.js';
import { drawer } from '../components/drawer.js';
import { h, icon, reducedMotion } from '../dom.js';
import { shortId } from '../format.js';
import { go } from '../router.js';
import * as store from '../store.js';
import { detail } from './findings.js';

const D3_SRC = '/vendor/d3.v7.9.0.min.js';
const SEARCH = ['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z', 'M20 20l-4-4'];
const FIT = ['M4 9V4h5', 'M20 9V4h-5', 'M4 15v5h5', 'M20 15v5h-5'];
const LEGEND = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['clean', 'No advisory'], ['root', 'Your project']];
let d3Loading = null;

function loadD3() {
  if (window.d3) return Promise.resolve(window.d3);
  d3Loading ??= new Promise((resolve, reject) => {
    const tag = h('script', { src: D3_SRC });
    tag.addEventListener('load', () => resolve(window.d3));
    tag.addEventListener('error', () => { d3Loading = null; reject(new Error('Graph library failed to load.')); });
    document.head.append(tag);
  });
  return d3Loading;
}

const radius = (n) => (n.root ? 10 : 4 + Math.min(8, Math.sqrt(n.dependents || 0) * 1.6));
const showLabel = (n) => n.root || n.target || n.direct;

export function graph({ id, query = {} }) {
  const state = { mode: 'focus', data: null, sim: null, sel: null };
  const meta = h('p', { class: 'fhead__meta' });
  const warn = h('div', { class: 'gwarn', hidden: true });
  const svgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svgEl.setAttribute('class', 'gsvg');
  svgEl.setAttribute('role', 'img');
  svgEl.setAttribute('aria-label', 'Dependency graph');
  const tip = h('div', { class: 'gtip', hidden: true, role: 'tooltip' });
  const stage = h('div', { class: 'gstage panel' }, svgEl, tip, h('div', { class: 'gstatus', role: 'status' }, 'Loading graph…'));
  const search = h('input', { class: 'search__input', type: 'search', placeholder: 'Find a package…', 'aria-label': 'Find a package in the graph', autocomplete: 'off' });
  const modeBtns = ['focus', 'full'].map((m) => h('button', { class: 'seg__btn', type: 'button', 'aria-pressed': String(m === 'focus'), dataset: { mode: m } },
    m === 'focus' ? 'Vulnerable paths' : 'Full graph'));
  const fitBtn = h('button', { class: 'btn btn--ghost btn--sm', type: 'button', 'aria-label': 'Fit graph to view' }, icon(FIT, 16), 'Fit');
  const dr = drawer({ label: 'Finding detail', onClose: () => {} });
  const el = h('div', { class: 'graphview' },
    h('div', { class: 'container fwrap' },
      h('header', { class: 'fhead' }, h('span', { class: 'eyebrow' }, `Job ${shortId(id)}`), h('h1', { class: 'fhead__title' }, 'Dependency graph'), meta),
      h('div', { class: 'gcontrols' },
        h('div', { class: 'seg', role: 'group', 'aria-label': 'Graph mode' }, modeBtns),
        h('label', { class: 'search gsearch' }, icon(SEARCH, 16), search, h('kbd', null, '/')),
        fitBtn,
        h('ul', { class: 'legend', 'aria-label': 'Legend' }, LEGEND.map(([k, t]) => h('li', { dataset: { sev: k } }, h('span', { class: 'legend__dot' }), t)),
          h('li', { class: 'legend__dev' }, h('span', { class: 'legend__dot' }), 'dev only'))),
      warn, stage),
    dr.scrim, dr.el);

  let d3, zoom, gRoot, nodeSel, linkSel, labelSel, parents, fitNow;

  function ancestors(start) {
    const seen = new Set([start]);
    const q = [start];
    while (q.length) for (const p of parents.get(q.shift()) || []) if (!seen.has(p)) { seen.add(p); q.push(p); }
    return seen;
  }

  function highlight(nodeId) {
    state.sel = nodeId;
    if (!nodeId) {
      nodeSel?.classed('is-dim', false).classed('is-sel', false).classed('is-path', false);
      labelSel?.classed('is-dim', false).classed('is-path', false);
      linkSel?.classed('is-dim', false).classed('is-hot', false);
      svgEl.removeAttribute('data-focus');
      return;
    }
    const keep = ancestors(nodeId);
    nodeSel.classed('is-dim', (d) => !keep.has(d.id)).classed('is-sel', (d) => d.id === nodeId).classed('is-path', (d) => keep.has(d.id));
    labelSel.classed('is-dim', (d) => !keep.has(d.id)).classed('is-path', (d) => keep.has(d.id));
    linkSel.classed('is-hot', (l) => keep.has(l.source.id) && keep.has(l.target.id))
      .classed('is-dim', (l) => !(keep.has(l.source.id) && keep.has(l.target.id)));
    svgEl.dataset.focus = nodeId;
  }

  async function openFinding(n) {
    if (!n.findings.length) return;
    dr.show(h('div', { class: 'skeleton skeleton--detail' }));
    try {
      dr.show(detail(await api(`/jobs/${id}/findings/${n.findings[0]}`), { jobId: id }));
    } catch (err) {
      dr.show(h('p', { class: 'note note--warn' }, `${err.code || 'Error'} · ${err.message}`));
    }
  }

  function showTip(event, n) {
    const rect = stage.getBoundingClientRect();
    tip.replaceChildren(
      h('strong', null, n.label),
      h('span', null, `${n.root ? 'project root' : n.scope} · ${n.direct ? 'direct' : `depth ${n.depth ?? '?'}`} · ${n.dependents} dependent${n.dependents === 1 ? '' : 's'}`),
      n.findings.length ? h('span', { class: 'gtip__sev', dataset: { sev: n.severity } }, `${n.findings.length} advisor${n.findings.length === 1 ? 'y' : 'ies'} · worst ${n.severity}`) : h('span', null, 'No known advisories'));
    tip.hidden = false;
    const x = Math.min(event.clientX - rect.left + 14, rect.width - tip.offsetWidth - 8);
    const y = Math.min(event.clientY - rect.top + 14, rect.height - tip.offsetHeight - 8);
    tip.style.transform = `translate(${Math.max(8, x)}px, ${Math.max(8, y)}px)`;
  }

  function render(data) {
    state.sim?.stop();
    d3.select(svgEl).selectAll('*').remove();
    const { width, height } = svgEl.getBoundingClientRect();
    const nodes = data.nodes.map((n) => ({ ...n }));
    const links = data.edges.map((e) => ({ ...e }));
    parents = new Map();
    for (const e of data.edges) {
      if (!parents.has(e.target)) parents.set(e.target, []);
      parents.get(e.target).push(e.source);
    }
    const root = nodes.find((n) => n.root);
    if (root) { root.fx = width / 2; root.fy = 60; }
    const svg = d3.select(svgEl);
    gRoot = svg.append('g');
    zoom = d3.zoom().scaleExtent([0.15, 4]).on('zoom', (e) => gRoot.attr('transform', e.transform));
    svg.call(zoom).on('dblclick.zoom', null);
    svg.on('click', (e) => { if (e.target === svgEl) highlight(null); });

    linkSel = gRoot.append('g').attr('class', 'glinks').selectAll('line').data(links).join('line')
      .attr('class', (l) => `glink glink--${l.kind}`);
    nodeSel = gRoot.append('g').attr('class', 'gnodes').selectAll('g').data(nodes, (d) => d.id).join('g')
      .attr('class', 'gnode')
      .attr('data-id', (d) => d.id)
      .attr('data-label', (d) => d.label)
      .attr('data-sev', (d) => (d.root ? 'root' : d.severity || 'clean'))
      .attr('data-scope', (d) => d.scope)
      .attr('tabindex', 0)
      .attr('role', 'button')
      .attr('aria-label', (d) => `${d.label}${d.findings.length ? `, ${d.findings.length} advisories, worst ${d.severity}` : ''}`);
    nodeSel.append('circle').attr('r', radius);
    labelSel = gRoot.append('g').attr('class', 'glabels').selectAll('text').data(nodes.filter(showLabel)).join('text')
      .attr('class', 'glabel').attr('dy', '0.32em').attr('data-sev', (d) => (d.root ? 'root' : d.severity || 'clean'))
      .text((d) => (d.root ? 'your project' : d.label));
    nodeSel
      .on('click', (e, d) => { e.stopPropagation(); highlight(d.id); openFinding(d); })
      .on('keydown', (e, d) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); highlight(d.id); openFinding(d); } })
      .on('mouseenter', (e, d) => showTip(e, d))
      .on('mousemove', (e, d) => showTip(e, d))
      .on('mouseleave', () => { tip.hidden = true; });

    const tick = () => {
      linkSel.attr('x1', (l) => l.source.x).attr('y1', (l) => l.source.y).attr('x2', (l) => l.target.x).attr('y2', (l) => l.target.y);
      nodeSel.attr('transform', (d) => `translate(${d.x},${d.y})`);
      labelSel.attr('x', (d) => d.x + radius(d) + 5).attr('y', (d) => d.y);
    };
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(46).strength(0.6))
      .force('charge', d3.forceManyBody().strength(nodes.length > 400 ? -60 : -170))
      .force('x', d3.forceX(width / 2).strength(0.04))
      .force('y', d3.forceY((d) => 60 + (d.depth ?? 4) * 95).strength(0.35))
      .force('collide', d3.forceCollide().radius((d) => radius(d) + 6));
    state.sim = sim;

    fitNow = (animate = true) => {
      const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
      const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
      const pad = 60;
      const k = Math.min(2, (width - pad * 2) / Math.max(1, x1 - x0), (height - pad * 2) / Math.max(1, y1 - y0));
      const t = d3.zoomIdentity.translate(width / 2 - k * (x0 + x1) / 2, height / 2 - k * (y0 + y1) / 2).scale(k);
      const target = animate && !reducedMotion() ? svg.transition().duration(500) : svg;
      target.call(zoom.transform, t);
    };

    const settle = () => {
      svgEl.dataset.settled = 'true';
      fitNow(!reducedMotion());
    };
    svgEl.dataset.settled = 'false';
    if (reducedMotion() || nodes.length > 600) {
      sim.stop();
      for (let i = 0; i < 300; i++) sim.tick();
      tick();
      settle();
    } else {
      sim.on('tick', tick).on('end', settle);
      setTimeout(() => { if (svgEl.dataset.settled !== 'true') { sim.stop(); settle(); } }, 4000);
    }
    stage.querySelector('.gstatus').hidden = true;
    const focusNode = query.focus && nodes.find((n) => n.findings.includes(query.focus));
    if (focusNode) highlight(focusNode.id);
  }

  async function load() {
    stage.querySelector('.gstatus').hidden = false;
    try {
      const [lib, data] = await Promise.all([loadD3(), api(`/jobs/${id}/graph?mode=${state.mode}`)]);
      d3 = lib;
      state.data = data;
      meta.textContent = `${data.nodes.length} of ${data.total_nodes} packages · ${data.edges.length} edges · ${state.mode === 'focus' ? 'paths to vulnerable packages' : 'full dependency graph'}`;
      warn.hidden = !data.warnings.length;
      warn.textContent = data.warnings.join(' ');
      render(data);
    } catch (err) {
      stage.querySelector('.gstatus').textContent = `${err.code || 'Error'} · ${err.message}`;
    }
  }

  function find(q) {
    const term = q.trim().toLowerCase();
    if (!term || !state.data) return;
    const nodes = nodeSel.data();
    const hit = nodes.find((n) => n.name.toLowerCase() === term) || nodes.find((n) => n.label.toLowerCase().includes(term));
    if (!hit) {
      search.setCustomValidity('No package with that name in this view');
      search.reportValidity();
      return;
    }
    search.setCustomValidity('');
    highlight(hit.id);
    const { width, height } = svgEl.getBoundingClientRect();
    const t = d3.zoomIdentity.translate(width / 2 - hit.x * 1.4, height / 2 - hit.y * 1.4).scale(1.4);
    (reducedMotion() ? d3.select(svgEl) : d3.select(svgEl).transition().duration(500)).call(zoom.transform, t);
  }

  modeBtns.forEach((b) => b.addEventListener('click', () => {
    if (state.mode === b.dataset.mode) return;
    state.mode = b.dataset.mode;
    modeBtns.forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    load();
  }));
  fitBtn.addEventListener('click', () => fitNow?.());
  search.addEventListener('keydown', (e) => { if (e.key === 'Enter') find(search.value); });
  search.addEventListener('input', () => search.setCustomValidity(''));

  function onKey(e) {
    const typing = e.target instanceof HTMLInputElement;
    if (e.key === 'Escape') {
      if (dr.isOpen()) dr.hide();
      else if (typing) e.target.blur();
      else highlight(null);
      return;
    }
    if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === '/') { e.preventDefault(); search.focus(); }
    if (e.key === 'f') go(`/jobs/${id}/findings`);
  }
  document.addEventListener('keydown', onKey);

  api(`/jobs/${id}`).then((job) => {
    store.set({ job });
    el.querySelector('.eyebrow').textContent = `Job ${shortId(id)} · ${job.filename || 'project'}`;
  }).catch(() => {});
  requestAnimationFrame(load);

  return {
    el,
    destroy() {
      state.sim?.stop();
      document.removeEventListener('keydown', onKey);
    },
  };
}
