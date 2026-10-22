import { api } from '../api.js';
import { h, reducedMotion } from '../dom.js';
import { inline } from '../md.js';

const BADGES = {
  evidence: ['template', 'Evidence-based (no AI)'],
  partial: ['partial', 'Evidence-based · values removed'],
};
const EXT = { target: '_blank', rel: 'noopener noreferrer nofollow' };

function weaknessCard(w) {
  if (!w) return null;
  return h('div', { class: 'xp__weak' },
    h('p', { class: 'xp__weakhead' }, h('span', { class: 'chip' }, w.id),
      h('span', { class: 'xp__weakname' }, w.short || w.name || 'Weakness type'),
      h('a', { class: 'xp__ext', href: w.source, ...EXT }, 'MITRE ↗')),
    h('p', null, w.plain),
    w.impact ? h('p', { class: 'xp__weakrow' }, h('b', null, 'Impact '), w.impact) : null,
    w.matters_when ? h('p', { class: 'xp__weakrow' }, h('b', null, 'Matters when '), w.matters_when) : null,
    w.mitigation ? h('p', { class: 'xp__weakrow' }, h('b', null, 'Mitigation '), w.mitigation) : null);
}

function quoteCard(q) {
  if (!q) return null;
  return h('figure', { class: 'xp__quote' },
    h('blockquote', null, q.text),
    h('figcaption', null, 'Verbatim from the advisory · ', h('a', { class: 'xp__ext', href: q.source, ...EXT }, 'osv.dev ↗')));
}
const CITE = /(\[E\d{1,2}\])/;

function flash(eid) {
  const el = document.getElementById(`ev-${eid}`);
  if (!el) return;
  el.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
  el.classList.remove('is-flash');
  void el.offsetWidth;
  el.classList.add('is-flash');
  setTimeout(() => el.classList.remove('is-flash'), 1600);
}

const cite = (eid) => h('button', { class: 'cite', type: 'button', 'aria-label': `Show evidence ${eid}`, onclick: () => flash(eid) }, eid);

function rich(text) {
  return text.split(CITE).filter(Boolean).map((part) => (CITE.test(part) ? cite(part.slice(1, -1)) : inline(part)));
}

function block(i, label, ...children) {
  return h('div', { class: 'xp__block', style: { '--i': String(i) } }, label ? h('h4', { class: 'xp__label' }, label) : null, ...children);
}

function render(x) {
  const [kind, text] = BADGES[x.grounding] || BADGES.evidence;
  const items = (list) => h('ul', { class: 'xp__list' }, list.map((t) => h('li', null, rich(t))));
  let i = 0;
  return [
    h('div', { class: 'xp__meta' },
      h('span', { class: 'aibadge', dataset: { kind } }, text),
      x.model ? h('span', { class: 'xp__model' }, x.model) : null,
      x.cached ? h('span', { class: 'xp__model' }, 'cached') : null),
    block(i++, null, h('p', { class: 'xp__summary' }, rich(x.summary))),
    block(i++, 'Why it matters', h('p', null, rich(x.why_it_matters))),
    block(i++, 'Recommended action', h('p', null, rich(x.recommended_action))),
    x.quote ? block(i++, 'From the advisory', quoteCard(x.quote)) : null,
    x.weakness ? block(i++, 'Weakness', weaknessCard(x.weakness)) : null,
    x.tradeoffs.length ? block(i++, 'Trade-offs', items(x.tradeoffs)) : null,
    x.uncertainties.length ? block(i++, 'Uncertainties', items(x.uncertainties)) : null,
    x.citations.length ? block(i++, 'Cites', h('div', { class: 'xp__cites' }, x.citations.map(cite))) : null,
    x.grounding === 'partial' ? h('p', { class: 'xp__note' },
      `Removed statements citing values not in the evidence: ${x.stripped.join(', ')}.`) : null,
    x.note ? h('p', { class: 'xp__note' }, x.note) : null,
  ];
}

export function explainPanel(jobId, findingId) {
  const body = h('div', { class: 'xp__body', 'aria-live': 'polite' });
  const el = h('section', { class: 'dsec xp' }, h('h3', { class: 'dsec__title' }, 'Explanation'), body);

  async function load() {
    body.replaceChildren(h('div', { class: 'xp__skel' }, h('span'), h('span'), h('span')));
    try {
      const x = await api(`/jobs/${jobId}/findings/${findingId}/explain`, { method: 'POST' });
      body.replaceChildren(...render(x).filter(Boolean));
    } catch (err) {
      body.replaceChildren(h('p', { class: 'xp__note' }, `${err.code || 'Error'} · ${err.message}`),
        h('button', { class: 'btn btn--ghost btn--sm', type: 'button', onclick: load }, 'Try again'));
    }
  }

  load();
  return el;
}
