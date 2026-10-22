const pad = (n, w = 2) => String(n).padStart(w, '0');

export function clock(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export function duration(ms) {
  if (ms == null) return '';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60_000)} m ${Math.round((ms % 60_000) / 1000)} s`;
}

export function bytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

export const shortId = (id) => (id || '').slice(0, 8);

export function ordinal(n) {
  const s = n % 100 >= 10 && n % 100 <= 20 ? 'th' : ({ 1: 'st', 2: 'nd', 3: 'rd' }[n % 10] || 'th');
  return `${n}${s}`;
}

export const pct = (p) => Math.floor(p * 100);

export function stamp(iso) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return 'an unknown time';
  return `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

export function describePolicy(p) {
  const parts = [p.fail_on === 'none' ? 'never fails' : `fails on ${p.fail_on} or worse`];
  if (p.prod_only) parts.push('production scope only');
  if (p.require_fix) parts.push('only when a fix exists');
  return parts.join(', ');
}

export function policyChip(h, verdict) {
  if (!verdict) return null;
  const fail = verdict.status === 'fail';
  return h('span', { class: ['chip', fail ? 'chip--err' : 'chip--ok', 'policychip'], title: `${verdict.source}: ${describePolicy(verdict.policy)}` },
    `Policy ${verdict.status.toUpperCase()}${fail ? ` · ${verdict.count} violation${verdict.count === 1 ? '' : 's'}` : ''}`);
}
