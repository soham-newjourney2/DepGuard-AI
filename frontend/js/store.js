const state = { health: null, job: null };
const subs = new Set();

export const get = () => state;

export function set(patch) {
  Object.assign(state, patch);
  for (const fn of subs) fn(state);
}

export function subscribe(fn) {
  subs.add(fn);
  return () => subs.delete(fn);
}
