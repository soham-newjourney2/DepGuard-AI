const KEY = 'depguard-theme';

export function current() {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
}

export function apply(theme) {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#F6F7F9' : '#06080D');
}

export function toggle() {
  const next = current() === 'light' ? 'dark' : 'light';
  apply(next);
  try { localStorage.setItem(KEY, next); } catch { /* storage unavailable */ }
  return next;
}

export function restore() {
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch { /* storage unavailable */ }
  apply(saved === 'light' ? 'light' : 'dark');
}
