const TERMINAL = (e) => e.type === 'done' || e.type === 'error' || (e.type === 'status' && e.data?.status === 'expired');

export function follow(url, { onEvent, onLost }) {
  const seen = new Set();
  const source = new EventSource(url);
  let closed = false;

  const close = () => {
    closed = true;
    source.close();
  };

  source.onmessage = (msg) => {
    if (seen.has(msg.data)) return;
    seen.add(msg.data);
    let event;
    try {
      event = JSON.parse(msg.data);
    } catch {
      return;
    }
    onEvent(event);
    if (TERMINAL(event)) close();
  };

  source.onerror = () => {
    if (!closed && source.readyState === EventSource.CLOSED) {
      closed = true;
      onLost?.();
    }
  };

  return close;
}
