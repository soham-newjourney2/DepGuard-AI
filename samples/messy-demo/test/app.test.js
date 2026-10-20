const test = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');
const { mergeSettings, issueToken, renderGreeting, readFeed, SECRET } = require('../src');

test('mergeSettings deep-merges overrides', () => {
  assert.deepStrictEqual(mergeSettings({ a: { b: 1, c: 2 } }, { a: { c: 3 } }), { a: { b: 1, c: 3 } });
});

test('issueToken signs a verifiable token', () => {
  const claims = jwt.verify(issueToken({ id: 7, role: 'admin' }), SECRET);
  assert.strictEqual(claims.sub, 7);
});

test('renderGreeting escapes input', () => {
  assert.strictEqual(renderGreeting('<b>x</b>'), 'Hello &lt;b&gt;x&lt;/b&gt;!');
});

test('readFeed counts items', async () => {
  assert.strictEqual(await readFeed('<feed><item>a</item><item>b</item></feed>'), 2);
});
