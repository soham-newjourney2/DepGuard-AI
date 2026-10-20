const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const app = require('..');

function get(server, path) {
  const { port } = server.address();
  return new Promise((resolve, reject) => {
    http.get({ port, path }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
    }).on('error', reject);
  });
}

test('search parses nested query strings', async () => {
  const server = app.listen(0);
  try {
    const res = await get(server, '/search?q=lodash&tags[]=a&tags[]=b');
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.json, { q: 'lodash', tags: ['a', 'b'] });
  } finally {
    server.close();
  }
});
