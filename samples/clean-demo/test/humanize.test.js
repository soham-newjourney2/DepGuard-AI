const test = require('node:test');
const assert = require('node:assert');
const { humanize } = require('..');

test('humanize formats durations', () => {
  assert.strictEqual(humanize(60000), '1 minute');
  assert.strictEqual(humanize(2 * 3600 * 1000), '2 hours');
});
