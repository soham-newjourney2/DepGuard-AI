const ms = require('ms');

function humanize(milliseconds) {
  return ms(milliseconds, { long: true });
}

module.exports = { humanize };
