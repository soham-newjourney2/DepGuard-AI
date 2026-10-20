const _ = require('lodash');
const jwt = require('jsonwebtoken');
const Handlebars = require('handlebars');
const { parseStringPromise } = require('xml2js');
const axios = require('axios');

const SECRET = 'demo-only-secret';

function mergeSettings(defaults, overrides) {
  return _.merge({}, defaults, overrides);
}

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
}

function renderGreeting(name) {
  return Handlebars.compile('Hello {{name}}!')({ name });
}

async function readFeed(xml) {
  const doc = await parseStringPromise(xml);
  return doc.feed.item.length;
}

async function ping(url) {
  const res = await axios.get(url, { timeout: 2000 });
  return res.status;
}

module.exports = { mergeSettings, issueToken, renderGreeting, readFeed, ping, SECRET };
