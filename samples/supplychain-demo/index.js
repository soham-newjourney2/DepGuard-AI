const ms = require('ms');
const express = require('expresss');
const leftPad = require('left-pad');
const config = require('./config/db');

module.exports = { timeout: ms('2s'), express, leftPad, config };
