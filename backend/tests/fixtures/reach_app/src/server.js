const express = require('express');
const { parse } = require("qs/lib/parse");
import lodash from 'lodash';
import('@scope/pkg/deep').then(() => {});
const fs = require('node:fs');
const local = require('./local');
