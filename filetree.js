'use strict';
const scanner = require('./scanner');
const fs = require('original-fs');
var Chart = require('chart.js');
const { remote } = require('electron'),
  dialog = remote.dialog,
  app = remote.app,
  WIN = remote.getCurrentWindow();
var Timer = require('easytimer.js').Timer;

