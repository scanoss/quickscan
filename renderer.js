// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2020 SCANOSS TECNOLOGIAS SL
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
'use strict';
const scanner = require('./scanner');
const fs = require('fs');
var Chart = require('chart.js');
const { remote } = require('electron'),
  dialog = remote.dialog,
  app = remote.app,
  WIN = remote.getCurrentWindow();
var Timer = require('easytimer.js').Timer;

window.$ = window.jQuery = require('jquery');
window.Bootstrap = require('bootstrap');
const SCANOSS_DIR = `${app.getPath('appData')}/scanoss`;
const DOWNLOADS_DIR = app.getPath('downloads');

module.exports = {
  SCANOSS_DIR,
  DOWNLOADS_DIR,
  updateCharts,
  createCharts,
  destroyCharts,
  licenseChart,
  ossChart,
  vulnChart,
  assignCtx,
};
const scan_worker = new Worker('./scanner.js');
const timerInstance = new Timer();
var timerFunction;

var licenseChart, ossChart, vulnChart;
var globctx;
function assignCtx(ctx) {
  globctx = ctx;
}

const chartColors = {
  red: '#790600',
  orange: '#FF7F11',
  yellow: '#E9B44C',
  green: '#6DA34D',
  cyan: '#50A2A7',
  blue: '#347FC4',
  black: '#020300',
  grey: '#5D536B',
};

const vulnColors = {
  LOW: chartColors.green,
  MODERATE: chartColors.yellow,
  MEDIUM: chartColors.orange,
  HIGH: chartColors.red,
  CRITICAL: '#020300',
};

const severity_rank = [
  'LOW',
  'MODERATE',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
].reverse();

scan_worker.onmessage = (e) => {
  scan_callback(e.data);
};

scan_worker.onerror = (e) => {
  console.log('Error received in renderer: ' + e.message);
  $('.report').hide();
  $('.loading').hide();
  $('.alert').show();
  $('#new-sbom').removeClass('disabled');
};

function update_table(components) {
  let tbody = '.table tbody';
  $(tbody).html('');
  let index = 0;
  for (const [key, value] of Object.entries(components)) {
    index++;
    let parts = key.split(':');
    $(tbody).append(
      `<tr><td>${parts[0]}</td><td>${parts[1]}</td><td>${value}</td></tr>`
    );
    if (index === 10) {
      return;
    }
  }
}

function updateVulnChart(ctx) {
  if (ctx.vulns && Object.keys(ctx.vulns).length > 0) {
    $('#novulns').hide();
    let index = 0;
    let keys = Object.keys(ctx.vulns);
    vulnChart.data.labels = [];
    let data = [];
    let colors = [];
    for (const severity of severity_rank) {
      if (keys.includes(severity)) {
        vulnChart.data.labels.push(severity);
        data.push(ctx.vulns[severity].counter);
        colors.push(vulnColors[severity]);
      }
    }

    vulnChart.data.datasets[0] = {
      data: data,
      backgroundColor: colors,
    };
    index++;

    vulnChart.update();
    $('#vuln-chart').show();
  }
}

function save_ctx(ctx) {
  let persistedCtx = {
    vulns: ctx.vulns,
    licenses: ctx.licenses,
    total: ctx.total,
    osscount: ctx.osscount,
    date: ctx.date,
  };
  fs.writeFileSync(`${ctx.scandir}/ctx.json`, JSON.stringify(persistedCtx));
}

function updateCharts(ctx) {
  const sortedLics = Object.entries(ctx.licenses)
    .sort(([, a], [, b]) => b.counter - a.counter)
    .reduce((r, [k, v]) => ({ ...r, [k]: v.counter }), {});

  licenseChart.data.labels = Object.keys(sortedLics).slice(0, 8);
  licenseChart.data.datasets[0].data = Object.values(sortedLics).slice(0, 8);
  licenseChart.update();

  ossChart.data.datasets[0].data = [ctx.osscount];
  ossChart.data.datasets[1].data = [ctx.total - ctx.osscount];
  ossChart.update();

  updateVulnChart(ctx);
}

function scan_callback(ctx) {
  globctx = ctx;
  if ($('.report').is(':hidden')) {
    $('.loading').hide();
    initReport(ctx);
  }

  let percent_completed = Math.round((100 * ctx.scanned) / ctx.total);
  let percent_matches = Math.round((100 * ctx.osscount) / ctx.total);
  $('.progress-bar').css('width', `${percent_completed}%`);
  $('.progress-bar').text(`${percent_completed}%`);
  $('.progress-bar').attr('aria-valuenow', percent_completed);
  $('.matches').text(`${ctx.osscount}/${ctx.total} (${percent_matches}%)`);

  updateCharts(ctx);

  $('.scanned-files').text(`${ctx.scanned}`);
  if (ctx.status !== 'DONE') {
  } else {
    // SCAN DONE
    timerInstance.stop();
    $('#new-sbom').removeClass('disabled');
    $('#new-sbom').on('click', scanDirectory);
    $('.download-button').prop('disabled', false);
    $('.download-button').removeClass('disabled');
    $('.refresh button').show();

    $('.download-button').on('click', (ev) => {
      ev.preventDefault();
      let path = dialog.showSaveDialogSync(WIN, {
        title: 'Save scan results',
        defaultPath: `${DOWNLOADS_DIR}/sbom.csv`,
      });
      if (!path) {
        console.log('No save path selected');
        return;
      }
      fs.copyFileSync(ctx.csvbom, path);
    });
    save_ctx(ctx);
  }
}

function createCharts() {
  licenseChart = new Chart($('#license-chart'), {
    type: 'pie',
    data: {
      datasets: [{ data: [], backgroundColor: Object.values(chartColors) }],
      labels: [],
    },
    options: {
      title: {
        display: true,
        text: 'Top Licenses',
      },
      onClick: (e, elements) => {
        if (elements.length > 0) {
          let license = elements[0]._chart.data.labels[elements[0]._index];
          $('.hoverlicense').text(license);
          update_table(globctx.licenses[license].components);
          $('.vtable').hide();
          $('.ctable').show();
        }
      },
    },
  });

  var barOptions_stacked = {
    scales: {
      xAxes: [
        {
          stacked: true,
        },
      ],
      yAxes: [
        {
          gridLines: {
            display: false,
            color: '#fff',
            zeroLineColor: '#fff',
            zeroLineWidth: 0,
          },
          stacked: true,
        },
      ],
    },
    title: {
      display: true,
      text: 'Files with OSS Match vs No Match',
    },

    pointLabelFontFamily: 'Quadon Extra Bold',
    scaleFontFamily: 'Quadon Extra Bold',
  };

  ossChart = new Chart($('#oss-chart'), {
    type: 'horizontalBar',
    data: {
      datasets: [
        {
          data: [0],
          backgroundColor: [chartColors.green],
          label: 'OSS Match',
        },
        {
          data: [0],
          backgroundColor: [chartColors.orange],
          label: 'No Match',
        },
      ],
      labels: [''],
    },
    options: barOptions_stacked,
  });

  vulnChart = new Chart($('#vuln-chart'), {
    type: 'horizontalBar',
    data: {
      datasets: [],
      labels: [],
    },
    options: {
      animation: {
        duration: 0,
      },
      title: {
        display: true,
        text: 'Vulnerabilities Found',
      },
      legend: {
        display: false,
      },
      scales: {
        xAxes: [
          {
            ticks: {
              min: 0,
              precision: 0,
            },
          },
        ],
      },
      onClick: (e, elements) => {
        if (elements.length > 0) {
          let severity = elements[0]._chart.data.labels[elements[0]._index];
          $('.severity').text(severity);
          update_table(globctx.vulns[severity].components);
          $('.vtable').show();
          $('.ctable').hide();
        }
      },
    },
  });
}

function initReport(ctx) {
  $('.report').show();
  $('.scanfolder').text(ctx.scandir);
  $('.progress-bar').css('width', `0%`);
  $('.progress-bar').text(`$0%`);
  $('.progress-bar').attr('aria-valuenow', 0);
  $('.matches').text('0');
  $('#vuln-chart').hide();
  createCharts();
}

function destroyCharts() {
  if (licenseChart) {
    licenseChart.destroy();
  }
  if (ossChart) {
    ossChart.destroy();
  }
  if (vulnChart) {
    vulnChart.destroy();
  }
}

function formatDate (date) {
  let formatted_date =
    date.getFullYear() +
    '-' +
    (date.getMonth() + 1) +
    '-' +
    date.getDate() +
    ' ' +
    date.getHours() +
    ':' +
    date.getMinutes() +
    ':' +
    date.getSeconds(); 
  return formatted_date
}

function scanDirectory(ev) {
  timerInstance.start();
  timerInstance.addEventListener('secondsUpdated', function (e) {
    $('#elapsed').html(timerInstance.getTimeValues().toString());
  });
  if (licenseChart) {
    licenseChart.destroy();
  }
  if (ossChart) {
    ossChart.destroy();
  }
  if (vulnChart) {
    vulnChart.destroy();
  }
  $('.alert, .intro, .report, .ctable, .vtable').hide();

  let options = { properties: ['openDirectory'] };
  
  let dir = dialog.showOpenDialogSync(options);
  if (dir === undefined) {
    console.log('No directory selected');
    return;
  }
  
  $('.loading').show();
  $('.counter').html('0');
  let ctx = {
    total: scanner.countFiles(dir[0]),
    sourceDir: dir[0],
    date: formatDate(new Date()),
  };
  $('.counter').html(ctx.total);
  
  // Using web workers
  scan_worker.postMessage({
    ctx: ctx,
    scanossdir: SCANOSS_DIR,
    downloadsdir: DOWNLOADS_DIR,
  });
  
  // disable buttons
  $('.download-button').off('click')
  $('.download-button').addClass('disabled');
  $('#new-sbom').addClass('disabled');
  $('#new-sbom').off('click');
}

$(function () {
  $('.alert').hide();
  $('.report').hide();
  $('.loading').hide();
  $('#new-sbom').on('click', scanDirectory);
});
