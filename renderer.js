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
  updateObligationTable,
  createCharts,
  destroyCharts,
  licenseChart,
  ossChart,
  vulnChart,
  assignCtx,
  save_ctx,
};
const scan_worker = new Worker('./scanner.js');
const obligation_worker = new Worker('./obligations.js')
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
  $('.loading').hide();
  $('.alert').show();
  $('#new-sbom').removeClass('disabled');
  $('#new-sbom').on('click', scanDirectory);
  $('.reports-btn').removeClass('disabled');
  $('#resume-scan a').removeClass('disabled');
  timerInstance.pause();
  $('#resume-scan').show();
  $('#resume-scan').on('click', (ev) => {
    disableButtons();
    $('.alert').hide();
    ev.preventDefault();
    resumeScan(globctx.scandir);
  });
  alert(`Ups, something went wrong parsing a JSON object \n ${e.message}`);
};

obligation_worker.onerror = (e) => {
  alert(`Error showing licenses obligations ${e.message}`);
}

obligation_worker.onmessage = (e) => {
  globctx.obligations = e.data;
  updateObligationTable(globctx);
  save_ctx(globctx);
};



function resumeScan(scandir) {
  console.log('Resume scan for dir: ', scandir)
  $('.alert').hide();
  $('#report-head').show();
  timerInstance.start();
  timerInstance.addEventListener('secondsUpdated', function (e) {
    $('#elapsed').html(timerInstance.getTimeValues().toString());
  });
  scan_worker.postMessage({
    scanossdir: SCANOSS_DIR,
    resume: scandir,
  });
}

function update_table(components) {
  let tbody = '.upgradeable tbody';
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

function update_vuln_table(components) {
  let tbody = '.upgradeable tbody';
  $(tbody).html('');
  let index = 0;
  for (const [key, value] of Object.entries(components)) {
    index++;
    let parts = key.split(':');
    let cves = value.cves === undefined ? [] : [...value.cves];
    $(tbody).append(
      `<tr><td>${parts[0]}</td><td>${parts[1]}</td><td>${value.versions
      }</td><td>${cves.join(',')}</td></tr>`
    );
    if (index === 10) {
      return;
    }
  }
}

function updateObligationTable(ctx) {

  const body_table = $('.otable tbody');
  
  //Avoids the case when the user brings back a previous scan without the license obligations table
  if(ctx.hasOwnProperty('obligations')) 
  {
    const obligations = ctx.obligations;

    let incompatible_licenses = new Set();
    let incompatible_licenses_count = 0;

    $(body_table).html('');  	// Clean the previous data
    $(body_table).next("tfoot").remove();	//Delete the previous footer

    //On each iteration one obligation is analized and is created one row.
    //Also incompatible licenses are added to a set to compare them later
    obligations.forEach(obligation => {

      //Create row
      let row = $("<tr></tr>");
      let license_name = Object.keys(obligation)[0];
      let data = obligation[license_name][0];

      //Add license name with tooltip  
      row.append($(`<td> 
                  <a href="${data.obligations}" target="_blank" data-toggle="tooltip" 
                  title="OSADL license obligations"> ${license_name} </a> 
                  </td>`
      ));

      let parameters = ["copyleft", "patent_hints", "incompatible_with"];
      for (let index = 0; index < parameters.length; index++) {

        if (data.hasOwnProperty(parameters[index]))
          row.append($(`<td>${data[parameters[index]]}</td>`));
        else
          row.append($(`<td>--</td>`));

        //Incompatible license are added to the set.
        if (parameters[index] == "incompatible_with" && data.hasOwnProperty("incompatible_with")) {
          let incompatible_license_array = data[parameters[index]].split(',');
          incompatible_license_array.forEach((item, index, array) => {
            array[index] = array[index].trim(); //Remove any whitespace and add it to the set
            if (!incompatible_licenses.has(array[index]))
              incompatible_licenses.add(array[index]);
          });
        }

      }

      $(body_table).append(row);
    });

    //Iterate over all the licenses names rows and check if there are some incompatible licenses.
    $(body_table).children().each((index, row) => {
      let license_element = $(row).children().eq(0);
      if (incompatible_licenses.has(license_element.text().trim())) {
        license_element.prepend('*');
        license_element.css({ 'color': 'red', 'font-weight': 'bold' });
        incompatible_licenses_count++;
      }
    });

    //Add a foot to the table
    if (incompatible_licenses_count > 0) {
      let text = "*Note: License conflicts have been identified."
      let tfoot = $(`<tfoot><tr><td colspan="5"><p>${text}</p></td></tr></tfoot>`);
      tfoot.css({ 'color': 'red', 'font-weight': 'bold' });
      $(body_table).after(tfoot);

    }

    $('.otable').show();
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
  // Convert CVEs from Set to arrays.
  Object.values(ctx.vulns).forEach((vuln) => {
    Object.values(vuln.components).forEach((component) => {
      component.cves = Array.from(component.cves);
    });
  });
  fs.writeFileSync(`${ctx.scandir}/ctx.json`, JSON.stringify(ctx));
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
  console.log('Calling scan_callback');
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
    timerInstance.pause();
    $('#new-sbom').removeClass('disabled');
    $('#new-sbom').on('click', scanDirectory);

    $('.reports-btn').removeClass('disabled');
    $('.refresh button').show();
    $('#resume-scan').hide();

    /* license obligations */
    const sortedLics = Object.entries(ctx.licenses)
      .sort(([, a], [, b]) => b.counter - a.counter)
      .reduce((r, [k, v]) => ({ ...r, [k]: v.counter }), {});

    let licenses = Object.keys(sortedLics);
    console.log(licenses);

    //Send an array with license name strings in order to get the licenses obligations
    obligation_worker.postMessage(licenses);
    /* license obligations */

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
        text: 'Components with Vulnerabilities',
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
          update_vuln_table(globctx.vulns[severity].components);
          $('.vtable').show();
          $('.ctable').hide();
        }
      },
    },
  });
}


function initReport(ctx) {
  $('.report').show();
  $('.scanfolder').text(ctx.sourceDir);
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

function formatDate(date) {
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
  return formatted_date;
}

function scanDirectory(ev) {
  $('#resume-scan').hide();
  $('.otable').hide(); //Hide obligations table
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
  disableButtons();
}

function disableButtons() {
  $('#resume-scan a').addClass('disabled');
  $('#resume-scan a').off('click');
  $('.reports-btn').off('click');
  $('.reports-btn').addClass('disabled');
  $('#new-sbom').addClass('disabled');
  $('#new-sbom').off('click');
}

$(function () {
  $('.alert').hide();
  $('.report').hide();
  $('.loading').hide();
  $('#resume-scan').hide();
  $('#new-sbom').on('click', scanDirectory);
});

