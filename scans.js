const fs = require('fs');
const { remote } = require('electron'),
  dialog = remote.dialog,
  WIN = remote.getCurrentWindow();
const {
  SCANOSS_DIR,
  DOWNLOADS_DIR,
  createCharts,
  updateCharts,
  updateObligationTable,
  destroyCharts,
  assignCtx,
  save_ctx
} = require('./renderer.js');
const scan_worker = new Worker('./scanner.js');
var Timer = require('easytimer.js').Timer;
const dirTree = require("directory-tree");

const timerInstance = new Timer();

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
  timerInstance.stop();
};

function resumeScan (scandir) {
  $('#report-head').show();
  timerInstance.start();
  timerInstance.addEventListener('secondsUpdated', function (e) {
    $('#elapsed').html(timerInstance.getTimeValues().toString());
  });
  scan_worker.postMessage( 
  {
    scanossdir: SCANOSS_DIR,
    resume: scandir
  });
}

function scan_callback(ctx) {
  console.log('Calling scan_callback');

  let percent_completed = Math.round((100 * ctx.scanned) / ctx.total);
  let percent_matches = Math.round((100 * ctx.osscount) / ctx.total);
  $('.progress-bar').css('width', `${percent_completed}%`);
  $('.progress-bar').text(`${percent_completed}%`);
  $('.progress-bar').attr('aria-valuenow', percent_completed);
  $('.matches').text(`${ctx.osscount}/${ctx.total} (${percent_matches}%)`);

  updateCharts(ctx);

  $('.scanned-files').text(`${ctx.scanned}`);
  if (ctx.status === 'DONE') {
    // SCAN DONE
    timerInstance.stop(); 
    $('.reports-btn').removeClass('disabled');
    $('.refresh button').show();
    $('#report-scan').hide();
    $('#goto-scans').show();

    save_ctx(ctx);
  }
}








function saveScanFile(ev, scanfile) {
  ev.preventDefault();
  let path = dialog.showSaveDialogSync(WIN, {
    title: 'Save scan result',
    defaultPath: `${DOWNLOADS_DIR}/${scanfile}`,
  });
  if (!path) {
    console.log('No save path selected');
    return;
  }
  let scan = ev.currentTarget.dataset['scan'];
  const jsonfile = `${SCANOSS_DIR}/${scan}/${scanfile}`;
  fs.copyFileSync(jsonfile, path);
}

function opencharts (ev) {
  $('.ctable, .vtable, #vuln-chart').hide();
  destroyCharts()
  $('.scans').hide()
  let scan = ev.currentTarget.dataset['scan'];
  $('.report-title').text(scan)
  const scandir = `${SCANOSS_DIR}/${scan}`;
  ctx = JSON.parse(fs.readFileSync(`${scandir}/ctx.json`));
  assignCtx(ctx);
  createCharts();
  updateCharts(ctx);
  updateObligationTable(ctx);
  $('.charts').show()
  if (fs.existsSync(`${scandir}/FAILED`)) {
    $('#goto-scans').hide();
    $('#resume-scan').show();
    $('#resume-scan').on('click', (ev) => {
      $(this).addClass('disabled');
      ev.preventDefault();
      resumeScan(scandir);
      

    })
  }
}

function getScanStatus (scandir) {
  let status = 'Completed';
  if (fs.existsSync(`${scandir}/FAILED`)) {
    let ctxString = fs.readFileSync(`${scandir}/ctx.json`);
    let ctx = JSON.parse(ctxString);
    let percent_completed = Math.round((100 * ctx.scanned) / ctx.total);
    status = `Failed (${percent_completed}%)`;
  }
  return status;
}

function listScans () {
  $('.charts').hide()
  $('.scans').show();
  const scans = fs.readdirSync(SCANOSS_DIR);
  let tbody = '.stable .table tbody';
  $(tbody).html('');
  scans.forEach((scan) => {
    const scandir = `${SCANOSS_DIR}/${scan}`;
    const files = fs.readdirSync(scandir);
    const hasCtx = files.includes('ctx.json');
    let ctx = { date: '' };
    if (hasCtx) {
      ctx = JSON.parse(fs.readFileSync(`${scandir}/ctx.json`));
    }
    
    const csv = files.includes('sbom.csv')
      ? `<a href="${scandir}/sbom.csv" id="${scan}-csv" class="csv" data-scan="${scan}">Download</a>`
      : 'Not Available';
    const json = files.includes('scanoss-scan.json')
      ? `<a href="${scandir}/scanoss-scan.json" id="${scan}-json" class="json" data-scan="${scan}">Download</a>`
      : 'Not Available';
    const wfp = files.includes('scan.wfp')
      ? `<a href="${scandir}/scan.wfp" id="${scan}-wfp" class="wfp" data-scan="${scan}">Download</a>`
      : 'Not Available';
    let chartsColumn = hasCtx
      ? `<td><a href="#" class="opencharts" data-scan="${scan}" data-toggle="tooltip" title="Scan charts"><i class="fas fa-chart-bar"></i></a></td>`
      : '<td></td>';
    let status = getScanStatus(scandir);
    
    $(tbody).append(
      `<tr><td>${scan}</td><td>${ctx.date}</td><td>${status}</td><td>${ctx.total}</td>${chartsColumn}<td>${wfp}</td><td>${json}</td><td>${csv}</td><td><a href="#" class="delete" data-scan="${scan}"><i class="fas fa-trash"></i></a></td></tr>`
    );
    
  });
  $('.csv').on('click', (ev) => {
    saveScanFile(ev, 'sbom.csv');
  });
  $('.json').on('click', (ev) => {
    saveScanFile(ev, 'scanoss-scan.json');
  });
  $('.wfp').on('click', (ev) => {
    saveScanFile(ev, 'scan.wfp');
  });
  $('.opencharts').on('click', (ev) => {
    opencharts(ev);
  });

  $('.delete').on('click', (ev) => {
    ev.preventDefault();
    let scan = ev.currentTarget.dataset['scan'];
    let path = dialog.showMessageBoxSync(WIN, {
      title: 'Delete',
      type: 'warning',
      buttons: ['OK', 'Cancel'],
      defaultId: 1,
      cancelId: 1,
      message: 'Are you sure that you want to delete scan ' + scan + '?',
    });
    if (!path) {
      console.log(`Deleting scan: ${scan}`);
      const scandir = `${SCANOSS_DIR}/${scan}`;
      fs.rmdirSync(scandir, { recursive: true });
      listScans();
      return;
    }
  });
  $('[data-toggle="tooltip"]').tooltip();
}

$(function () {
  $('#resume-scan').hide();
  $('#report-head').hide();
  listScans();
});
