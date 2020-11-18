const fs = require('fs');
const { remote } = require('electron'),
  dialog = remote.dialog,
  WIN = remote.getCurrentWindow();
const {
  SCANOSS_DIR,
  DOWNLOADS_DIR,
  createCharts,
  updateCharts,
  destroyCharts,
  assignCtx
} = require('./renderer');


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
  assignCtx(ctx)
  createCharts()
  updateCharts(ctx)
  $('.charts').show()
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
    $(tbody).append(
      `<tr><td>${scan}</td><td>${ctx.date}</td>${chartsColumn}<td>${wfp}</td><td>${json}</td><td>${csv}</td><td><a href="#" class="delete" data-scan="${scan}"><i class="fas fa-trash"></i></a></td></tr>`
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
  listScans();
});
