
const fs = require('fs')
const { remote } = require('electron'),
  dialog = remote.dialog,
  WIN = remote.getCurrentWindow();
const { SCANOSS_DIR, DOWNLOADS_DIR } = require('./renderer')

function listScans () {
  const scans = fs.readdirSync(SCANOSS_DIR)
  let tbody = '.table tbody';
  $(tbody).html('');
  scans.forEach((scan) => {
    const scandir = `${SCANOSS_DIR}/${scan}`
    const files = fs.readdirSync(scandir)
    const csv = files.includes('sbom.csv') ? `<a href="${scandir}/sbom.csv" id="${scan}-csv" class="csv" data-scan="${scan}">Download</a>` : 'Not Available'
    const json = files.includes('scanoss-scan.json')
      ? `<a href="${scandir}/scanoss-scan.json" id="${scan}-json" class="json" data-scan="${scan}">Download</a>`
      : 'Not Available';
    const wfp = files.includes('scan.wfp')
      ? `<a href="${scandir}/scan.wfp" id="${scan}-wfp" class="wfp" data-scan="${scan}">Download</a>`
      : 'Not Available';

    $(tbody).append(
      `<tr><td>${scan}</td><td>${wfp}</td><td>${json}</td><td>${csv}</td><td><a href="#" class="delete" data-scan="${scan}"><i class="fas fa-trash"></i></a><td></tr>`
    ); 
  })
  $('.csv').on('click', (ev) => {
    ev.preventDefault();
    let path = dialog.showSaveDialogSync(WIN, {
      title: 'Save scan report',
      defaultPath: `${DOWNLOADS_DIR}/sbom.csv`,
    });
    if (!path) {
      console.log('No save path selected');
      return;
    }
    let scan = $(this).data('scan');
    const csvfile = `${SCANOSS_DIR}/${scan}/sbom.csv`;
    fs.copyFileSync(csvfile, path);
  });
  $('.json').on('click', (ev) => {
    ev.preventDefault();
    let path = dialog.showSaveDialogSync(WIN, {
      title: 'Save scan raw result',
      defaultPath: `${DOWNLOADS_DIR}/result.json`,
    });
    if (!path) {
      console.log('No save path selected');
      return;
    }
    let scan = ev.currentTarget.dataset['scan'];
    const jsonfile = `${SCANOSS_DIR}/${scan}/scanoss-scan.json`;
    fs.copyFileSync(jsonfile, path);
  });
  $('.wfp').on('click', (ev) => {
    ev.preventDefault();
    let path = dialog.showSaveDialogSync(WIN, {
      title: 'Save scan report',
      defaultPath: `${DOWNLOADS_DIR}/scan.wfp`,
    });
    if (!path) {
      console.log('No save path selected');
      return;
    }
    let scan = ev.currentTarget.dataset['scan'];
    const wfpfile = `${SCANOSS_DIR}/${scan}/scan.wfp`;
    fs.copyFileSync(wfpfile, path);
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
      message: 'Are you sure that you want to delete scan '+scan+'?'
    });
    if (!path) {
      console.log(`Deleting scan: ${scan}`);
      const scandir = `${SCANOSS_DIR}/${scan}`;
      fs.rmdirSync(scandir, { recursive: true })
      listScans()
      return;
    }
  });

}

$(function () {
  listScans()
});