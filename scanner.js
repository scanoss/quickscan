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
const fs = require('fs');
const os = require('os');
const winnowing = require('./winnowing');
const path = require('path');
const { request } = require('http');

const request_worker = new Worker('./queued-request-worker.js');
var SCANOSS_DIR;
// The list of files is divided in chunks for processing.
var CHUNK_SIZE = 40;
const QUEUE_DIR = `${os.tmpdir()}/quickscan-queue`;

var ctx = {};

onmessage = (e) => {
  SCANOSS_DIR = e.data.scanossdir;
  scanFolder(e.data.ctx, render_callback);
};

function render_callback(ctx) {
  postMessage(ctx);
}

function scan_wfp_worker(counter, wfp) {
  request_worker.postMessage({ wfp: wfp, chunk: CHUNK_SIZE, counter: counter });
}

request_worker.onmessage = (e) => {
  let json = e.data.json;
  let counter = e.data.counter;
  ctx.scanned += counter;
  let done = ctx.scanned >= ctx.total;
  ctx.wfp = e.data.wfp;
  update_licenses(ctx, json);
  update_vulns(ctx, json);
  append_to_results(ctx, json, done);
  if (done) {
    console.log('Scan done');
    ctx.status = 'DONE';
  }
  json = '';
  postMessage(ctx);
};

request_worker.onerror = (e) => {
  throw e;
};

function get_scan_dir(path) {
  return path.match(/[^\\\/]+$/);
}

function countFiles(dir) {
  let index = 0;
  const files = fs.readdirSync(dir);
  files.forEach((file) => {
    var filepath = path.join(dir, file);
    const stats = fs.lstatSync(filepath);
    if (
      stats.isDirectory() &&
      !stats.isSymbolicLink() &&
      !winnowing.is_filtered_dir(filepath)
    ) {
      index += countFiles(filepath);
    } else if (
      stats.isFile() &&
      !stats.isSymbolicLink() &&
      !winnowing.FILTERED_EXT.includes(path.extname(filepath))
    ) {
      index++;
    }
  });
  return index;
}

async function* walk(dir) {
  for await (const d of await fs.promises.opendir(dir)) {
    const entry = path.join(dir, d.name);
    // const stats = fs.lstatSync(filepath);
    if (
      d.isDirectory() &&
      !d.isSymbolicLink() &&
      !winnowing.is_filtered_dir(entry)
    )
      yield* walk(entry);
    else if (
      d.isFile() &&
      !d.isSymbolicLink() &&
      !winnowing.FILTERED_EXT.includes(path.extname(entry))
    )
      yield entry;
  }
}

async function recursive_scan(dir) {
  let wfp = '';
  let counter = 0;
  for await (const filepath of walk(dir)) {
    counter++;
    wfp += winnowing.wfp_for_file(
      filepath,
      filepath.replace(ctx.sourceDir, '')
    );

    if (counter % CHUNK_SIZE === 0) {
      scan_wfp_worker(counter, wfp);
      wfp = '';
      counter = 0;
    }
  }
  if (dir === ctx.sourceDir && wfp !== '') {
    scan_wfp_worker(counter, wfp);
  }
  return counter;
}

function scanFolder(initctx, callback) {
  fs.rmdirSync(QUEUE_DIR, { recursive: true });
  // Initialise directories
  if (!fs.existsSync(SCANOSS_DIR)) {
    fs.mkdirSync(SCANOSS_DIR);
  }
  ctx = initctx;
  ctx.scandir = SCANOSS_DIR + '/' + get_scan_dir(ctx.sourceDir);

  // Remove contents of previous scan.
  if (fs.existsSync(ctx.scandir)) {
    fs.rmdirSync(ctx.scandir, { recursive: true });
  }
  fs.mkdirSync(ctx.scandir);
  // Initialise context
  ctx.status = 'IN_PROGRESS';
  ctx.scanned = 0;
  ctx.osscount = 0;
  ctx.resultfile = `${ctx.scandir}/scanoss-scan.json`;
  ctx.csvbom = `${ctx.scandir}/sbom.csv`;
  ctx.wfpfile = `${ctx.scandir}/scan.wfp`;
  ctx.wfp = '';
  // console.log(`Result file: ${ctx.resultfile}`)
  fs.writeFileSync(
    ctx.csvbom,
    'FILE,MATCH TYPE,% MATCH,VENDOR,COMPONENT,VERSION,URL,LICENSE,COPYRIGHT,VULNERABILITIES' +
      os.EOL
  );
  fs.writeFileSync(ctx.resultfile, `{${os.EOL}`);

  // Process directory in chunks
  console.log('Starting Walk ');
  recursive_scan(ctx.sourceDir);
  console.log('Walk completed');
}

function append_to_results(ctx, json, done) {
  let count = Object.keys(json).length;
  let index = 0;
  for (let key in json) {
    index++;
    let value = json[key][0];
    fs.appendFileSync(
      ctx.resultfile,
      `"${key}":${JSON.stringify(json[key])}${os.EOL}`
    );
    // CSV
    if (value.id !== 'none') {
      ctx.osscount++;
      let versions =
        value.version === value.latest
          ? value.version
          : `${value.version}-${value.latest}`;
      let license = value.licenses.length > 0 ? value.licenses[0].name : '';
      let copyright =
        value.copyrights.length > 0 ? value.copyrights[0].name : '';
      let vulns = value.vulnerabilities.map((v) => v.CVE).join(',');
      fs.appendFileSync(
        ctx.csvbom,
        `${key},${value.id},${value.matched},${value.vendor},${value.component},${versions},${value.url},${license},${copyright},"${vulns}"\n`
      );
    }
    if (index === count && done) {
      fs.appendFileSync(ctx.resultfile, `${os.EOL}}`);
    } else {
      fs.appendFileSync(ctx.resultfile, `,`);
    }
    fs.appendFileSync(ctx.wfpfile, `${ctx.wfp}${os.EOL}`);
  }
}

function update_components(ctx, json) {
  if (ctx.components === undefined) {
    ctx.components = {};
  }
  for (key in json) {
    let value = json[key];
    for (let i = 0; i < value.length; i++) {
      let val = value[i];
      if (val.id !== 'none') {
        let comp_id = `${val.vendor}:${val.component}:${val.version}`;
        if (!(comp_id in ctx.components)) {
          ctx.components[comp_id] = 1;
        } else {
          ctx.components[comp_id]++;
        }
      }
    }
  }
}

function update_licenses(ctx, json) {
  if (ctx.licenses === undefined) {
    ctx.licenses = {};
  }
  for (key in json) {
    let value = json[key];
    for (let i = 0; i < value.length; i++) {
      let val = value[i];
      let comp_id = `${val.vendor}:${val.component}`;
      let versions =
        val.version === val.latest
          ? val.version
          : `${val.version}..${val.latest}`;
      // Only look at first license.
      if (val.licenses && val.licenses[0]) {
        let license = val.licenses[0].name;
        if (!(license in ctx.licenses)) {
          ctx.licenses[license] = { counter: 0, components: {} };
        }
        let lic = ctx.licenses[license];

        if (!(comp_id in lic.components)) {
          lic.counter++;
          lic.components[comp_id] = versions;
        }
      }
    }
  }
}

function update_vulns(ctx, json) {
  if (!ctx.vulns) {
    ctx.vulns = {};
  }
  for (key in json) {
    let value = json[key];
    value.forEach((match) => {
      let comp_id = `${match.vendor}:${match.component}`;
      let versions =
        match.version === match.latest
          ? match.version
          : `${match.version}..${match.latest}`;
      if (match.vulnerabilities && match.vulnerabilities.length > 0) {
        match.vulnerabilities.forEach((vuln) => {
          let severity = vuln.severity;
          if (!(vuln.severity in ctx.vulns)) {
            ctx.vulns[severity] = { counter: 0, components: {} };
          }
          if (!(comp_id in ctx.vulns[severity].components)) {
            ctx.vulns[severity].counter++;
            cves = new Set()
            cves.add(vuln.CVE)
            ctx.vulns[severity].components[comp_id] = {
              versions: versions,
              cves: cves
            }
          } else {
            ctx.vulns[severity].components[comp_id].cves.add(vuln.CVE);
          } 
        });
      }
    });
  }
}

module.exports = {
  scanFolder,
  countFiles,
};
