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
const fs = require('original-fs');
const os = require('os');
const winnowing = require('./winnowing');
const path = require('path');
const { request } = require('http');
const { count } = require('console');

const MAX_FILES = 10000;
const request_worker = new Worker('./queued-request-worker.js');
var SCANOSS_DIR;
// The list of files is divided in chunks for processing.
var CHUNK_SIZE = 100;
const QUEUE_DIR = `${os.tmpdir()}/quickscan-queue`;


var ctx = {};

onmessage = (e) => {
  SCANOSS_DIR = e.data.scanossdir;
  if (e.data.resume) {
    resumeScan(e.data.resume);
  } else {
    scanFolder(e.data.ctx);
  }
};

/**
 * This function stores a scan wfp and metadata in a file in the queue folder
 * @param {*} wfp
 * @param {*} counter
 */
function queue_scan(wfp, counter) {
  console.log('queue_scan, counter: ' + counter);
  if (!fs.existsSync(QUEUE_DIR)) {
    fs.mkdirSync(QUEUE_DIR);
  }
  let filename = `${QUEUE_DIR}/${new Date().getTime()}.json`;

  fs.writeFileSync(filename, JSON.stringify({ wfp: wfp, counter: counter }));
  scan_wfp_worker();
}

/**
 * This function sends a message to the worker requesting to scan a WFP file
 */
function scan_wfp_worker() {
  const files = fs.readdirSync(QUEUE_DIR);
  if (files.length > 0) {
    let file = files.sort()[0];
    var filepath = path.join(QUEUE_DIR, file);
    let context = ctx.max_component ? ctx.max_component.name : '';
    request_worker.postMessage({
      file: filepath,
      chunk: CHUNK_SIZE,
      context: context,
    });
  }
}

request_worker.onmessage = (e) => {
  let json = e.data.json;
  let counter = e.data.counter;
  ctx.scanned += counter;
  let done = ctx.scanned >= ctx.total;
  ctx.wfp = e.data.wfp;
  update_components(ctx, json);
  update_licenses(ctx, json);
  update_vulns(ctx, json);
  append_to_results(ctx, json, done);
  if (done) {
    console.log('Scan done');
    ctx.status = 'DONE';
  }
  json = '';
  postMessage(ctx);
  // Scan next batch
  scan_wfp_worker();
};

request_worker.onerror = (e) => {
  console.log(`Received error while scanning. Preparing for recovery ${e.message}`);
  let pending_dir = `${ctx.scandir}/pending`;
  fs.mkdirSync(pending_dir);
  const files = fs.readdirSync(QUEUE_DIR);
  files.forEach((file) => {
    var filepath = path.join(QUEUE_DIR, file);
    const stats = fs.lstatSync(filepath);
    if (stats.isFile()) {
      fs.copyFileSync(filepath, `${pending_dir}/${file}`);
    }
  });
  // Convert CVEs from Set to arrays.
  Object.values(ctx.vulns).forEach((vuln) => {
    Object.values(vuln.components).forEach((component) => {
      component.cves = Array.from(component.cves);
    });
  });
  fs.writeFileSync(`${ctx.scandir}/ctx.json`, JSON.stringify(ctx));
  fs.writeFileSync(`${ctx.scandir}/FAILED`, '');
  throw e;
};

function resumeScan(scandir) {
  console.log(`Resuming scan ${scandir}`);
  let pending_dir = `${scandir}/pending`;
  const files = fs.readdirSync(pending_dir);
  files.forEach((file) => {
    var filepath = path.join(pending_dir, file);
    const stats = fs.lstatSync(filepath);
    if (stats.isFile()) {
      fs.copyFileSync(filepath, `${QUEUE_DIR}/${file}`);
    }
  });
  let ctxString = fs.readFileSync(`${scandir}/ctx.json`);
  ctx = JSON.parse(ctxString);
  scan_wfp_worker();
  try {
    fs.unlinkSync(`${scandir}/FAILED`);
  } catch (error) {
    console.log('Error unlinking FAILED file: ', error);
  }
}

function get_scan_dir(path) {
  return path.match(/[^\\\/]+$/);
}


function countFilesOnWFP(text) {
  let count = (text.match(/file=/g)||[]).length
  return count;
}



function getWfpFromFile(filepath) {
  let content = fs.readFileSync(filepath,{encoding:'utf8', flag:'r'});
  return content;

}

function getFileExtention(filepath){
  return filepath.split(".").pop().toLocaleLowerCase();
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
      )
      
    {
      //If there are a wfp file, explore it and add to count
      if( getFileExtention(filepath) == "wfp") {
        content = fs.readFileSync(filepath,{encoding:'utf8', flag:'r'});
        index += countFilesOnWFP(content);
      }else{
        index++;
      }
      
      
    }
  });

  return index;
}

async function* walk(dir) {
  for await (const d of await fs.promises.opendir(dir)) {
    const entry = path.join(dir, d.name);
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
  let preWfp = '';
  let counter = 0;
  let totalCounter = 0;
  
  loop:
  for await (const filepath of walk(dir)) {
      
    if(getFileExtention(filepath)!="wfp") {
        counter++;
        totalCounter++;
        preWfp = winnowing.wfp_for_file(
          filepath,
          filepath.replace(ctx.sourceDir, '')
        );
        
        if (wfp.length + preWfp.length >= winnowing.MAX_SIZE_CHUNK) {
          queue_scan(wfp, counter);
          wfp = '';
          counter = 0;
        }
        wfp +=preWfp;

      }else{
        
        //Particular case when a wfp file it is found
        let wfpString = getWfpFromFile(filepath);
        let wfpArray = wfpString.split('file=');
        wfpArray.shift(); //Removes the first element because it's empty

        for(preWfp of wfpArray) {
          preWfp = 'file=' + preWfp; //Add 'file=' because it was removed when the array was splited.
          totalCounter++;
          counter++;

          if (wfp.length + preWfp.length >= winnowing.MAX_SIZE_CHUNK) {
             queue_scan(wfp, counter);
             wfp = '';
             counter = 0;
             console.log('pass');
          }
          wfp+=preWfp;

          if(totalCounter>=MAX_FILES)
            break loop;
        }
      }

      if(totalCounter>=MAX_FILES)
        break loop;
  }
  if (dir === ctx.sourceDir && wfp !== '') {
    queue_scan(wfp, counter);
  }
  console.log(totalCounter);
  return counter;
}

async function scanFolder(initctx) {
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
    'FILE,MATCH TYPE,% MATCH,VENDOR,COMPONENT,VERSION,URL,LICENSE,URL LICENSE,COPYRIGHT,VULNERABILITIES' +
      os.EOL
  );
  fs.writeFileSync(ctx.resultfile, `{${os.EOL}`);

  // Process directory in chunks
  console.log('Starting Walk ');
  await recursive_scan(ctx.sourceDir); 
  console.log('Walk completed');
}

function append_to_results (ctx, json, done) {
  if (!json) {
    return;
  }
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
      let URLlicense = value.licenses.length > 0 ? value.licenses[0].obligations : '' ;
      let copyright =
        value.copyrights.length > 0 ? value.copyrights[0].name : '';
      let vulns = value.vulnerabilities.map((v) => v.CVE).join(',');
      fs.appendFileSync(
        ctx.csvbom,
        `${key},${value.id},${value.matched},${value.vendor},${value.component},${versions},${value.url},${license},${URLlicense},${copyright},"${vulns}"\n`
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

function update_components (ctx, json) {
  if (!json) {
    return;
  }
  // max_component is the component with more hits.
  if (!ctx.max_component) {
    ctx.max_component = { name: '', hits: 0 };
  }
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
        if (ctx.max_component.hits < ctx.components[comp_id]) {
          ctx.max_component.name = val.component;
          ctx.max_component.hits = ctx.components[comp_id];
        }
      }
    }
  }
}

function update_licenses (ctx, json) {
  if (!json) {
    return;
  }
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

function update_vulns (ctx, json) {
  if (!json) {
    return;
  }
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
            cves = new Set();
            cves.add(vuln.CVE);
            ctx.vulns[severity].components[comp_id] = {
              versions: versions,
              cves: cves,
            };
          } else {
            if (!ctx.vulns[severity].components[comp_id].cves) {
              ctx.vulns[severity].components[comp_id].cves = new Set();
            } else if (
              Array.isArray(ctx.vulns[severity].components[comp_id].cves)
            ) {
              ctx.vulns[severity].components[comp_id].cves = new Set(
                ctx.vulns[severity].components[comp_id].cves
              );
            }
            try {
              ctx.vulns[severity].components[comp_id].cves.add(vuln.CVE);
            } catch (error) {
              console.log(
                `ctx.vulns[severity].components[comp_id]: ${JSON.stringify(
                  ctx.vulns[severity].components[comp_id]
                )}, `,
                error
              );
            }
          }
        });
      }
    });
  }
}

module.exports = {
  scanFolder,
  countFiles,
  MAX_FILES
};
