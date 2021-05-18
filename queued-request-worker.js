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

/**
 * queue-request-worker.
 *
 * This module implements a web worker that queues http requests to ensure that the requests are handled
 * sequentially.
 *
 */
const fs = require('original-fs');
const fs_asar = require('fs');
const os = require('os');
const path = require('path');

const QUEUE_DIR = `${os.tmpdir()}/quickscan-queue`;
const TIMEOUT = 60000;
const MAX_RETRIES = 3;
const RETRY_MAP = {};

var RUNNING = 0;
var CHUNK_SIZE = 50;

let TIMESTAMP = "quickscan-lite" + "1.2.3" + "05.18.21";

onmessage = (e) => {
  

  CHUNK_SIZE = e.data.chunk;
  next();
};

function next() {
  if (RUNNING) {
    return;
  }
  const files = fs.readdirSync(QUEUE_DIR);
  if (files.length > 0) {
    let file = files.sort()[0];
    var filepath = path.join(QUEUE_DIR, file);
    let json = JSON.parse(fs.readFileSync(filepath));
    scan_wfp(json.wfp, json.counter, filepath);
  }
}

function scan_wfp (wfp, counter, file, context) {
  RUNNING = 1;
  const data = new FormData();
  data.append('filename', new Blob([wfp]), 'data.wfp');
  data.append('client',new Blob([TIMESTAMP]));
  if (context) {
    data.append('context', context);
  }
  Promise.race([
    fetch('https://osskb.org/api/scan/direct', {
      method: 'post',
      body: data,
    }),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Timeout')), TIMEOUT)
    ),
  ])
    .then((response) => {
      if (response.ok) {
        return response.text();
      } else {
        throw response;
      }
    })
    .then((responseBodyAsText) => {
      try {
        
        // remove all trailing commas
        let regex = /\,(?!\s*?[\{\[\"\'\w])/g;
        responseBodyAsText = responseBodyAsText.replace(regex, ''); 

        const bodyAsJson = JSON.parse(responseBodyAsText);
        return bodyAsJson;
      } catch (e) {
        console.log('Unparseable body: ' + responseBodyAsText);
        
        //Throw an error if the JSON is not parseable.
        //It is catched on the promises chain and then scan_worker.onerror is called.
        throw e;
      }
    })
    .then((json) => {
      postMessage({ wfp: wfp, json: json, counter: counter });
      RUNNING = 0;
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
      if (file in RETRY_MAP) {
        delete RETRY_MAP[file];
      }
      next();
    })
    .catch((e) => {
      RUNNING = 0;
      if (e.message === 'Timeout') {
        if (!(file in RETRY_MAP)) {
          RETRY_MAP[file] = 0;
        }
        if (RETRY_MAP[file] <= MAX_RETRIES) {
          RETRY_MAP[file]++;
          next();
        } else {
          setTimeout(() => {
            throw e;
          });
        }
      } else {
        setTimeout(() => {
          throw e;
        });
      }
    });
}
