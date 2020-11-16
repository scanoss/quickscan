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
const path = require('path');

const QUEUE_DIR = `${os.tmpdir()}/quickscan-queue`;

var RUNNING = 0;
var CHUNK_SIZE = 10;

onmessage = (e) => {
  CHUNK_SIZE = e.data.chunk;
  queue_scan(e.data.wfp, e.data.counter);
};

function queue_scan(wfp, counter) {
  if (!fs.existsSync(QUEUE_DIR)) {
    fs.mkdirSync(QUEUE_DIR);
  }
  let filename = `${QUEUE_DIR}/${new Date().getTime()}.json`;
  console.log('Add to queue: ' + filename);
  fs.writeFileSync(filename, JSON.stringify({ wfp: wfp, counter: counter }));
  next();
}

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

function scan_wfp(wfp, counter, file) {
  RUNNING = 1;
  const data = new FormData();
  data.append('filename', new Blob([wfp]), 'data.wfp');

  fetch('https://osskb.org/api/scan/direct', {
    method: 'post',
    body: data,
  })
    .then((response) => {
      if (response.ok) {
        return response.text();
      } else {
        throw response;
      }
    })
    .then((responseBodyAsText) => {
      try {
        const bodyAsJson = JSON.parse(responseBodyAsText);
        return bodyAsJson;
      } catch (e) {
        console.log('Unparseable body: ' + responseBodyAsText);
        Promise.reject({ body: responseBodyAsText, type: 'unparseable' });
      }
    })
    .then((json) => {
      postMessage({ wfp: wfp, json: json, counter: counter });
      RUNNING = 0;
      fs.unlinkSync(file);
      next();
    })
    .catch((error) => {
      RUNNING = 0;
      console.log(error);
      next();
    });
}
