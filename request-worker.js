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
const Queue = require('smart-request-balancer');
const fs = require('fs');
const os = require('os');

var CHUNK_SIZE = 10;

onmessage = (e) => {
  CHUNK_SIZE = e.data.chunk;
  scan_wfp(e.data.wfp, e.data.counter);
};

const queue = new Queue({
  rules: {
    common: {
      rate: 1, // Allow to send N messages
      limit: 1, // per X second
      priority: 1, // Rule priority. The lower priority is, the higher chance that
      // this rule will execute faster
    },
  },
  retryTime: 30, // Default retry time. Can be configured in retry fn
  ignoreOverallOverheat: true, // Should we ignore overheat of queue itself
});

function scan_wfp(wfp, counter) {
  const data = new FormData();
  data.append('filename', new Blob([wfp]), 'data.wfp');
  var requestHandler = (retry) => {
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
      })
      .catch((error) => {
        console.log(error);
        if (error.status && error.status == 429) return retry(5);
      });
  };

  queue
    .request(requestHandler, '', 'common')
    .catch((error) => console.error(error));
}
