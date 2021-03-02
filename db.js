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
const sqlite3 = require('sqlite3').verbose()

const CREATE_TABLE_STATUS = "create table if not exists status (status text, message text, created timestamp, total integer default 0, scanned integer default 0);"
const CREATE_TABLE_FILES = "create table if not exists files (id integer primary key asc, path text, scanned integer default 0);"
const CREATE_TABLE_RESULTS =
  'create table if not exists results (id integer primary key asc, source text, vendor text, component text, version text, latest text, url text, lines text, oss_lines text, matched text, file text, idtype text, file_id text, component_id text, elapsed text);';
const CREATE_TABLE_RESULT_VULNS = 'create table if not exists result_vulns (id integer primary key asc, resultid integer not null, vuln_id text, cve text, severity text, reported text, introduced text, patched text, summary text, source text);'
const CREATE_TABLE_RESULT_LICS = 'create table if not exists result_lics (id integer primary key asc, resultid integer not null, name text, source text);'
const CREATE_TABLE_RESULT_COPYS =
  'create table if not exists result_copys (id integer primary key asc, resultid integer not null, name text, source text);';


class ScanDB {

  constructor(filename) {
    this.filename = filename;
    this.db = new sqlite3.Database(filename)
  }

  create () {
    this.db.exec(CREATE_TABLE_FILES);
    this.db.exec(CREATE_TABLE_RESULTS);
    this.db.exec(CREATE_TABLE_RESULT_COPYS);
    this.db.exec(CREATE_TABLE_RESULT_VULNS);
    this.db.exec(CREATE_TABLE_RESULT_LICS);
    this.db.exec(CREATE_TABLE_STATUS);
  }

  close () {
    this.db.close()
  }

  fileInsert (path) {
    this.db.exec(`insert into files (path) values (${path});`)
  }

  fileScanned (path) {
    this.db.exec(`update files set scanned=1 where path=${path}`)
  }

  resultInsert (result) {
    this.db.exec(
      `insert into results (fileid,vendor,component,version,latest_version, license, url, lines, oss_lines, matched, filename, size, idtype, md5_file, md5_comp) values 
      (${result.fileid},${result.vendor},${result.component},${result.version},${result.latest_version},${result.license},${result.url},${result.lines},${result.oss_lines},${result.matched},${result.filename},${result.size},${result.idtype},${result.md5_file},${result.md5_comp});`
    );
  }
  
}
