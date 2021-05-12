// This file is (mostly) Copyright Cozy Labs
// taken from https://github.com/cozy-labs/cozy-desktop
const path = require('path');
const fs = require('fs');
const util = require('util');

const renameAsync = util.promisify(fs.rename);
const unlinkAsync = util.promisify(fs.unlink);

module.exports = async function (context) {
  // Replace the app launcher on linux only.
  if (process.platform !== 'linux') {
    return;
  }
  // eslint-disable-next-line no-console
  console.log('afterPack hook triggered', context);

};
