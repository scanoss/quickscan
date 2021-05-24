const MAX_FILES = 10000;

const winnowing = require ('./winnowing.js');
const path = require('path');
const fs = require('original-fs');


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




module.exports = {
    countFiles,
    getFileExtention,
    getWfpFromFile,
    countFilesOnWFP,
    MAX_FILES,
  };