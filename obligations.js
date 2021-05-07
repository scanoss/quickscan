var licenses_name = [];
var obligations = []
var index = 0;


onmessage = (e) => {
    
  obligations.length =0 //Clean the array 	
  e.data.forEach(element => {
    licenses_name.push(element);
  });

  fetch_licenses_obligations(); //Start the fetch machine :)

};







function fetch_licenses_obligations () {
    console.log(`${licenses_name[index]} index: ${index}`);
    fetch(`https://osskb.org/api/license/obligations/${licenses_name[index]}`)
    .then((response) => {
        if (response.ok) {
        return response.text();
        } else {
        throw response;
        }
    })
    .then((responseBodyAsText) => {

        // remove all trailing commas
        let regex = /\,(?!\s*?[\{\[\"\'\w])/g;
        responseBodyAsText = responseBodyAsText.replace(regex, ''); 

        const bodyAsJson = JSON.parse(responseBodyAsText);
        
        //Append the JSON only if there is an obligation.
        //Otherwise JSON is discarded
        nameKey = Object.keys(bodyAsJson)[0];
        let obligation = bodyAsJson[nameKey];
        if (obligation.length)
            obligations.push(bodyAsJson);

        //Once all the licenses has been requested post the message with all the obligations.
        if(index>=(licenses_name.length-1)) {
            postMessage(obligations);
        }else{
            index++;
            fetch_licenses_obligations ();
        }
    })
    .catch((e) => {
        throw e;        
    });
};

