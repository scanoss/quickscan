# SCANOSS Quickscan


## What is SCANOSS Quickscan?
It is a tool that demonstrates scanning source code against <a href="https://osskb.org">osskb.org</a>.
SCANOSS Quickscan scans source code against a knowledge base representing the entire OSS community. The results of the scan contain OSS matches
(full file or snippet) of the scanned code against OSS components.


## How does it work? 
Select a folder containing source code files and the application will generate fingerprints and send them to the OSSKB API for scanning. It is important to stress that no source code is sent to the osskb.org API. The client extracts hashes from the source code using an open source algorithm. A good explanation of the algorithm as well as an implementation can be found here: 
[https://github.com/scanoss/wfp](https://github.com/scanoss/wfp).

Quickscan will show a simple visualisation that represents the data contained in the scan results. If you
click on a segment in the licenses chart, you will be presented with a table containing the list of components where a particular license has been detected.
Similarly, if you click on a severity in the vulnerability chart, you will see the components affected by vulnerabilites with the selected severity.
        
You can also download the full report of the scan in CSV format, via the "DOWNLOAD REPORT" button on the top
right corner.


## About the results

The results of the scan support building a [Software Bill of Materials (SBOM)](https://en.wikipedia.org/wiki/Software_bill_of_materials) of a
software product. The SBOM describes the list of software components in a product. They can also provide additional information
that can help evaluate the use of the component. 
 
The CSV Report provided by SCANOSS Quickscan should be considered as a <i>draft</i> SBOM.
 
Each OSS component match provided by osskb.org contains the following metadata:

- Component identification (vendor, component, version, url...)
- License identifications
- Copyright notices
- Vulnerabilities
  
## Next Steps

For an enhanced scanning experience with richer results, visit [https://scanoss.com](https://scanoss.com)