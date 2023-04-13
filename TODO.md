# pysec2vuxml
## Improvements
* Writing some label to indicate when a reported vulnerability is for another port name

## Bugs to correct
* In [pipinfo](https://github.com/HubTou/pipinfo):
  * Caching empty json files for "HTTP 404: Not Found" errors does not work

## Limitations to be removed
* Noticing a vulnerability is already reported to VuXML when there is no associated CVE
  * Use the URL tags:
```XML
<references>
  <url>URL</url>
</references>
```
* In [pipinfo](https://github.com/HubTou/pipinfo):
  * Understanding why some packages/versions are not found with the PyPI API

## New features
* Fetching the discovery date from the CVE published date for given entry at [CVE Details](https://www.cvedetails.com/)
* Listing the existing flavours for each package
* In [pipinfo](https://github.com/HubTou/pipinfo):
  * A way to suppress warnings for "HTTP 404: Not Found" errors would be useful

## Other possible features
* Command line options. For example:
  * To print either the summary, the vulnerabilities found with/without the VuXML skeleton entries 
* Downloading the [latest version of the Ports index](https://download.freebsd.org/ftp/ports/index/INDEX-13) instead of relying on an up-to-date ports tree:
  * This wouldn't help having up to date Makefiles for the ports...
  * But it would be a first step in helping pysec2vuxml to run on non FreeBSD systems
