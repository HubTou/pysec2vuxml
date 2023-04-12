# pysec2vuxml
## Bugs to correct
* In [pipinfo](https://github.com/HubTou/pipinfo):
  * Caching empty json files for "HTTP 404: Not Found" errors does not work
  * A way to suppress warnings for "HTTP 404: Not Found" errors would be useful
  * Understanding why these packages/versions are not found with the PyPI API

## Limitations to be removed
* Noticing a vulnerability is already reported to VuXML when there is no associated CVE
  * Use the URL tags:
```XML
<references>
  <url>URL</url>
</references>
```

## New features
* Fetching the discovery date from the CVE published date for given entry at [CVE Details](https://www.cvedetails.com/)

## Other possible features
* Downloading the latest version of the Ports index instead of relying on an up-to-date ports tree:
  * [https://download.freebsd.org/ftp/ports/index/INDEX-13](https://download.freebsd.org/ftp/ports/index/INDEX-13)
  * However, this wouldn't help having up to date Makefiles for the ports...
