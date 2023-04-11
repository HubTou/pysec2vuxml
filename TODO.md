# pysec2vuxml
## Bugs to correct
* **Use py-PACKAGE for topic tag**
* **Use py37-PACKAGE, py38-PACKAGE, py39-PACKAGE, py310-PACKAGE, py311-PACKAGE for name tag**
* **Replacing &lt; and &gt; characters by their & escaped equivalent**

* In pipinfo:
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
* **Checking if a CVE is already reported for any other port name**
* **Fetching the discovery date from the CVE published date** 

## Other possible features
* Downloading the latest version of the Ports index instead of relying on an up-to-date ports tree:
  * [https://download.freebsd.org/ftp/ports/index/INDEX-13](https://download.freebsd.org/ftp/ports/index/INDEX-13)
