# pysec2vuxml
## Things to investigate
* Correct way to declare vulnerability for a Python package? Between:
  * package
  * py-package
  * py39-package
  * py3*-package

## Bugs to correct
* In pipinfo:
  * Caching empty json files for "HTTP 404: Not Found" errors does not work
  * A way to suppress warnings for "HTTP 404: Not Found" errors would be useful
  * Understanding why these packages/versions are not found with the PyPI API
  * Only the first package for a given name is taken into account. For example:
```Shell
$ cut -d"|" -f1 /usr/ports/INDEX-13 | grep setuptools
py311-setuptools-63.1.0 # entry for setuptools
py37-setuptools-63.1.0
py310-setuptools-63.1.0
py38-setuptools-63.1.0
py39-setuptools-63.1.0
py27-setuptools44-44.1.1 # entry for setuptools44
py38-setuptools58-58.5.3_2 # entry for setuptools58
py37-setuptools58-58.5.3_2
py311-setuptools58-58.5.3_2
py310-setuptools58-58.5.3_2
py39-setuptools58-58.5.3_2
```

## Limitations to be removed
* Noticing a vulnerability is already reported to VuXML when there is no associated CVE
  * Use the URL tags:
```XML
<references>
  <url>URL</url>
</references>
```

## New features

## Other possible features
* Downloading the latest version of the Ports index instead of relying on an up-to-date ports tree:
  * [https://download.freebsd.org/ftp/ports/index/INDEX-13](https://download.freebsd.org/ftp/ports/index/INDEX-13)

