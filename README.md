# pysec2vuxml
## What is it?
It's a Python script (not a package for once) written for mass checking Python packages [FreeBSD ports](https://www.freshports.org/) for PYSEC vulnerabilities and reporting in [FreeBSD VuXML](https://www.vuxml.org/freebsd/index.html) port vulnerabilities database.

It uses my [pipinfo](https://github.com/HubTou/pipinfo) and [vuxml](https://github.com/HubTou/vuxml) Python packages.

## How to install and use?
Install pre-requisites once:
```
portsnap fetch extract # You need superuser rights to install the ports tree
pip install pnu-pipinfo
pip install pnu-vuxml
chmod a+x pysec2vuxml.py
```

Then launch the script:
```
portsnap fetch update # You need superuser rights to update the ports index and the port tree
pysec2vuxml.py | tee results.txt
```

The execution will take some time in order to call the [Python Packaging Authority's web service for checking vulnerabilities](https://warehouse.pypa.io/api-reference/json.html#known-vulnerabilities) for each of the 4.000+ FreeBSD Python packages ports.
The web service results are cached and reused for 1 day.

## Results
On the first run, out of the current versions of 4.075 Python packages FreeBSD ports, 364 weren't found in the [PyPA](https://www.pypa.io/en/latest/)'s web service, and 45 vulnerable ports were identified.
None of those 45 vulnerable ports were already reported in FreeBSD VuXML port vulnerabilities database.

The file [results.txt](https://github.com/HubTou/pysec2vuxml/blob/main/results.txt) contains the script output of a recent run as an example.

The files [vuxml_new_entries.xml](https://github.com/HubTou/pysec2vuxml/blob/main/vuxml_new_entries.xml) and [vuxml_modified_entries.xml](https://github.com/HubTou/pysec2vuxml/blob/main/vuxml_modified_entries.xml) respectively contain new and modified VuXML entries for the vulnerable ports identified.

## Reporting new vulnerabilities to the security team
You can get a [quick introduction to the VuXML format](https://docs.freebsd.org/en/books/porters-handbook/security/#security-notify-vuxml-intro) in the [FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/).

The structure that needs to be filled for each vulnerability is:
```xml
  <vuln vid="INSERT UUID HERE">
    <topic>py-PACKAGE_NAME -- INSERT VULNERABILITY SUMMARY HERE</topic>
    <affects>
      <package>
    <name>py37-PORT_NAME</name>
    <name>py38-PORT_NAME</name>
    <name>py39-PORT_NAME</name>
    <name>py310-PORT_NAME</name>
    <name>py311-PORT_NAME</name>
    <range><lt>INSERT VULNERABLE VERSION HERE</lt></range>
      </package>
    </affects>
    <description>
      <body xmlns="http://www.w3.org/1999/xhtml">
    <p>INSERT SOURCE NAME HERE reports:</p>
    <blockquote cite="INSERT SOURCE URL HERE">
      <p>INSERT DESCRIPTION HERE</p>
    </blockquote>
      </body>
    </description>
    <references>
      <cvename>INSERT CVE RECORD IF AVAILABLE</cvename>
      <url>INSERT BLOCKQUOTE URL HERE</url>
    </references>
    <dates>
      <discovery>YEAR-MONTH-DAY</discovery>
      <entry>YEAR-MONTH-DAY</entry>
    </dates>
  </vuln>
```

**pysec2vuxml** will automatically generate most of this structure for each vulnerability that is not withdrawn, ignored (if its ID is present in the [ignore.txt](https://github.com/HubTou/pysec2vuxml/blob/main/ignore.txt) file) or already reported in FreeBSD VuXML.

**You**'ll have to complete a few remaining fields (vuln summary, vuln discoverer), check some of them (affected versions and port name) and verify all the vulnerabilities for a given port to see if they can be factored (check vuln vid "e4181981-ccf1-11ed-956f-7054d21a9e2a" in [vuxml_new_entries.xml](https://github.com/HubTou/pysec2vuxml/blob/main/vuxml_new_entries.xml) for a good example).

Then, if you have superuser access, put your new or modified entries into **/usr/ports/security/vuxml/vuln** and use the [vuxml](https://www.freshports.org/security/vuxml/) FreeBSD port to [verify if everything is correct](https://docs.freebsd.org/en/books/porters-handbook/security/#security-notify-vuxml-testing):
```Shell
cd /usr/ports/security/vuxml
make validate
```

If it's the case, please clone this repository and [submit pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request) to the [vuxml_new_entries.xml](https://github.com/HubTou/pysec2vuxml/blob/main/vuxml_new_entries.xml) and [vuxml_modified_entries.xml](https://github.com/HubTou/pysec2vuxml/blob/main/vuxml_modified_entries.xml) files, and/or directly create [FreeBSD bug reports](https://bugs.freebsd.org/bugzilla/enter_bug.cgi?product=Ports%20%26%20Packages&component=Individual%20Port%28s%29) with your entries, using a title starting with **security/vuxml:** and adding the **security** keyword.

If you don't want to see VuXML entries proposals for vulnerabilities that have been reported but are not yet committed to the FreeBSD files, you can add their IDs in the [reported.txt](https://github.com/HubTou/pysec2vuxml/blob/main/reported.txt) file.

## House cleaning
The tool downloads and caches files in the following directories, which you can remove if you want:
```
$HOME/.cache/cve
$HOME/.cache/pipinfo
$HOME/.cache/vuxml
```
