# pysec2vuxml
## What is it?
It's a Python script (not a package for once) written for mass checking Python packages [FreeBSD ports](https://www.freshports.org/) for PYSEC vulnerabilities and reporting in [FreeBSD VuXML](https://www.vuxml.org/freebsd/index.html) port vulnerabilities database.

It uses my [pipinfo](https://github.com/HubTou/pipinfo) and [vuxml](https://github.com/HubTou/vuxml) Python packages.

## How to install and use?
Install pre-requisites once:
```
pip install pnu-pipinfo
pip install pnu-vuxml
chmod a+x pysec2vuxml.py
```

Then launch the script:
```
pysec2vuxml.py
```

The execution will take some time in order to call the [Python Packaging Authority's web service for checking vulnerabilities](https://warehouse.pypa.io/api-reference/json.html#known-vulnerabilities) for each of the 4.000+ FreeBSD Python packages ports.
The web service results are cached and reused for 1 day.

## Results
Out of the current versions of 4.075 Python packages FreeBSD ports, 364 weren't found in the [PyPA](https://www.pypa.io/en/latest/)'s web service, and 45 vulnerable ports were identified.
None of those 45 vulnerable ports were already reported in FreeBSD VuXML port vulnerabilities database.

The file [results.txt](https://github.com/HubTou/pysec2vuxml/blob/main/results.txt) contains the script output on my last run.

The file [vuxml_newentries.txt](https://github.com/HubTou/pysec2vuxml/blob/main/vuxml_newentries.txt) contains the beginning of VuXML new entries for the vulnerable ports identified.

## Helping the security team
**I need help converting the above results in new VuXML port entries!**

You can get a [quick introduction to the VuXML format](https://docs.freebsd.org/en/books/porters-handbook/security/#security-notify-vuxml-intro) in the [FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/).

The structure that needs to be filed for each of these 45 vulnerabilities is:
```xml
  <vuln vid="INSERT UUID HERE">
    <topic>INSERT PORT NAME HERE -- INSERT VULNERABILITY SUMMARY HERE</topic>
    <affects>
      <package>
    <name>INSERT PORT NAME HERE</name>
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

You can obtain a new UUID by running the [uuidgen](https://man.freebsd.org/cgi/man.cgi?query=uuidgen) command without parameter.

Or you can get full assistance for [making and validating new entries](https://docs.freebsd.org/en/books/porters-handbook/security/#security-notify-vuxml-testing) with the scripts included in the [vuxml](https://www.freshports.org/security/vuxml/) FreeBSD port.

If you produce one or more of these new entries please clone this repository and [submit pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request), and/or directly send your entries to  the FreeBSD Ports Security Team at <ports-secteam@FreeBSD.org>.
