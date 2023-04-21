#!/usr/bin/env python3
""" pysec2vuxml - Mass checking FreeBSD Python packages ports for PYSEC vulnerabilities and reporting in FreeBSD VuXML
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import datetime
import json
import os
import re
import sys
import urllib.request
import uuid

import pipinfo  # pip install pnu-pipinfo
import vuxml    # pip install pnu-vuxml

# Flavours range for generated VuXML entries:
MAJOR_VERSION=3
FIRST_MINOR_VERSION=7
LAST_MINOR_VERSION=11

# The FreeBSD ports list
PORTS_INDEX = "/usr/ports/INDEX-13"


####################################################################################################
def get_freebsd_ports_list():
    """ Returns a list of FreeBSD ports """
    ports_list = []

    # Is the ports list installed?
    if not os.path.isfile(PORTS_INDEX):
        print("Please install and update the ports tree ('portsnap fetch extract' as root)", file=sys.stderr)
        sys.exit(1)

    # Loading the ports list:
    with open(PORTS_INDEX, encoding='utf-8', errors='ignore') as file:
        lines = file.read().splitlines()

    for line in lines:
        # The file format is described at: https://wiki.freebsd.org/Ports/INDEX
        fields = line.split('|')
        if len(fields) != 13:
            print(f"WARNING: line '{line}' from '{PORTS_INDEX}' doesn't have 13 fields", file=sys.stderr)
        else:
            # {"vname": versioned_name, "dir": port_directory}
            ports_list.append({"vname": fields[0], "dir": fields[1]})

    return ports_list


####################################################################################################
def _is_python_package(element):
    """ Returns True if ports name starts with py2 or py3 """
    return re.match("py[23][0-9]+-", element["vname"]) is not None


####################################################################################################
def select_python_ports(ports_list):
    """ Filters out FreeBSD ports that are not Python packages """
    return list(filter(_is_python_package, ports_list))


####################################################################################################
def enrich_ports_list(ports_list):
    """ Try to get additional info from the port's Makefile """
    enriched_ports_list = []

    for port in ports_list:
        # Loading the port makefile:
        port_makefile = port["dir"] + os.sep + 'Makefile'
        if os.path.isfile(port_makefile):
            with open(port_makefile, encoding='utf-8', errors='ignore') as file:
                lines = file.read().splitlines()
        else:
            lines = []

        # Searching for PORTNAME=, PORTVERSION=, DISTVERSION=, WWW= and COMMENT= lines:
        name = ''
        version = ''
        maintainer = ''
        www = ''
        comment = ''
        for line in lines:
            line = re.sub(r'[ 	]*#.*', '', line)
            if line.startswith('PORTNAME='):
                name = re.sub(r'^PORTNAME=[ 	]*', '', line)
            elif line.startswith('PORTVERSION='):
                version = re.sub(r'^PORTVERSION=[ 	]*', '', line)
            elif line.startswith('DISTVERSION='):
                version = re.sub(r'^DISTVERSION=[ 	]*', '', line)
            elif line.startswith('MAINTAINER='):
                maintainer = re.sub(r'^MAINTAINER=[ 	]*', '', line)
            elif line.startswith('WWW='):
                www = re.sub(r'^WWW=[ 	]*', '', line)
            elif line.startswith('COMMENT='):
                comment = re.sub(r'^COMMENT=[ 	]*', '', line)

        if not name or not version or "$" in name or "$" in version:
            simplified_vname = re.sub(r",[0-9]*$", "", port["vname"]) # remove ,PORTEPOCH
            simplified_vname = re.sub(r"_[0-9]*$", "", simplified_vname) # remove _PORTREVISION
            name = re.sub(r"-[0-9.pg+]+$", "", simplified_vname)
            version = re.sub(r"" + name + "-", "", simplified_vname)
            name = re.sub(r"^py[0-9]+-", "", name)

        if '$' in www:
            www = ''
        elif www.endswith('/'):
            www = re.sub(r"/$", "", www)
        elif www.endswith('/ \\'):
            www = re.sub(r"/ \\$", "", www)
        elif www.endswith('\\'):
            www = re.sub(r"\\$", "", www)

        enriched_ports_list.append(
            {
                "vname": port["vname"],
                "dir": port["dir"],
                "name": name,
                "version": version,
                "maintainer": maintainer,
                "www": www,
                "comment": comment,
            }
        )

    return enriched_ports_list


####################################################################################################
def get_ids_from_file(filename):
    """ Load a list of vulnerabilities IDs to ignore """
    lines = []

    if os.path.isfile(filename):
        with open(filename, encoding='utf-8', errors='ignore') as file:
            lines = file.read().splitlines()

    # Return all non empty lines not starting with a '#' comment character
    return [line for line in lines if line and not line.startswith('#')]


####################################################################################################
def get_caching_directory(name):
    """ Find and create a directory to save cached files """
    directory = ''

    if os.name == 'nt':
        if 'LOCALAPPDATA' in os.environ:
            directory = os.environ['LOCALAPPDATA'] + os.sep + "cache" + os.sep + name
        elif 'TMP' in os.environ:
            directory = os.environ['TMP'] + os.sep + "cache" + os.sep + name

    else: # os.name == 'posix':
        if 'HOME' in os.environ:
            directory = os.environ['HOME'] + os.sep + ".cache" + os.sep + name
        elif 'TMPDIR' in os.environ:
            directory = os.environ['TMPDIR'] + os.sep + ".cache" + os.sep + name
        elif 'TMP' in os.environ:
            directory = os.environ['TMP'] + os.sep + ".cache" + os.sep + name

    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            directory = ''

    return directory


####################################################################################################
def get_cve_publication_date(cve):
    """ Get the publication date for a given CVE from the Mitre web service """
    publication_date = ''

    caching_dir = get_caching_directory('cve')
    caching_file = ''
    if caching_dir:
        caching_file = caching_dir + os.sep + f"{cve}.json"

    # If there's a caching file, read it instead of using the Web service
    # As we only need the publication date which should never change, there's no need to refresh the cached file
    if os.path.isfile(caching_file):
        with open(caching_file, "rb") as file:
            json_data = file.read()
    else:
        # Using the new Mitre CVE API
        url = f'https://cveawg.mitre.org/api/cve/{cve}'
        try:
            with urllib.request.urlopen(url) as http:
                json_data = http.read()
        except urllib.error.HTTPError as error:
            print(f"Error while fetching '{url}': {error}", file=sys.stderr)
            if error == 'HTTP Error 404: Not Found':
                # Let's write an empty file to avoid retrying later...
                if caching_file:
                    with open(caching_file, "wb") as file:
                        pass
            return ''

        if caching_file:
            with open(caching_file, "wb") as file:
                file.write(json_data)

    data = json.loads(json_data)
    if 'cveMetadata' in data:
        if 'datePublished' in data['cveMetadata']:
            publication_date = re.sub(r"T.*$", "", data['cveMetadata']['datePublished'])

    return publication_date


####################################################################################################
def print_table_of_contents(python_ports, vulnerable_ports, ignored_vulns):
    """ Print a table of contents to stdout """
    contents = []
    longuest_package = len('Package')
    longuest_subdir = len('Port path')
    longuest_name = len('Port name')
    longuest_version = len('Port version')
    longuest_maintainer = len('Maintainer')
    longuest_vulnerabilities = len('Vulns')

    # About (Python) packages and (FreeBSD) ports:
    # For example:
    #   package_name = rencode     package_version = 1.0.6
    #   port_name = py39-rencode   port_version = 1.0.6_1
    false_positive = 0
    for package_name, package_info in vulnerable_ports.items():
        for package_version, package_vulns in package_info.items():
            # Try to find the corresponding (FreeBSD) port:
            found = False
            port_vname = ''
            port_name = ''
            port_version = ''
            port_subdir = ''
            port_maintainer = ''
            for port in python_ports:
                if port['name'] == package_name and port['version'] == package_version:
                    found = True
                    port_vname = port['vname']
                    port_name = re.sub(r"-[0-9pg.+,_]*$", "", port_vname)
                    port_version = re.sub(r"^" + port_name + "-", "", port_vname)
                    port_subdir = port['dir'].replace('/usr/ports/', '')
                    port_maintainer = port['maintainer']
                    break
            if not found:
                print(f"Python package '{package_name}-{package_version}' not found in the FreeBSD ports tree!", file=sys.stderr)
                continue

            # How many unignored and unwithdrawn vulnerabilities do we have?
            vulnerabilities = 0
            for vulnerability in package_vulns:
                ignore_vuln = False
                if vulnerability['id'] in ignored_vulns:
                    ignore_vuln = True
                for alias in vulnerability['aliases']:
                    if alias in ignored_vulns:
                        ignore_vuln = True
                        break

                if not ignore_vuln and vulnerability['withdrawn'] is None:
                    vulnerabilities += 1

            if not vulnerabilities:
                false_positive += 1
                continue

            if len(package_name) > longuest_package:
                longuest_package = len(package_name)
            if len(port_subdir) > longuest_subdir:
                longuest_subdir = len(port_subdir)
            if len(port_name) > longuest_name:
                longuest_name = len(port_name)
            if len(port_version) > longuest_version:
                longuest_version = len(port_version)
            if len(port_maintainer) > longuest_maintainer:
                longuest_maintainer = len(port_maintainer)
            if len(str(vulnerabilities)) > longuest_vulnerabilities:
                longuest_vulnerabilities = len(str(vulnerabilities))

            contents.append(
                {
                    "package": package_name,
                    "subdir": port_subdir,
                    "name": port_name,
                    "version": port_version,
                    "maintainer": port_maintainer,
                    "vulnerabilities": vulnerabilities,
                }
            )

    print("-" * (longuest_vulnerabilities + longuest_package + longuest_subdir + longuest_name + longuest_version + longuest_maintainer + 5))
    print(f"{'Vulns':{longuest_vulnerabilities}} "
          + f"{'Package':{longuest_package}} "
          + f"{'Port path':{longuest_subdir}} "
          + f"{'Port name':{longuest_name}} "
          + f"{'Port version':{longuest_version}} "
          + f"{'Maintainer':{longuest_maintainer}}"
    )
    print("-" * (longuest_vulnerabilities + longuest_package + longuest_subdir + longuest_name + longuest_version + longuest_maintainer + 5))
    vulnerabilities_count = 0
    for content in contents:
        print(f"{str(content['vulnerabilities']):{longuest_vulnerabilities}} "
              + f"{content['package']:{longuest_package}} "
              + f"{content['subdir']:{longuest_subdir}} "
              + f"{content['name']:{longuest_name}} "
              + f"{content['version']:{longuest_version}} "
              + f"{content['maintainer']:{longuest_maintainer}}"
        )
        vulnerabilities_count += content['vulnerabilities']
    print("=" * (longuest_vulnerabilities + longuest_package + longuest_subdir + longuest_name + longuest_version + longuest_maintainer + 5))
    print(f"Python packages's FreeBSD ports = {len(python_ports)}")
    print(f"  vulnerable ports              = {len(vulnerable_ports) - false_positive}")
    print(f"  vulnerable ports/version      = {len(contents)}")
    print(f"    vulnerabilities             = {vulnerabilities_count}")
    print("-" * (longuest_vulnerabilities + longuest_package + longuest_subdir + longuest_name + longuest_version + longuest_maintainer + 5))


####################################################################################################
def print_vulnerabilities(python_ports, vulnerable_ports, ignored_vulns, reported_vulns, vuxml_data):
    """ Print vulnerabilities to stdout """
    today = datetime.date.today()
    today_string = f"{today.year}-{today.month:02}-{today.day:02}"

    # About (Python) packages and (FreeBSD) ports:
    # For example:
    #   package_name = rencode     package_version = 1.0.6
    #   port_name = py39-rencode   port_version = 1.0.6_1
    print()
    for package_name, package_info in vulnerable_ports.items():
        for package_version, package_vulns in package_info.items():
            # Try to find the corresponding (FreeBSD) port:
            found = False
            port_vname = ''
            port_name = ''
            port_version = ''
            port_subdir = ''
            port_maintainer = ''
            port_www = ''
            for port in python_ports:
                if port['name'] == package_name and port['version'] == package_version:
                    found = True
                    port_vname = port['vname']
                    port_name = re.sub(r"-[0-9pg.+,_]*$", "", port_vname)
                    port_version = re.sub(r"^" + port_name + "-", "", port_vname)
                    port_subdir = port['dir'].replace('/usr/ports/', '')
                    port_maintainer = port['maintainer']
                    port_www = port['www']
                    port_comment = port['comment']
                    break
            if not found:
                print(f"Python package '{package_name}-{package_version}' not found in the FreeBSD ports tree!", file=sys.stderr)
                continue

            print("-" * 80)
            print(f"Python package '{package_name} {package_version}' / FreeBSD port '{port_name} {port_version}' is vulnerable:")
            print(f"  Please report to  maintainer '{port_maintainer}' for port '{port_subdir}'")
            print("-" * 80)
            print("Flavours and versions detection")
            print("Similar names, with (=W) for same WWW site and/or (=C) for same description:")
            for port in python_ports:
                if re.match(r'py[23][0-9]+-' + package_name, port['vname']) is not None:
                    same_www = False
                    same_comment = False
                    if port_www and port['www'] == port_www:
                        same_www = True
                    if port_comment and port['comment'] == port_comment:
                        same_comment = True
                    if same_www or same_comment:
                        print(f"  {port['vname']}", end="")
                        if same_www:
                            print(" (=W)", end="")
                        if same_comment:
                            print(" (=C)", end="")
                        print()
            print("-" * 80)
            print()

            for vulnerability in package_vulns:
                ignore_vuln = False
                if vulnerability['id'] in ignored_vulns:
                    ignore_vuln = True
                for alias in vulnerability['aliases']:
                    if alias in ignored_vulns:
                        ignore_vuln = True
                        break
                if ignore_vuln:
                    print("=> Package ignored (this vulnerability doesn't apply to FreeBSD)\n")
                    continue

                print("PYSEC vulnerability:")
                print(f"  Id:        {vulnerability['id']}")
                if vulnerability['aliases']:
                    print(f"  Aliases:   {vulnerability['aliases']}")
                print("  Details:   ", end="")
                # We print around 120 characters of details, skipping blank lines
                characters_count = 0
                for line in vulnerability['details'].splitlines():
                    line = re.sub(r"^[ 	]*$", "", line)
                    if line:
                        print(line, end="")
                    characters_count += len(line)
                    if characters_count > 120:
                        print(" +++")
                        break
                    else:
                        print()
                if vulnerability['fixed_in']:
                    print(f"  Fixed in:  {vulnerability['fixed_in']}")
                print(f"  Link:      {vulnerability['link']}")
                print(f"  Source:    {vulnerability['source']}")
                if vulnerability['summary'] is not None:
                    print(f"  Summary:   {vulnerability['summary']}")
                if vulnerability['withdrawn'] is not None:
                    print(f"  Withdrawn: {vulnerability['withdrawn']}")
                print()

                # Don't process withdrawn vulnerabilities
                if vulnerability['withdrawn'] is not None:
                    print("=> Vulnerability withdrawn\n")
                    continue

                # Don't process already reported vulnerabilities
                reported_vuln = False
                if vulnerability['id'] in reported_vulns:
                    reported_vuln = True
                for alias in vulnerability['aliases']:
                    if alias in reported_vulns:
                        reported_vuln = True
                        break
                if reported_vuln:
                    print("=> Package vulnerability already reported\n")
                    continue

                # Gather related CVEs (if any)
                cve_list = []
                no_cve = True
                if vulnerability['id'].startswith("CVE"):
                    cve_list.append(vulnerability['id'])
                    no_cve = False
                for alias in vulnerability['aliases']:
                    if alias.startswith("CVE") and alias not in cve_list:
                        cve_list.append(alias)
                        no_cve = False

                # Has this vulnerability already been reported to FreeBSD VuXML for THIS port?
                something_found = False
                if no_cve:
                    # We'll search for a mention of the vulnerability link in references/url
                    vid_list = []
                    vulns = vuxml.search_vulns_by_reference(vuxml_data, 'url', vulnerability['link'])
                    for vid in vulns:
                        if vid not in vid_list:
                            if not something_found:
                                print("=> FreeBSD VuXML vulnerability for THIS port:")
                                something_found = True
                            vuxml.print_vuln(vid, vuxml_data[vid])
                            vid_list.append(vid)
                else:
                    # We search for the CVE gathered in references/cvename
                    vulns = vuxml.search_vulns_by_package(vuxml_data, port_name, package_version)
                    for vid in vulns:
                        if 'references' in vuxml_data[vid]:
                            for reference in vuxml_data[vid]['references']:
                                for key, value in reference.items():
                                    if key == "cvename":
                                        if value in cve_list:
                                            if not something_found:
                                                print("=> FreeBSD VuXML vulnerability for THIS port:")
                                                something_found = True
                                            vuxml.print_vuln(vid, vuxml_data[vid])
                                            cve_list.remove(value)
                    if len(cve_list) > 0:
                        vulns = vuxml.search_vulns_by_package(vuxml_data, port_name, '')
                        for vid in vulns:
                            if 'references' in vuxml_data[vid]:
                                for reference in vuxml_data[vid]['references']:
                                    for key, value in reference.items():
                                        if key == "cvename":
                                            if value in cve_list:
                                                if not something_found:
                                                    print("=> FreeBSD VuXML vulnerability for THIS port:")
                                                    something_found = True
                                                vuxml.print_vuln(vid, vuxml_data[vid])
                                                cve_list.remove(value)

                # Have the remaining CVE been reported to FreeBSD VuXML for ANOTHER port name?
                something_found = False
                vid_list = []
                for cve in cve_list:
                    vulns = vuxml.search_vulns_by_reference(vuxml_data, 'cvename', cve)
                    for vid in vulns:
                        if vid not in vid_list:
                            if not something_found:
                                print("=> FreeBSD VuXML vulnerability for ANOTHER port:")
                                something_found = True
                            vuxml.print_vuln(vid, vuxml_data[vid])
                            vid_list.append(vid)

                # Here is a skeleton entry for the unreported CVE vulnerability
                if len(cve_list) > 0 or no_cve:
                    root_port_name = re.sub(r"^py[0-9]+-", "", port_name)
                    details = vulnerability["details"].replace(">", "&gt;").replace("<", "&lt;")
                    print("=> UNREPORTED FreeBSD VuXML vulnerability skeleton:")
                    print(f'  <vuln vid="{str(uuid.uuid4())}">')
                    if vulnerability['summary'] is None:
                        print(f'    <topic>py-{package_name} -- INSERT_VULNERABILITY_SUMMARY_HERE</topic>')
                    else:
                        print(f'    <topic>py-{package_name} -- {vulnerability["summary"]}</topic>')
                    print( '    <affects>')
                    print( '      <package>')
                    for minor_version in range(FIRST_MINOR_VERSION, LAST_MINOR_VERSION + 1):
                        print(f'    <name>py{MAJOR_VERSION}{minor_version}-{root_port_name}</name>')
                    if len(vulnerability['fixed_in']) == 0:
                        print(f'    <range><le>{port_version}</le></range>')
                    elif len(vulnerability['fixed_in']) == 1:
                        print(f'    <range><lt>{vulnerability["fixed_in"][0]}</lt></range>')
                    else:
                        print( '    <range><lt>INSERT_VULNERABLE_VERSION_HERE</lt></range>')
                    print( '      </package>')
                    print( '    </affects>')
                    print( '    <description>')
                    print( '      <body xmlns="http://www.w3.org/1999/xhtml">')
                    print( '    <p>INSERT_SOURCE_NAME_HERE reports:</p>')
                    print(f'    <blockquote cite="{vulnerability["link"]}">')
                    print(f'      <p>{details}</p>')
                    print( '    </blockquote>')
                    print( '      </body>')
                    print( '    </description>')
                    print( '    <references>')
                    first_publication_date = ''
                    for cve in cve_list:
                        print(f'      <cvename>{cve}</cvename>')
                        publication_date = get_cve_publication_date(cve)
                        if not first_publication_date \
                        or datetime.datetime.strptime(publication_date, "%Y-%m-%d") < datetime.datetime.strptime(first_publication_date, "%Y-%m-%d"):
                            first_publication_date = publication_date
                    print(f'      <url>{vulnerability["link"]}</url>')
                    print( '    </references>')
                    print( '    <dates>')
                    if first_publication_date:
                        print(f'      <discovery>{first_publication_date}</discovery>')
                    else:
                        print( '      <discovery>INSERT_YEAR-MONTH-DAY</discovery>')
                    print(f'      <entry>{today_string}</entry>')
                    print( '    </dates>')
                    print( '  </vuln>\n')


####################################################################################################
def main():
    """ The program's main entry point """
    # Getting the Python packages ports list:
    python_ports = select_python_ports(get_freebsd_ports_list())
    python_ports = enrich_ports_list(python_ports)

    # Checking vulnerable Python packages:
    vulnerable_ports = pipinfo.get_packages_vulnerabilities(python_ports)
    #vulnerable_ports = pipinfo.get_packages_vulnerabilities(python_ports, progress_meter=False)

    # Getting the ignore and reported lists:
    ignored_vulns = get_ids_from_file("ignore.txt")
    reported_vulns = get_ids_from_file("reported.txt")

    # Getting the FreeBSD VuXML
    vuxml_data = vuxml.load_vuxml()

    # Printing identified vulnerabilities
    print_table_of_contents(python_ports, vulnerable_ports, ignored_vulns)
    print_vulnerabilities(python_ports, vulnerable_ports, ignored_vulns, reported_vulns, vuxml_data)

    sys.exit(0)


if __name__ == "__main__":
    main()
