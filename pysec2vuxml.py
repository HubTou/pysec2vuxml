#!/usr/bin/env python3
""" pysec2vuxml - Mass checking FreeBSD Python packages ports for PYSEC vulnerabilities and reporting in FreeBSD VuXML
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import datetime
import os
import re
import sys
import uuid

import pipinfo  # pip install pnu-pipinfo
import vuxml    # pip install pnu-vuxml


####################################################################################################
def get_freebsd_ports_list():
    """ Returns a dictionary of FreeBSD ports """
    ports_list = []

    # The FreeBSD ports list
    # Its file format is described at: https://wiki.freebsd.org/Ports/INDEX
    ports_index = "/usr/ports/INDEX-13"

    # Is the ports list installed?
    if not os.path.isfile(ports_index):
        print("Please install and update the ports tree", file=sys.stderr)
        sys.exit(1)

    # Loading the ports list:
    with open(ports_index, encoding='utf-8', errors='ignore') as file:
        lines = file.read().splitlines()

    for line in lines:
        fields = line.split('|')
        if len(fields) != 13:
            print(f"WARNING: line '{line}' from '{ports_list}' doesn't have 13 fields", file=sys.stderr)
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
    """ Try to get name, version and maintainer from the port's Makefile """
    enriched_ports_list = []

    for port in ports_list:
        # Loading the port makefile:
        port_makefile = port["dir"] + os.sep + 'Makefile'
        with open(port_makefile, encoding='utf-8', errors='ignore') as file:
            lines = file.read().splitlines()

        # Searching for PORTNAME=, PORTVERSION= or DISTVERSION= lines:
        name = ''
        version = ''
        maintainer = ''
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

        if not name or not version or "$" in name or "$" in version:
            simplified_vname = re.sub(r",[0-9]*$", "", port["vname"])
            simplified_vname = re.sub(r"_[0-9]*$", "", simplified_vname)
            name = re.sub(r"-[0-9.pg+]+", "", simplified_vname)
            version = re.sub(r"" + name + "-", "", simplified_vname)
            name = re.sub(r"^py[0-9]+-", "", name)

        enriched_ports_list.append(
            {
                "vname": port["vname"],
                "dir": port["dir"],
                "name": name,
                "version": version,
                "maintainer": maintainer,
            }
        )

    return enriched_ports_list


####################################################################################################
def get_ignored_vulnerabilities():
    """ Load a list of vulnerabilities IDs to ignore """
    lines = []

    if os.path.isfile('ignore.txt'):
        with open('ignore.txt', encoding='utf-8', errors='ignore') as file:
            lines = file.read().splitlines()

    # Return all non empty lines not starting with a '#' comment character
    return [line for line in lines if line and not line.startswith('#')]


####################################################################################################
def print_table_of_contents(python_ports, vulnerable_ports, ignored_vulns, vuxml_data):
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
    print(f"  vulnerable packages           = {len(vulnerable_ports) - false_positive}")
    print(f"  vulnerable ports              = {len(contents)}")
    print(f"    vulnerabilities             = {vulnerabilities_count}")
    print("-" * (longuest_vulnerabilities + longuest_package + longuest_subdir + longuest_name + longuest_version + longuest_maintainer + 5))


####################################################################################################
def print_vulnerabilities(python_ports, vulnerable_ports, ignored_vulns, vuxml_data):
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

            print("-" * 80)
            print(f"Python package '{package_name} {package_version}' / FreeBSD port '{port_name} {port_version}' is vulnerable:")
            print(f"  Please report to  maintainer '{port_maintainer}' for port '{port_subdir}'")
            print("-" * 80)

            for vulnerability in package_vulns:
                ignore_vuln = False
                if vulnerability['id'] in ignored_vulns:
                    ignore_vuln = True
                for alias in vulnerability['aliases']:
                    if alias in ignored_vulns:
                        ignore_vuln = True
                        break
                if ignore_vuln:
                    print("Package ignored (vulnerability doesn't apply to FreeBSD)\n")
                    continue

                print(f"Id:          {vulnerability['id']}")
                print(f"  Aliases:   {vulnerability['aliases']}")
                print(f"  Details:   {vulnerability['details']}")
                print(f"  Fixed in:  {vulnerability['fixed_in']}")
                print(f"  Link:      {vulnerability['link']}")
                print(f"  Source:    {vulnerability['source']}")
                print(f"  Summary:   {vulnerability['summary']}")
                print(f"  Withdrawn: {vulnerability['withdrawn']}\n")

                # Don't process withdrawn vulnerabilities
                if vulnerability['withdrawn'] is not None:
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

                # Is this vulnerability already reported to FreeBSD VuXML?
                # If there's no CVE we won't know!
                vulns = vuxml.search_vulns_by_package(vuxml_data, package_name, package_version)
                something_found = False
                for vid in vulns:
                    if 'references' in vuxml_data[vid]:
                        for reference in vuxml_data[vid]['references']:
                            for key, value in reference.items():
                                if key == "cvename":
                                    if value in cve_list:
                                        if not something_found:
                                            print("Vulnerability reported to FreeBSD VuXML:")
                                            something_found = true
                                        vuxml.print_vuln(vid, vuxml_data[vid])
                                        cve_list.remove(value)
                if len(cve_list):
                    vulns = vuxml.search_vulns_by_package(vuxml_data, package_name, '')
                    for vid in vulns:
                        if 'references' in vuxml_data[vid]:
                            for reference in vuxml_data[vid]['references']:
                                for key, value in reference.items():
                                    if key == "cvename":
                                        if value in cve_list:
                                            if not something_found:
                                                print("Vulnerability reported to FreeBSD VuXML:")
                                                something_found = true
                                            vuxml.print_vuln(vid, vuxml_data[vid])
                                            cve_list.remove(value)

                # Here is a skeleton entry for the unreported CVE vulnerability
                if len(cve_list) or no_cve:
                    print("Skeleton for this unreported vulnerability in FreeBSD VuXML:\n")
                    print(f'  <vuln vid="{str(uuid.uuid4())}">')
                    if vulnerability['summary'] is None:
                        print(f'    <topic>{port_name} -- INSERT VULNERABILITY SUMMARY HERE</topic>')
                    else:
                        print(f'    <topic>{port_name} -- {vulnerability["summary"]}</topic>')
                    print( '    <affects>')
                    print( '      <package>')
                    print(f'    <name>{port_name}</name>')
                    if len(vulnerability['fixed_in']) == 0:
                        print(f'    <range><le>{port_version}</le></range>')
                    elif len(vulnerability['fixed_in']) == 1:
                        print(f'    <range><lt>{vulnerability["fixed_in"][0]}</lt></range>')
                    else:
                        print( '    <range><lt>INSERT VULNERABLE VERSION HERE</lt></range>')
                    print( '      </package>')
                    print( '    </affects>')
                    print( '    <description>')
                    print( '      <body xmlns="http://www.w3.org/1999/xhtml">')
                    print( '    <p>INSERT SOURCE NAME HERE reports:</p>')
                    print(f'    <blockquote cite="{vulnerability["link"]}">')
                    print(f'      <p>{vulnerability["details"]}</p>')
                    print( '    </blockquote>')
                    print( '      </body>')
                    print( '    </description>')
                    print( '    <references>')
                    for cve in cve_list:
                        print(f'      <cvename>{cve}</cvename>')
                    print(f'      <url>{vulnerability["link"]}</url>')
                    print( '    </references>')
                    print( '    <dates>')
                    print( '      <discovery>INSERT YEAR-MONTH-DAY</discovery>')
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

    # Getting the ignore list:
    ignored_vulns = get_ignored_vulnerabilities()

    # Getting the FreeBSD VuXML
    vuxml_data = vuxml.load_vuxml()

    # Printing identified vulnerabilities
    print_table_of_contents(python_ports, vulnerable_ports, ignored_vulns, vuxml_data)
    print_vulnerabilities(python_ports, vulnerable_ports, ignored_vulns, vuxml_data)

    sys.exit(0)


if __name__ == "__main__":
    main()
