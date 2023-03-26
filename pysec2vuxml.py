#!/usr/bin/env python3
""" pysec2vuxml - Mass checking FreeBSD Python packages ports for PYSEC vulnerabilities and reporting in FreeBSD VuXML
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import os
import re
import sys

import pipinfo  # pip install pnu-pipinfo
import vuxml    # pip install pnu-vuxml


####################################################################################################
def get_freebsd_ports_list():
    """ Returns a dictionary of FreeBSD ports """
    ports_list = []

    # The FreeBSD ports list
    # Its file format is described at: https://wiki.freebsd.org/Ports/INDEX
    ports_index = "/usr/ports/INDEX-13"

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
    return re.match("py[0-9]+-", element["vname"]) is not None


####################################################################################################
def select_python_ports(ports_list):
    """ Filters out FreeBSD ports that are not Python packages """
    return list(filter(_is_python_package, ports_list))


####################################################################################################
def enrich_ports_list(ports_list):
    """ Try to get name and version from the port's Makefile """
    enriched_ports_list = []

    for port in ports_list:
        # Loading the port makefile:
        port_makefile = port["dir"] + os.sep + 'Makefile'
        with open(port_makefile, encoding='utf-8', errors='ignore') as file:
            lines = file.read().splitlines()

        # Searching for PORTNAME=, PORTVERSION= or DISTVERSION= lines:
        name = ''
        version = ''
        """
        revision = ''
        epoch = ''
        """
        for line in lines:
            if line.startswith('PORTNAME='):
                line = re.sub(r'[ 	]*#.*', '', line)
                name = re.sub(r'^PORTNAME=[ 	]*', '', line)
            elif line.startswith('PORTVERSION='):
                line = re.sub(r'[ 	]*#.*', '', line)
                version = re.sub(r'^PORTVERSION=[ 	]*', '', line)
            elif line.startswith('DISTVERSION='):
                line = re.sub(r'[ 	]*#.*', '', line)
                version = re.sub(r'^DISTVERSION=[ 	]*', '', line)
            """
            elif line.startswith('PORTREVISION='):
                line = re.sub(r'[ 	]*#.*', '', line)
                revision = re.sub(r'^PORTREVISION=[ 	]*', '', line)
            elif line.startswith('PORTEPOCH='):
                line = re.sub(r'[ 	]*#.*', '', line)
                epoch = re.sub(r'^PORTEPOCH=[ 	]*', '', line)
            """

        if not name or not version or "$" in name or "$" in version:
            simplified_vname = re.sub(r",[0-9]*$", "", port["vname"])
            simplified_vname = re.sub(r"_[0-9]*$", "", simplified_vname)
            name = re.sub(r"-[0-9.]+", "", simplified_vname)
            version = re.sub(r"" + name + "-", "", simplified_vname)
            name = re.sub(r"^py[0-9]+-", "", name)
            """
            Doesn't work for 2 records out of 4000+:
                py39-uiCA-g20230312+2022.12 -> 'py39-uiCA-g20230312+2022.12', 'py39-uiCA-g20230312+2022.12'
                py39-ansible-sysrc-g20200803_1,1 -> 'py39-ansible-sysrc-g20200803', 'py39-ansible-sysrc-g20200803'
            """

        enriched_ports_list.append(
            {
                "vname": port["vname"],
                "dir": port["dir"],
                "name": name,
                "version": version,
            }
        )

    return enriched_ports_list


####################################################################################################
def print_vulnerabilities(python_ports, vulnerable_ports):
    """ Try """
    # Loading the FreeBSD VuXML database
    vuxml_data = vuxml.load_vuxml()

    print(f"\nFound {len(vulnerable_ports)} vulnerable ports in {len(python_ports)} Python packages ports:\n")
    for package_name, package_info in vulnerable_ports.items():
        for package_version, package_vulns in package_info.items():
            port_vname = ''
            for port in python_ports:
                if port['name'] == package_name and port['version'] == package_version:
                    port_vname = port['vname']
                    break
            print(f"FreeBSD's port '{port_vname}' / PIP's package '{package_name}-{package_version}' is vulnerable:")
            for vulnerability in package_vulns:
                print(f"    Id:        {vulnerability['id']}")
                print(f"    Aliases:   {vulnerability['aliases']}")
                print(f"    Details:   {vulnerability['details']}")
                print(f"    Fixed in:  {vulnerability['fixed_in']}")
                print(f"    Link:      {vulnerability['link']}")
                print(f"    Source:    {vulnerability['source']}")
                print(f"    Summary:   {vulnerability['summary']}")
                print(f"    Withdrawn: {vulnerability['withdrawn']}\n")

            print("Vulnerabilities reported to FreeBSD VuXML:")
            print(f">>> for version {package_version} >>>>>>>>>>>>>>>>>>>>>>>>")
            vulns = vuxml.search_vulns_by_package(vuxml_data, package_name, package_version)
            for vid in vulns:
                vuxml.print_vuln(vid, vuxml_data[vid])
            print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
            print(">>> for any version >>>>>>>>>>>>>>>>>>>>>>>>")
            vulns = vuxml.search_vulns_by_package(vuxml_data, package_name, '')
            for vid in vulns:
                vuxml.print_vuln(vid, vuxml_data[vid])
            print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n\n")


####################################################################################################
def main():
    """ The program's main entry point """
    # Getting the Python packages ports list:
    python_ports = select_python_ports(get_freebsd_ports_list())
    python_ports = enrich_ports_list(python_ports)

    # Checking vulnerable Python packages:
    vulnerable_ports = pipinfo.get_packages_vulnerabilities(python_ports)
    #vulnerable_ports = pipinfo.get_packages_vulnerabilities(python_ports, progress_meter=False)

    # Printing identified vulnerabilities
    print_vulnerabilities(python_ports, vulnerable_ports)

    sys.exit(0)


if __name__ == "__main__":
    main()
