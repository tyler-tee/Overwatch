import datetime
import pathlib
import pandas as pd
import subprocess as sp
from typing import Tuple
import xml.etree.ElementTree as et


nmap_direct, mass_direct = 'Scans/Nmap', 'Scans/Masscan'


def direct_create():
    #
    directories = ['Scans', nmap_direct, mass_direct]

    for directory in directories:
        pathlib.Path(directory).mkdir(exist_ok=True)


def masscan_parser(masscan_output: str) -> Tuple[str, str]:
    """
    Takes a file produced from Masscan's -oL option, returns online IP addresses and listening ports
    :param masscan_output:
    :return addresses, ports:
    """

    with open(masscan_output) as f:
        temp_data = f.readlines()

    addresses = " ".join({host.split()[3] for host in temp_data if len(host.split(' ')) > 2})
    ports = ",".join({host.split()[2] for host in temp_data if len(host.split(' ')) > 2})

    return addresses, ports


def host_parser(raw_txt: str) -> str:
    """
    Simple function to parse a host from Nmap txt file.
    """
    start = 'nmap scan report for'
    end = 'host'
    raw_txt = raw_txt.lower()

    host = raw_txt[raw_txt.find(start) + 20:raw_txt.find(end)]

    return host


def port_parser(raw_txt: str) -> str:
    """
    Simple function to parse port information from Nmap txt file.
    """
    start = 'service'
    ports = raw_txt[raw_txt.find(start) + 7:]
    ports = [port for port in ports.split('\n') if port]
    print(ports)
    ports = [port.split() for port in ports]

    ports = [port for port in ports if len(port) == 3]

    return ports


def df_generator(raw_txt: str):
    """
    Uses host and port parsers above to spit out a semi-usable dataframe.
    """
    raw_data = raw_txt.split('\n\n\n')
    records = []

    for finding in raw_data:
        host = host_parser(finding)
        ports = port_parser(finding)

        records = [[host] + port for port in ports]

    df_scan_data = pd.DataFrame(records)

    return df_scan_data


def xml_to_df(scan_xml):
    """
    (Try) to convert Nmap XML scan output into a Pandas dataframe.
    """

    scan_data = []  # Empty list to which data will be appended.

    # Read in XML file, establish XML root, then parse all scanned hosts.
    tree = et.parse(scan_xml)
    root = tree.getroot()
    hosts = root.findall('host')

    # Iterate over hosts to find IP, Status, hostnames, ports, and associated port information.
    for host in hosts:
        address = host.findall('address')[0].attrib['addr']
        status = host.findall('status')[0].attrib['state']

        try:
            hostnames = host.findall('hostnames')[0].attrib['name']
        except Exception as e:
            print(e)
            hostnames = ''

        port_element = host.findall('ports')
        ports = port_element[0].findall('port')
        for port in ports:
            port_data = []
            proto = port.attrib['protocol']
            port_id = port.attrib['portid']
            try:
                service = port.findall('service')[0].attrib['name']
            except Exception as e:
                print(e)
                service = ''
            try:
                state = port.findall('state')[0].attrib['state']
            except Exception as e:
                print(e)
                state = ''

            # Create a list of the port data
            port_data.extend((address, status, hostnames,
                              proto, port_id, service, state))

            # Add the port data to the host data
            scan_data.append(port_data)

    # Establish dataframe columns and create the dataframe.
    df_cols = ['host', 'status', 'hostnames', 'protocol', 'port', 'service', 'port_state']
    df_scan = pd.DataFrame(data=scan_data, columns=df_cols)

    return df_scan


def scan_handler(ranges: dict, timestamp: datetime, port_quant: str = '1-65535', port_type: str = 'tcp_udp',
                 os_detection: bool = True):
    for site, subnet in ranges.items():
        target_mass_file = str(pathlib.Path(f"Scans/Masscan/{site}_mass_{timestamp}"))
        target_nmap_file = str(pathlib.Path(f"Scans/Nmap/{site}_{timestamp}"))

        mass_cmd = f"masscan {subnet} "
        nmap_cmd = "nmap "

        if port_type == 'tcp_udp':
            mass_cmd += f"-p{port_quant},U:{port_quant}"
            nmap_cmd += "-sS -sU "

        elif port_type == 'tcp':
            mass_cmd += f"-p{port_quant}"
            nmap_cmd += "-sS "

        else:
            mass_cmd += f"--udp-ports {port_quant}"
            nmap_cmd += "-sU "

        mass_cmd += f" --rate 10000 -oL {target_mass_file}.txt"

        sp.run(mass_cmd, shell=True)

        # Load, clean, and format our masscan txt for nmap
        addresses, ports = masscan_parser(f"{target_mass_file}.txt")

        if os_detection:
            nmap_cmd += "-O "

        # Finish building our Nmap command with collected data from Masscan, then execute
        nmap_cmd += f"-p {ports} -Pn {addresses} -oX {target_nmap_file}.xml"
        sp.run(nmap_cmd, shell=True)
