import datetime
import pathlib
import subprocess as sp
from typing import Tuple

shodan_uri = 'https://api.shodan.io/shodan/host/search'

nmap_direct, mass_direct = 'Scans/Nmap', 'Scans/Masscan'


def direct_create():
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


def scan_handler(ranges: dict, timestamp: datetime, port_quant: str = '1-65535', port_type: str = 'tcp_udp',
                 os_detection: bool = True):
    for site, subnet in ranges.items():
        target_mass_file = str(pathlib.Path(f"Scans/Masscan/{site}_mass_{timestamp}"))
        target_nmap_file = str(pathlib.Path(f"Scans/Nmap/{site}_{timestamp}"))

        mass_cmd = f"masscan {subnet} "
        nmap_cmd = "nmap "

        if port_type == 'tcp_udp':
            mass_cmd += f"-p{port_quant},U:{port_quant}"
            nmap_cmd += f"-sS -sU "

        elif port_type == 'tcp':
            mass_cmd += f"-p{port_quant}"
            nmap_cmd += f"-sS "

        else:
            mass_cmd += f"--udp-ports {port_quant}"
            nmap_cmd += f"-sU "

        mass_cmd += f" --rate 10000 -oL {target_mass_file}.txt"

        sp.run(mass_cmd, shell=True)

        # Load, clean, and format our masscan txt for nmap
        addresses, ports = masscan_parser(f"{target_mass_file}.txt")

        if os_detection:
            nmap_cmd += "-O "

        # Finish building our Nmap command with collected data from Masscan, then execute
        nmap_cmd += f"-p {ports} -Pn {addresses} -oX {target_nmap_file}.xml"
        sp.run(nmap_cmd, shell=True)
