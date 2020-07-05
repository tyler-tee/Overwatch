from config import shodan_key
import datetime
from os import mkdir
import requests
import subprocess as sp
from typing import Tuple

shodan_uri = 'https://api.shodan.io/shodan/host/search'

nmap_direct, mass_direct = '.\\Scans\\Nmap', '.\\Scans\\Masscan'


def direct_create():
    directories = ['Scans', nmap_direct, mass_direct]

    for directory in directories:
        try:
            mkdir(directory)
        except FileExistsError:
            pass


def masscan_parser(masscan_output: str) -> Tuple[str, str]:
    """
    Takes a file produced from Masscan's -oL option and returns two strings
    :param masscan_output:
    :return addresses, ports:
    """

    with open(masscan_output) as f:
        temp_data = f.readlines()

    addresses = " ".join({host.split()[3] for host in temp_data if len(host.split(' ')) > 2})

    ports = ",".join({host.split()[2] for host in temp_data if len(host.split(' ')) > 2})

    return addresses, ports


def scan_handler(ranges: dict, timestamp: datetime, port_quant: str = '1-65535', port_type: str = 'tcp_udp'):
    for site, subnet in ranges.items():
        scan_cmd = f"masscan {subnet} "

        if port_type == 'tcp_udp':
            scan_cmd += f"-p{port_quant},U:{port_quant}"
        elif port_type == 'tcp':
            scan_cmd += f"-p{port_quant}"
        else:
            scan_cmd += f"--udp-ports {port_quant}"

        scan_cmd += f" --rate 10000 -oL {mass_direct}\\{site}_mass_{timestamp}.txt"
        print(scan_cmd)

        sp.run(scan_cmd)

        # Load, clean, and format our masscan txt for nmap
        addresses, ports = masscan_parser(f"{mass_direct}\\{site}_mass_{timestamp}.txt")

        # Launch an Nmap scan for each set of data
        sp.run(f"nmap -sS -sU -Pn {addresses} -p {ports} -oX {nmap_direct}\\{site}_{timestamp}.xml",
               shell=True)


def shodan_query(subnet: str) -> dict:
    params = {'key': shodan_key,
              'query': f'net:{subnet}'}

    response = requests.get(shodan_uri, params=params)

    if response.status_code == 200:
        return response.json()
