import datetime
from os import mkdir
import subprocess as sp
from typing import Tuple


def direct_create():
    try:
        mkdir('Scans')
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

    addresses = ",".join(list(set(host.split()[3] for host in temp_data)))

    ports = ",".join(list(set(host.split()[2] for host in temp_data)))

    return addresses, ports


def scan_handler(ranges: dict, timestamp: datetime):
    """
    Initiates a Masscan, then feeds the output back into Nmap for a more detailed scan of online hosts/listening ports
    :param ranges:
    :param timestamp:
    :return:
    """
    for site, subnet in ranges.items():
        # First we'll launch a masscan against our specified ranges
        # -p1-65535,U:1-65535 -> All ports, TCP and UDP alike
        # --rate 1000 -> 1k packets/sec; Can go faster, but speed seems to scale inversely with accuracy
        # -oL -> Exports results in plaintext
        sp.run(f"masscan {subnet} -p1-65535,U:1-65535 --rate 10000 -oL {site}_mass_{timestamp}.txt", shell=True)

        # Load, clean, and format our masscan txt for nmap
        addresses, ports = masscan_parser(f"{site}_mass_{timestamp}")

        # Launch an Nmap scan for each set of data
        sp.run(f"nmap -sS -sU {addresses} -p {ports} -oX {site}_{timestamp}.xml", shell=True)
