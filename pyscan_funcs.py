import ast
import datetime
from os import mkdir
import subprocess as sp


def direct_create():
    try:
        mkdir('Scans')
    except FileExistsError:
        pass


def masscan_parser(json_output: str):
    """
    Takes a file produced from Masscan's -oJ option and returns two lists - System addresses and Ports
    :param json_output:
    :return addresses, ports:
    """

    with open(json_output) as f:
        temp_data = ast.literal_eval(f.read())

    addresses = ",".join(list(set(host['ip'] for host in temp_data)))

    ports = ",".join(list(set(host['ports'][0]['port'] for host in temp_data)))

    return addresses, ports


def scan_handler(ranges: dict, timestamp: datetime):
    """

    :param ranges:
    :param timestamp:
    :return:
    """
    for site, subnet in ranges.items():
        # First we'll launch a masscan against our specified ranges
        sp.run(f"masscan {subnet} --ports 0-65535 --rate 100000 -oJ {site}_mass_{timestamp}.json")

        # Load, clean, and format our masscan json for nmap
        addresses, ports = masscan_parser(f"{site}_mass_{timestamp}.json")

        # Launch an Nmap scan for each set of data
        sp.run(f"nmap -sS -sU {addresses} -p {ports} -oX {site}_{timestamp}.xml")
