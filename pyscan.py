import datetime
import subprocess as sp
from config import *
from pyscan_funcs import *

timestamp = datetime.datetime.now().strftime("%Y-%m-%d")

# Create our working directories
direct_create()

if not ranges:
    site = input('Please enter a title for your scan.')
    subnet = input('Please enter your target subnet.')

for site, subnet in ranges.items():
    # First we'll launch a masscan against our specified ranges
    sp.call(f"masscan {subnet} --ports 0-65535 -oJ {site}_mass_{timestamp}.json")

    # Load, clean, and format our masscan json for nmap
    addresses, ports = masscan_parser(f"{site}_mass_{timestamp}.json")

    # Launch an Nmap scan for each set of data
    # sp.call(f"nmap -sS -sU {addresses} -p {ports} -oX {site}_{timestamp}.xml")
