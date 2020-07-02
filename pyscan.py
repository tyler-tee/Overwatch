from config import *
from pyscan_funcs import *

timestamp = datetime.datetime.now().strftime("%Y-%m-%d")

# Create our working directories
direct_create()

# Populate our ranges if none are defined
if not ranges:
    site = input('Please enter a title for your scan.')
    subnet = input('Please enter your target subnet.')

# Initiate the scan
scan_handler(ranges, timestamp)
