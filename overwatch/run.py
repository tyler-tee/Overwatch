from config import config
import overwatch_funcs
import overwatch_gui
import datetime

timestamp = datetime.datetime.now().strftime("%Y-%m-%d")
try:
    ranges = config['ranges']
except ValueError:
    ranges = None

def main():
    # Create our working directories
    overwatch_funcs.direct_create()

    # Check for run_mode in config, launch script accordingly
    if config['run_mode'] != 'gui':
        # Populate our ranges if none are defined
        if not ranges:
            site = input('Please enter a title for your scan.')
            subnet = input('Please enter your target subnet.')
        overwatch_funcs.scan_handler({site: subnet}, timestamp)
    else:
        overwatch_gui.run_gui()

if __name__ == '__main__':
    main()
