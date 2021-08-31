from config import config
import overwatch_funcs
import overwatch_gui
import datetime
import os
import PySimpleGUIQt as sg

timestamp = datetime.datetime.now().strftime("%Y-%m-%d")
ranges = config['ranges']


def main():
    # Create our working directories
    overwatch_funcs.direct_create()

    sg.ChangeLookAndFeel(config['theme'])
    headless = sg.popup_yes_no('Launch headless?')

    if headless == 'Yes':
        # Populate our ranges if none are defined
        if not ranges:
            site = input('Please enter a title for your scan.')
            subnet = input('Please enter your target subnet.')
        overwatch_funcs.scan_handler(ranges, timestamp)
    else:
        overwatch_gui.run_gui()

if __name__ == '__main__':
    main()
