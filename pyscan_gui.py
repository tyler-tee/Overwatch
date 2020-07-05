import PySimpleGUIQt as sg
from pyscan_funcs import *

sg.ChangeLookAndFeel('Dark')

layout = [
    [sg.Text('Target IP/Range:'), sg.In('', size=(30, 1), key='ranges')],
    [sg.Frame(layout=[
        [sg.Radio('All Ports', group_id='port_num', key='ports_all', default=True),
         sg.Radio('Top Ports', group_id='port_num', key='ports_top')],
        [sg.Radio('TCP/UDP', group_id='port_types', key='tcp_udp', default=True),
         sg.Radio('TCP', group_id='port_types', key='tcp'),
         sg.Radio('UDP', group_id='port_types', key='udp')]
    ], title='Scan options'),
        sg.Frame(layout=[
            [sg.Checkbox('Default', default=True), sg.Checkbox('XML', key='-oX')],
            [sg.Checkbox('JSON', key='-oX_json', tooltip='Experimental'), sg.Checkbox('All', key='-oA')]
        ], title='Output Format')],
    [sg.Button('Scan', button_color=(None, '#383838'), key='scan_init'),
     sg.Button('Exit', button_color=(None, '#383838'))]
]

window = sg.Window('PyScan', layout)

timestamp = datetime.datetime.now().strftime("%Y-%m-%d")

while True:
    event, values = window.read()

    if event in (None, 'Exit'):
        break

    if event == 'scan_init':
        site = sg.popup_get_text('Choose a label for your scan:')

        address_ranges = {site: values['ranges']}

        port_ranges = '1-65535' if values['ports_all'] else '1-1024'

        port_types = 'tcp_udp' if values['tcp_udp'] else 'tcp' if values['tcp'] else 'udp'

        scan_handler(address_ranges, timestamp, port_ranges, port_types)
