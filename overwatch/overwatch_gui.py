import PySimpleGUIQt as sg
from shodan import Shodan, exception
from config import config
from overwatch_funcs import *

sg.ChangeLookAndFeel(config['theme'])
theme_lst = sg.theme_list()

layout = [
    [sg.ButtonMenu('Menu', menu_def=['Menu', 
                                        ['Open Scan', 'Scan Diff', 'About', 
                                            'Startup Mode', ['GUI', 'Headless'],
                                            'Theme', theme_lst, 'Exit']
                                    ],
                   size=(10, 1), button_color=(None, '#383838'), key='menu')],
    [sg.Frame(layout=[
        [sg.Text('IP/Subnet:'), sg.In('', size=(30, 1), key='ranges')]
    ], title='Targets')],
    [sg.Frame(layout=[
        [sg.Column([
            [sg.Radio('All Ports', group_id='port_num', key='ports_all', default=True)],
            [sg.Radio('Top Ports', group_id='port_num', key='ports_top')],
            [sg.Radio('Custom', group_id='port_num', key='ports_cust')]
        ]),
            sg.Column([
                [sg.Radio('TCP/UDP', group_id='port_types', key='tcp_udp', default=True)],
                [sg.Radio('TCP', group_id='port_types', key='tcp')],
                [sg.Radio('UDP', group_id='port_types', key='udp')]
            ])],
        [sg.Check('Shodan Query', key='shodan_query'), sg.Check('OS Detection', key='os_detect')]
    ], title='Scan Options'),
        sg.Frame(layout=[
            [sg.Checkbox('Default', default=True), sg.Checkbox('XML', key='-oX')],
            [sg.Checkbox('JSON', key='-oX_json', tooltip='Experimental'), sg.Checkbox('All', key='-oA')]
        ], title='Output Format')],
    [sg.Stretch(),
        sg.Button('Scan', button_color=(None, '#383838'), size=(20, 1), key='scan_init'),
     sg.Button('Exit', button_color=(None, '#383838'), size=(20, 1)),
     sg.Stretch()]
]

window = sg.Window('Overwatch', layout, grab_anywhere=True, no_titlebar=True, keep_on_top=True)

timestamp = datetime.datetime.now().strftime("%Y-%m-%d")

def run_gui():
    while True:
        event, values = window.read()

        if event in (None, 'Exit'):
            break

        if event == 'scan_init':
            site = sg.popup_get_text('Choose a label for your scan:', keep_on_top=True)

            address_ranges = {site: values['ranges']}

            port_ranges = '1-65535' if values['ports_all'] else '1-1024' if values['ports_top'] else \
                sg.popup_get_text('Ports: ')

            port_types = 'tcp_udp' if values['tcp_udp'] else 'tcp' if values['tcp'] else 'udp'

            addresses, ports = scan_handler(address_ranges, timestamp, port_ranges, port_types,
                                            os_detection=values['os_detect'])

            if values['shodan_query']:
                shodan_api = Shodan(config['shodan_key'])
                shodan_results = {}

                for address in addresses:
                    try:
                        host = shodan_api.host(address, history=True)
                        exploits = shodan_api.exploits.search(query=f"net:{address}")
                        shodan_results[address] = {
                            'Domains': host['domains'],
                            'Hostnames': host['hostnames'],
                            'Port History': host['ports'],
                            'OS': host['os'],
                            'Exploits': exploits
                        }

                    except exception.APIError:
                        shodan_results[address] = 'No information found for this host.'

        if event == 'menu':
            if values['menu'] in theme_lst:
                config['theme'] = values['menu']
                with open('config.py', 'w') as f:
                    f.write(f"config = {config}")
                sg.popup('Theme updated! Please re-launch Overwatch to see your changes.',
                        title='Theme Updated', keep_on_top=True)

            elif values['menu'] in ('GUI', 'Headless'):
                config['run_mode'] = values['menu'].lower()
                with open('config.py', 'w') as f:
                    f.write(f"config = {config}")
            
            elif values['menu'] == 'Open Scan':
                scan = sg.popup_get_file('Select Previous Scan', keep_on_top=True)
                if scan.endswith('xml'):
                    df_scan = xml_to_df(scan)

                    df_scan_values = df_scan.values.tolist()

                    scan_layout = [
                        [sg.Table(values=df_scan_values, headings=config['df_cols'])]
                    ]

                    scan_window = sg.Window("Scan Results", scan_layout)
                    scan_event, scan_values = scan_window.read()
                else:
                    sg.popup('Sorry, that file type isn\'t supported just yet!',
                             title='Unsupported File Type', keep_on_top=True)
        
if __name__ == '__main__':
    run_gui()
