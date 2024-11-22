import datetime
import PySimpleGUIQt as sg
from shodan import Shodan
from config import config
from overwatch_funcs import scan_handler, xml_to_df

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


def get_port_ranges(values, sg):
    if values['ports_all']:
        return '1-65535'
    elif values['ports_top']:
        return '1-1024'
    else:
        return sg.popup_get_text('Ports: ')


def get_port_type(values):
    if values['tcp_udp']:
        return 'tcp_udp'
    elif values['tcp']:
        return 'tcp'
    else:
        return 'udp'


def handle_exit(event):
    return event in (None, 'Exit')


def handle_scan_init(values, sg, config, timestamp):
    site = sg.popup_get_text('Choose a label for your scan:', keep_on_top=True)
    if not site:
        return

    address_ranges = {site: values['ranges']}
    port_ranges = get_port_ranges(values, sg)
    port_types = get_port_type(values)

    addresses, _ = scan_handler(address_ranges, timestamp, port_ranges, port_types,
                                os_detection=values['os_detect'])

    if values['shodan_query']:
        shodan_results = query_shodan(addresses, config['shodan_key'])
        return shodan_results


def query_shodan(addresses, api_key):
    shodan_api = Shodan(api_key)
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
        except Exception:  # Use a more specific exception if possible
            shodan_results[address] = 'No information found for this host.'
    return shodan_results


def handle_menu(values, sg, config, theme_lst):
    if values['menu'] in theme_lst:
        update_theme(values['menu'], config)
        sg.popup('Theme updated! Please re-launch Overwatch to see your changes.',
                 title='Theme Updated', keep_on_top=True)
    elif values['menu'] in ('GUI', 'Headless'):
        update_run_mode(values['menu'], config)
    elif values['menu'] == 'Open Scan':
        open_scan(sg, config)


def update_theme(theme, config):
    config['theme'] = theme
    with open('config.py', 'w') as f:
        f.write(f"config = {config}")


def update_run_mode(mode, config):
    config['run_mode'] = mode.lower()
    with open('config.py', 'w') as f:
        f.write(f"config = {config}")


def open_scan(sg, config):
    scan = sg.popup_get_file('Select Previous Scan', keep_on_top=True)
    if scan and scan.endswith('xml'):
        df_scan = xml_to_df(scan)
        show_scan_results(df_scan, config['df_cols'], sg)
    else:
        sg.popup('Sorry, that file type isn\'t supported just yet!',
                 title='Unsupported File Type', keep_on_top=True)


def show_scan_results(df_scan, columns, sg):
    df_scan_values = df_scan.values.tolist()
    scan_layout = [
        [sg.Table(values=df_scan_values, headings=columns)]
    ]
    scan_window = sg.Window("Scan Results", scan_layout)
    scan_window.read()


def run_gui():
    while True:
        event, values = window.read()

        if handle_exit(event):
            break

        if event == 'scan_init':
            handle_scan_init(values, sg, config, timestamp)

        if event == 'menu':
            handle_menu(values, sg, config, theme_lst)


if __name__ == '__main__':
    run_gui()
