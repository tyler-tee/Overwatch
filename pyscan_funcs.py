import ast
from os import mkdir


def direct_create():
    try:
        mkdir('Scans')
    except FileExistsError:
        pass


def masscan_parser(json_output):
    """
    Takes a file produced from Masscan's -oJ option and returns two lists - Systems and Ports
    :param json_output:
    :return addresses, ports:
    """

    with open(json_output) as f:
        temp_data = ast.literal_eval(f.read())

    addresses = ",".join(list(set(host['ip'] for host in temp_data)))

    ports = ",".join(list(set(host['ports'][0]['port'] for host in temp_data)))

    return addresses, ports
