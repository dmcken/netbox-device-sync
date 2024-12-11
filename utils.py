'''
General Utility definitions and functions
'''


# System imports
import ipaddress
import re


# Common definitions
link_local_subnet = ipaddress.ip_network('fe80::/10')

device_roles_to_ignore = [
    'dh-txrx-receivers',
    'generic',
    'patch-panel',
    'pdu',
    'svr-transcoder',
    'video-encoder',
    'video-satellite-receiver',
    'video-satellite-splitter',
]
networks_to_ignore = [
    ipaddress.ip_network('127.0.0.0'), # IPv4 Loopback
    ipaddress.ip_network('::1/128'),     # IPv6 Loopback
    ipaddress.ip_network('FE80::/10'),   # Link local

]

# Utility functions
def parse_device_parameters(config):
    """Parse the config parameters.

    Args:
        config (_type_): _description_

    Returns:
        _type_: _description_
    """
    device_credentials = {}
    for curr_dev_attr in dir(config):
        attr_re = re.match("DEV_([A-Za-z0-9]+)", curr_dev_attr)
        if not attr_re:
            continue

        attr_value = getattr(config, curr_dev_attr)

        if not attr_value:
            continue

        device_credentials[attr_re.group(1).lower()] = attr_value

    return device_credentials
