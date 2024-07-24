'''
General Utility definitions and functions
'''


# System imports
import ipaddress
import re



link_local_subnet = ipaddress.ip_network('fe80::/10')

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
