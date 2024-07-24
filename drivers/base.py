'''Base classes for all device drivers.

'''
# System imports
import abc
import ipaddress
import logging

# Globals
logger = logging.getLogger(__name__)

# Exceptions
class ConnectError(Exception):
    '''General error if we can't connect'''
    pass

class AuthenticationError(Exception):
    '''Thrown if auhentiction to a device fails'''
    pass

# Data classes

# Factories
class DriverFactory(object):
    #
    pass


class DriverBase(metaclass = abc.ABCMeta):
    '''

    Protocols:
    - If a value is unknown return None, the sync will ignore that value
      failing if it is required by netbox.

    To define in _connect_params:
    - hostname
    - username
    - password
    - key_file
    '''
    _addresses_to_ignore = [
        ipaddress.ip_interface('127.0.0.1/8'),
        ipaddress.ip_interface('::1/128'),
    ]
    _connect_params = {}
    _connection = None

    def __init__(self, **kwargs) -> None:

        # This cache is for storing data in the drivers between calls
        self._cache = {}

        # Parse the device connection parameters
        creds = {}
        for k,v in self._connect_params.items():
            try:
                creds[v['dest']] = kwargs[k]
            except KeyError:
                continue

        logger.debug("Creds within base: {0}".format(creds))

        self._connect(**creds)

    def __del__(self):
        self._close()

    @abc.abstractmethod
    def _connect(self, **kwargs):
        '''
        Creates a connection to the device:

        The incoming parameters will be from the config.py DEV_* with the DEV_
        prefix removed and then lowercased (e.g. DEV_USERNAME becomes username).
        The hostname parameter is also added to this set of parameters and is
        the current device's hostname / IP.

        These parameters are then filtered and mapped using the _connect_params

        Example:
        _connect_params = {
            'hostname': 'host',
            'username': 'user',
            'keyfile':  'ssh_private_key_file',
        }

        will only accept the hostname, username and keyfile parameters and map them
        to host, user and ssh_private_key_file respectively.

        This setup should make allowing the drivers to share parameters that make
        sense and break out the ones that don't. An example of this could be
        defining DEV_ROUTEROS_PORT with a matching mapping of:
            'routeros_port': 'port',
        in the dictionary. The routeros driver will know what port to use for its
        connections without requiring any changes to the other drivers.
        '''
        pass

    @abc.abstractmethod
    def _close(self,):
        '''
        Close the connection to the device
        '''
        pass

    @abc.abstractmethod
    def get_interfaces(self,):
        '''
        TODO: Document what is expected of the drivers

        Return:
        List of interface definitions:

        Interface definitions:
        - Dictionary containing the following fields:
        -- description: Description of the interface (string,mandatory)
        -- mac_address: MAC address of the interface (string,None allowed)
        -- mtu: MTU of the interface (integer,None allowed)
        -- name: Interface name (string,mandatory)
        -- type: Type of the interface (string,None allowed)

        Example:
        {'description': None, 'mac_address': '64:87:88:ef:34:00', 'mtu': 1514, 'name': 'ge-0/0/0', 'type': None}
        '''
        pass

    @abc.abstractmethod
    def get_ipaddresses(self,):
        '''
        TODO: Document what is expected of the drivers

        Return:
        list of IP definitions:

        IP definition:
        - Dictionary containing the following fields:
        -- address: IP With subnet mask (IPv4Interface or IPv6Interface, mandatory)
        -- interface:  name of the interface. (string,mandatory)
        -- status: One of the netbox IP address statuses. The current list: active,reserved,deprecated,dhcp,slaac (string,mandatory)
        -- vrf: VRF this IP sits within (string,If unknown set to None)
        Example:
        {'address': IPv4Interface('172.17.10.89/29'), 'interface': 'ge-0/0/2.0', 'status': 'active', 'vrf': None}

        '''
        pass

    # @abc.abstractmethod
    # def get_vlans(self,):
    #     pass

    # @abc.abstractmethod
    # def get_neighbours(self,):
    #     pass
