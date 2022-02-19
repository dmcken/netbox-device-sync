
import abc
import logging

logger = logging.getLogger(__name__)

class ConnectError(Exception):
    pass


class driver_base(metaclass = abc.ABCMeta):
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
    _connect_params = {}
    _connection = None

    def __init__(self, **kwargs) -> None:
        
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
    def get_interfaces(self,):
        '''
        TODO: Document what is expected of the drivers
        '''
        pass

    @abc.abstractmethod
    def get_ipaddresses(self,):
        '''
        TODO: Document what is expected of the drivers
        '''
        pass

    # @abc.abstractmethod
    # def get_vlans(self,):
    #     pass

    # @abc.abstractmethod
    # def get_neighbours(self,):
    #     pass
