
# System import
import ipaddress
import librouteros
import logging
import pprint
import socket

# Local imports
import drivers.base
import utils

logger = logging.getLogger(__name__)

class RouterOS(drivers.base.driver_base):
    '''
    RouterOS device driver
    '''

    _connect_params = {
        'hostname': {'dest': 'host'},
        'username': {'dest': 'username'},
        'password': {'dest': 'password'},
        #'keyfile':  {'dest': 'ssh_private_key_file'},
    }

    _type_map = {
        'bond':   'lag',
        'bridge': 'bridge',
        'eoip':   'virtual',
        'ether':  None,        # Most will already be defined by the templates
        'vlan':   'virtual',
    }

    def _connect(self, **kwargs) -> None:
        '''
        '''
        try:
            # Connection type, 6.43 and later use plain, before that uses token
            # https://librouteros.readthedocs.io/en/3.2.0/connect.html
            # kwargs['login_method'] = librouteros.login.plain
            logger.debug("Attempting to connect to RouterOS device: {0}".format(kwargs))
            self._dev = librouteros.connect(**kwargs)
        except socket.timeout:
            raise drivers.base.ConnectError()

    def _close(self,):
        if self._dev:
            self._dev.close()
        del self._dev

    def get_interfaces(self):
        rez_interfaces = []

        ros_interfaces = list(self._dev.path('interface'))

        for curr_interface in ros_interfaces:
            interface_rec = {}

            #logger.debug("Inteface data: {0}".format(pprint.pformat(ros_interfaces)))

            # Mandatory fields
            interface_rec['name']        = curr_interface['name']
            try:
                interface_rec['mac_address'] = curr_interface['mac-address']
            except KeyError:
                interface_rec['mac_address'] = None

            try:
                interface_rec['mtu']  = int(curr_interface['mtu'])
            except ValueError:
                interface_rec['mtu'] = int(curr_interface['actual-mtu'])

                # logger.error("Invalid MTU '{0}' on {1}".format(
                #     curr_interface['mtu'],
                #     curr_interface,
                # ))                  

            try:
                interface_rec['description'] = curr_interface['name']
            except KeyError:
                interface_rec['description'] = None

            # Map from mikrotik types to netbox types
            try:
                interface_rec['type'] = self._type_map[curr_interface['type']]
            except KeyError:
                interface_rec['type'] = None

            rez_interfaces.append(interface_rec)

        return rez_interfaces

    def get_ipaddresses(self):

        rez_ip_addresses = []

        families = {
            4: self._dev.path('ip','address'),
            6: self._dev.path('ipv6','address'),
        }
        for family,data in families.items():

            ros_ips = list(data)

            for curr_ip_addr in ros_ips:
                logger.debug("IPv{0} address: {1}".format(family, curr_ip_addr))
                try:
                    if curr_ip_addr['link-local'] == True:
                        continue
                except KeyError:
                    pass

                # Using depreciated for disabled IPs
                ip_status = 'active'
                if curr_ip_addr['disabled'] == True:
                    ip_status = 'deprecated'

                ip_rec = {}

                ip_rec['address'] = ipaddress.ip_interface(curr_ip_addr['address'])
                ip_rec['interface'] = curr_ip_addr['interface']
                ip_rec['status'] = ip_status
                ip_rec['vrf'] = None

                rez_ip_addresses.append(ip_rec)

        return rez_ip_addresses
