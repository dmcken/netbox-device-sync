'''
'''

import jnpr.junos
import jnpr.junos.exception
import logging
import re
from lxml import etree

# Local imports
import drivers.base 

logger = logging.getLogger(__name__)

class JunOS(drivers.base.driver_base):

    _connect_params = {
        'hostname': 'host',
        'username': 'user',
        'password': 'passwd',
        'key_file': 'ssh_private_key_file',
    }
    _config = {
        'interfaces': {
            'filter': '<configuration><interfaces/></configuration>',
            'result': None,
        },
        'protocols': {
            'filter': '<configuration><protocols/></configuration>',
            'result': None,
        },
    }
    

    def _connect(self, **kwargs):
        '''
        '''
        try:
            logger.debug("Attempting to connect to JunOS device: {0}".format(kwargs))

            kwargs['gather_facts'] = True

            self._dev = jnpr.junos.Device(**kwargs)
            self._dev.open()

        except jnpr.junos.exception.ConnectError:
            raise drivers.base.ConnectError()
        except Exception as err:
            logger.error("General connection error: {0}".format(err))
            raise err

    def _close(self,):
        if self._connection:
            self._connection.close()

    def _get_config(self, xml_filter=None):
        
        args = {
            'options': {
                # We always want the live config.
                'database' : 'committed'
            },
        }

        if xml_filter:
            args['xml_filter'] = xml_filter

        return self._dev.rpc.get_config(**args)


    def get_interfaces(self,):
        '''
        

        For Juniper naming conventions:
        https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet-switches/topics/topic-map/switches-interface-understanding.html
        '''

        parent_interfaces = []
        normal_interfaces = []
        interface_units = []
        config = self._get_config(self._config['interfaces'])

        interfaces = config.find('interfaces')

        for interface in interfaces.findall('interface'):
            int_name = interface.find('name').text

            try:
                int_desc = interface.find('description').text
            except AttributeError:
                int_desc = ""

            try:
                int_mtu = interface.find('mtu').text
            except AttributeError:
                int_mtu = 1514

            logger.debug("Interface name: {0}".format(int_name))

            if int_name in ['lo0', 'vlan', 'irb']:
                parent_interfaces.append({
                    'name': "{0}".format(int_name),
                    'mtu':  int_mtu,
                    'type': 'virtual',
                    'desc': int_desc,
                })
            elif re.match('ae[0-9]+', int_name):
                parent_interfaces.append({
                    'name': "{0}".format(int_name),
                    'mtu':  int_mtu,
                    'type': 'lag',
                    'desc': int_desc,
                })
            else:
                # TODO: Handle LAG slave interfaces
                # Insert into normal_interfaces
                normal_interfaces.append({
                    'name': "{0}".format(int_name),
                    'mtu':  int_mtu,
                    'type': 'other',
                    'desc': int_desc,
                })

            
            for unit in interface.findall('unit'):
                unit_name = unit.find('name').text
                try:
                    unit_desc = unit.find('description').text
                except AttributeError:
                    unit_desc = ''

                try:
                    unit_mtu = int(unit.find('mtu').text)
                except AttributeError:
                    #logger.error("MTU parse error: {0}".format(etree.tostring(unit, encoding='unicode', pretty_print=True)))
                    unit_mtu = 1500

                logger.debug("Unit: {0}".format(unit_name))

                # TODO: Detect ethernet-switching and update 802.1Q settings.

                interface_units.append({
                    'name': "{0}.{1}".format(int_name, unit_name),
                    'mtu': unit_mtu,
                    #'mac': None,
                    'type': 'virtual',
                    'desc': unit_desc,
                    'parent': '{0}'.format(int_name),
                })

        # This ordering is important
        # We are creating certain parent interfaces like aeX, lo0 first
        # Then the physical interfaces (mostly confirming they are in place)
        # Finally the units built on top of the first two.
        return parent_interfaces + normal_interfaces + interface_units

    def get_ipaddresses(self,):


        ip_addresses = []

        config = self._get_config(self._config['interfaces'])

        interfaces = config.find('interfaces')

        for interface in interfaces.findall('interface'):
            interface_name = interface.find('name').text
            for unit in interface.findall('unit'):
                unit_name = unit.find('name').text

                # Now start going through the families
                for family_inet in unit.find('family').findall('inet'):
                    for family_inet_address in family_inet.findall('address'):
                        ip_addresses.append({
                            'interface': "{0}.{1}".format(interface_name, unit_name),
                            'address': family_inet_address.find('name').text,
                        })

                for family_inet in unit.find('family').findall('inet6'):
                    for family_inet_address in family_inet.findall('address'):
                        ip_addresses.append({
                            'interface': "{0}.{1}".format(interface_name, unit_name),
                            'address': family_inet_address.find('name').text,
                        })

        return ip_addresses
            










