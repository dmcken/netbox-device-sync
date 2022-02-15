'''
'''
import collections
import jnpr.junos
import jnpr.junos.exception
import logging
import pprint
import re
import xmltodict
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

    # Interfaces and logical units that are to be ignored
    # For Juniper naming conventions:
    # https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet-switches/topics/topic-map/switches-interface-understanding.html
    _interfaces_to_ignore = [
        'fxp2',     # Temp
        'fxp2.0',   # Temp
        'gre',              # GRE
        'gr-0/0/0',         # GRE
        'ipip',             #
        'ip-0/0/0',         # IP-in-IP
        'lo0.16384',        #
        'lo0.16385',        # 
        'lsi',              # 
        'lsq-0/0/0',        # link services queuing interface
        'lt-0/0/0',         # 
        'mt-0/0/0',         # Unknown
        'mtun',             # 
        'pimd',             # 
        'pime',             # 
        'pp0',              # 
        'ppd0',             #
        'ppe0',             # 
        'sp-0/0/0',         # 
        'sp-0/0/0.0',       # 
        'sp-0/0/0.16383',   # 
        'st0',              # 
        'tap',              # 
    ]
    

    def _connect(self, **kwargs):
        '''
        '''
        try:
            logger.debug("Attempting to connect to JunOS device: {0}".format(kwargs))

            kwargs['gather_facts'] = True

            self._dev = jnpr.junos.Device(**kwargs)
            self._dev.open(normalize=True)

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


        parent_interfaces = []
        normal_interfaces = []
        interface_units = []

        '''
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
        '''

        # TODO: pull in the interfaces via something like show interfaces.
        # We don't want to go deleting unconfigured interfaces
        active_interfaces = []
        rez = self._dev.rpc.get_interface_information()
        int_dict = xmltodict.parse(etree.tostring(rez))
        for curr_int in int_dict['interface-information']['physical-interface']:
            logger.info("Processing interface: {0}".format(curr_int['name']))
            if curr_int['name'] in self._interfaces_to_ignore:
                logger.info("Ignoring")
                continue

            #print("Interface name: {0}".format(curr_int['name']))

            try:
                interface_description = curr_int['description']
            except KeyError:
                interface_description = None

            try:
                interface_mac = curr_int['current-physical-address']
                if isinstance(interface_mac, collections.OrderedDict):
                    interface_mac = interface_mac['#text']
            except KeyError:
                interface_mac = None

            try:
                interface_mtu = int(curr_int['mtu'])
            except ValueError:
                interface_mtu = None

            # Lag interfaces interfaces
            if re.match('ae[0-9]+', curr_int['name']):
                parent_interfaces.append({
                    'name': "{0}".format(curr_int['name']),
                    'mtu':  interface_mtu,
                    'type': 'lag',
                    'desc': interface_description,
                    'mac':  interface_mac,
                })
            #TODO: Handle bridge interfaces
            else: # Every other type of interface
                # 'if-type', 'GRE' - for GRE interfaces
                normal_interfaces.append({
                    'name': "{0}".format(curr_int['name']),
                    'mtu':  interface_mtu,
                    'type': None,
                    'desc': interface_description,
                    'mac': interface_mac,
                })
            if 'logical-interface' in curr_int:
                
                # In the case of a single unit it is a direct OrderedDict vs list of OrderedDict
                if isinstance(curr_int['logical-interface'], list):
                    logical_int_list = curr_int['logical-interface']
                else:
                    logical_int_list = [curr_int['logical-interface']]

                for curr_logical_int in logical_int_list:
                    if curr_logical_int['name'] in self._interfaces_to_ignore:
                        continue

                    #pprint.pprint(curr_logical_int)
                    try:
                        unit_descripion = curr_logical_int['description']
                    except KeyError:
                        unit_descripion = None

                    try:
                        unit_mtu = 0
                        if isinstance(curr_logical_int['address-family'], list):
                            address_family_list = curr_logical_int['address-family']
                        else:
                            address_family_list = [curr_logical_int['address-family']]
                    except KeyError:
                        # No address families under the unit, why?
                        continue

                    for curr_address_family in address_family_list:
                        try:
                            address_family_mtu = int(curr_address_family['mtu'])
                        except ValueError:
                            address_family_mtu = 0
                            
                        if address_family_mtu > unit_mtu:
                            unit_mtu = address_family_mtu

                    # Seems for the ethernet-switching family the MTU is 0
                    if unit_mtu == 0:
                        unit_mtu = interface_mtu

                    interface_units.append({
                        'name': "{0}".format(curr_logical_int['name']),
                        'mtu': unit_mtu,
                        'mac': None,
                        'type': 'virtual',
                        'desc': unit_descripion,
                        'parent': '{0}'.format(curr_int['name']),
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
            










