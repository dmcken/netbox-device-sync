'''





'''

import ipaddress
import logging
import pprint
import pynetbox
import sys
import traceback

import config

import drivers.junos
import drivers.routeros

# How best to make this dynamic (likely factory method)
platform_to_driver = {
    'JunOS':    drivers.junos.JunOS,
    'RouterOS': drivers.routeros.RouterOS,
}

logger = logging.getLogger(__name__)


def sync_interfaces(nb, device_nb, device_conn):
    '''
    
    nb - pynetbox instance
    device_nb - the device from netbox's perspective
    device_conn - 
    '''

    # - Interfaces:
    # -- flag the routing instance / logical systems (use VRF to keep track of this)
    # -- On SRXes use tags to flag the security-zones
    nb_interfaces = nb.dcim.interfaces.filter(device=device_nb.name)
    nb_interface_dict = {v.name:v for v in nb_interfaces}
    nb_interfaces_names = set(map(lambda x: x.name, nb_interfaces))
    dev_interfaces = device_conn.get_interfaces()
    dev_interfaces_names = set(map(lambda x: x['name'], dev_interfaces))
    logger.info("Interface data for '{0}'\n{1}".format(device_nb.name,
        pprint.pformat(dev_interfaces, width=200)))

    to_add_to_netbox = sorted(list(dev_interfaces_names.difference(nb_interfaces_names)))        
    to_check_for_updates = sorted(list(nb_interfaces_names.intersection(dev_interfaces_names)))
    to_delete_from_nb = sorted(list(nb_interfaces_names.difference(dev_interfaces_names)))
    logger.info("\nAdd: {0}\nDel: {1}\nUpdate: {2}".format(to_add_to_netbox, to_delete_from_nb, to_check_for_updates))

    for curr_dev_interface in dev_interfaces:

        cleaned_params = {}
        for curr_param in ['description', 'mac', 'mtu', 'name', 'type']:
            try:
                if curr_dev_interface[curr_param] == None:
                    continue
            except KeyError:
                continue
            cleaned_params[curr_param] = curr_dev_interface[curr_param]

        if curr_dev_interface['name'] in nb_interface_dict:
            # Update
            logger.debug("Updating '{0}' on '{1}' => {2}".format(curr_dev_interface['name'], device_nb.name, cleaned_params))
            curr_nb_obj = nb_interface_dict[curr_dev_interface['name']]
            for k,v in cleaned_params.items():
                # Only update if different
                if getattr(curr_nb_obj,k) != v:
                    setattr(curr_nb_obj, k, v)
            curr_nb_obj.save()
        else:
            # Create
            if 'type' not in cleaned_params:
                cleaned_params['type'] = 'other'
                
            logger.debug("Creating '{0}' on '{1}' => {2}".format(curr_dev_interface['name'], device_nb.name, cleaned_params))
            nb.dcim.interfaces.create(device=device_nb.id, **cleaned_params)
            #TODO: Error checking?

    # Delete extra interfaces
    nb_interfaces_to_delete = filter(lambda x: x.name in to_delete_from_nb, nb_interfaces)
    for curr_int_to_delete in nb_interfaces_to_delete:
        curr_int_to_delete.delete()

def main() -> None:
    '''
    '''

    BASIC_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    logging.getLogger('ncclient').setLevel(logging.ERROR)
    #logging.getLogger('ncclient.operations.rpc').setLevel(logging.ERROR)
    #logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)
    #logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    logging.basicConfig(level = logging.DEBUG, format=BASIC_FORMAT)

    nb = pynetbox.api(config.NB_URL, token=config.NB_TOKEN, threading = True)


    device_credentials = {
        'username': config.DEV_USERNAME,
        #'password': 'passwd',
        'key_file': config.DEV_KEYFILE,
    }

    devices = nb.dcim.devices.all()

    for device_nb in devices:
        logger.info("Processing device: {0}/{1} => {2} => {3}".format(device_nb.id, device_nb.name, device_nb.platform, device_nb.primary_ip))

        if device_nb.platform == None:
            continue

        try:
            driver = platform_to_driver[str(device_nb.platform)]
        except KeyError:
            logger.error("Unsupported platform '{0}'".format(device_nb.platform))
            continue

        if str(device_nb.platform) == 'RouterOS':
            continue

        if device_nb.primary_ip == None:
            continue

        if device_nb.name not in ['DC-GML-CE1']:
            continue

        # Create a driver passing it the credentials and the primary IP
        device_ip = str(ipaddress.ip_interface(device_nb.primary_ip).ip)
        full_dev_creds = {**device_credentials, 'hostname': device_ip}
        try:
            device_conn = driver(**full_dev_creds)
        except Exception as e:
            logger.error("There was an error connecting to '{2}': {0}, {1}".format(e.__class__, e, device_ip))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.error(pprint.pformat(traceback.format_exception(exc_type, exc_value, exc_traceback)))
            continue

        # sync_vlans()
        sync_interfaces(nb, device_nb, device_conn)
        # sync_ips(nb, device_nb, device_conn)
        # sync_routes(nb, device_nb, device_conn)
        # sync_neighbours(nb, device_nb, device_conn)
        

        # - IP Addresses - The matching interfaces should already exist (create the matching prefixes)
        # dev_ips = device_conn.get_ipaddresses()
        # pprint.pprint(dev_ips)
        # rez = nb.ipam.prefixes.filter(prefix='10.254.253.156/30') # [] or list with entry [131.72.76.0/32]
        # rez = nb.ipam.ip_addresses.filter(address="10.254.253.158/30")
        # rez = nb.ipam.ip_addresses.filter(address="10.254.253.158") # This seems to be taking longer
        # 

        # To Sync
        # - Vlans - Only for devices in charge of the vlan domain
        # - Static routes - Use to update prefixes
        # - Neighbour data (LLDP / CDP) - For building neighbour relations and rough cable plant.
        # 
        # Drivers for use to fetch the data from devices:
        # - Mikrotik
        # - JunOS
        # - EdgeRouter

        del device_conn

        logger.info("Completed processing")


main()
