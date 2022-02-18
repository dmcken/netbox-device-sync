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
    logger.debug("\nAdd: {0}\nDel: {1}\nUpdate: {2}".format(to_add_to_netbox, to_delete_from_nb, to_check_for_updates))

    for curr_dev_interface in dev_interfaces:

        cleaned_params = {}
        for curr_param in ['description','mac','mtu','name','parent','type']:
            try:
                if curr_dev_interface[curr_param] == None:
                    continue
            except KeyError:
                continue
            cleaned_params[curr_param] = curr_dev_interface[curr_param]

        if curr_dev_interface['name'] in nb_interface_dict:
            # Update
            
            curr_nb_obj = nb_interface_dict[curr_dev_interface['name']]
            changed = {}
            for k,v in cleaned_params.items():
                # Only update if different

                # Type's get has the value in type.value vs type itself.
                # Ugly hack for now.
                if k == 'type': 
                    if curr_nb_obj.type.value != v:
                        changed[k] = {
                            'old': str(curr_nb_obj.type.value),
                            'new': v,
                        }
                        curr_nb_obj.type = v
                elif k == 'parent':
                    if v:
                        nb_parent_interfaces = nb.dcim.interfaces.filter(device=device_nb.name,name=v)
                        new_parent_desc = "{0}/{1}".format(nb_parent_interfaces[0].id, v)
                        new_parent = nb_parent_interfaces[0].id
                    else:
                        # Its None
                        new_parent_desc = "{0}".format(v)

                    if curr_nb_obj.parent:
                        old_parent_desc = "{0}/{1}".format(curr_nb_obj.parent.id, nb_parent_interfaces[0].name)
                    else:
                        old_parent_desc = "None"

                    if new_parent_desc != old_parent_desc:
                        changed[k] = {
                            'old': old_parent_desc,
                            'new': new_parent_desc,
                        }
                        setattr(curr_nb_obj, k, new_parent)
                elif getattr(curr_nb_obj,k) != v:
                    changed[k] = {
                        'old': getattr(curr_nb_obj,k),
                        'new': v,
                    }
                    setattr(curr_nb_obj, k, v)
                    

            if changed:
                logger.debug("Updating '{0}' on '{1}' => {2}".format(curr_dev_interface['name'], device_nb.name, changed))
                curr_nb_obj.save()
        else:
            # Create
            if 'type' not in cleaned_params:
                # Type is mandatory
                cleaned_params['type'] = 'other'

            if 'parent' in cleaned_params:
                # Parent needs to be converted from the name to its id.
                if cleaned_params['parent'] != None:
                    nb_parent_interfaces = nb.dcim.interfaces.filter(device=device_nb.name,name=v)
                    try:
                        cleaned_params['parent'] = nb_parent_interfaces[0].id
                    except (KeyError,AttributeError):
                        logger.error("Unable to fetch parent interface '{0}' => '{1}'".format(device_nb.name, v))
                        cleaned_params['parent'] = None

            logger.debug("Creating '{0}' on '{1}' => {2}".format(curr_dev_interface['name'], device_nb.name, cleaned_params))
            nb.dcim.interfaces.create(device=device_nb.id, **cleaned_params)
            #TODO: Error checking?

    # Delete extra interfaces
    nb_interfaces_to_delete = filter(lambda x: x.name in to_delete_from_nb, nb_interfaces)
    for curr_int_to_delete in nb_interfaces_to_delete:
        curr_int_to_delete.delete()


    return


def sync_ips(nb, device_nb, device_conn):
    '''
    
    '''

    # - IP Addresses - The matching interfaces should already exist (create the matching prefixes)
    dev_ips = device_conn.get_ipaddresses()
    #pprint.pprint(dev_ips, width = 200)

    # We need the interfaces to map the interface name to the netbox id.
    nb_interfaces = nb.dcim.interfaces.filter(device=device_nb.name)
    nb_interface_dict = {v.name:v for v in nb_interfaces}

    for curr_ip in dev_ips:
        # logger.debug("Processing IP address: {0}".format(curr_ip))
        if curr_ip['interface'] not in nb_interface_dict:
            logger.error("Missing interface for IP: {1}".format(curr_ip))
            continue

        nb_ip_network = nb.ipam.prefixes.filter(prefix=str(curr_ip['address'].network))
        if not nb_ip_network:
            logger.error("Creating prefix: {0}".format(curr_ip['address'].network))
            nb.ipam.prefixes.create(
                prefix="{0}".format(curr_ip['address'].network),
                vrf=curr_ip['vrf'],
                status='active',
            )

        nb_ip_record = nb.ipam.ip_addresses.filter(address=curr_ip['address'])
        if nb_ip_record:
            if len(nb_ip_record) == 1:
                # Update
                changed = False

                if nb_ip_record[0].assigned_object_id != nb_interface_dict[curr_ip['interface']].id or \
                   nb_ip_record[0].assigned_object_type != 'dcim.interface':
                    nb_ip_record[0].assigned_object_id = nb_interface_dict[curr_ip['interface']].id
                    nb_ip_record[0].assigned_object_type = 'dcim.interface'
                    changed = True

                if nb_ip_record[0].status.value != curr_ip['status']:
                    nb_ip_record[0].status = curr_ip['status']
                    changed = True

                if nb_ip_record[0].vrf != curr_ip['vrf']:
                    nb_ip_record[0].vrf = curr_ip['vrf']
                    changed = True

                if changed == True:
                    logger.info("Updating IP record: {0}".format(curr_ip))
                    nb_ip_record[0].save()
            else:
                logger.error("Multiple IPs found for: {0}".format(curr_ip['address']))
                continue
        else:
            # Create
            logger.info("Creating IP record: {0}".format(curr_ip))
            nb.ipam.ip_addresses.create(
                assigned_object_id=nb_interface_dict[curr_ip['interface']].id,
                assigned_object_type='dcim.interface',
                address=str(curr_ip['address']),
                status=curr_ip['status'],
                vrf=curr_ip['vrf'],
            )

    return

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

        devices_to_try = [
            'DC-GML-CE1',
            'DC-GML-CE2',
            'DC-BRZ-CE1',
            'DC-BRZ-CE3',
            'DC-MDV-IE1',
            'DC-NAP-IE2',
            'DC-DC1-SPINE1'
        ]

        if device_nb.name not in devices_to_try:
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

        
        sync_interfaces(nb, device_nb, device_conn)
        sync_ips(nb, device_nb, device_conn)

        # sync_vlans()
        # sync_routes(nb, device_nb, device_conn)
        # sync_neighbours(nb, device_nb, device_conn)


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

    logger.info("Main() - Done")


main()
