'''





'''

import ipaddress
import logging
import pprint
import pynetbox
import re
import sys
import traceback

# Local imports
import config
import drivers.edgeos
import drivers.junos
import drivers.routeros
import utils

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
    #logger.info("Interface data for '{0}'\n{1}".format(device_nb.name,
    #    pprint.pformat(dev_interfaces, width=200)))

    to_add_to_netbox = sorted(list(dev_interfaces_names.difference(nb_interfaces_names)))
    to_check_for_updates = sorted(list(nb_interfaces_names.intersection(dev_interfaces_names)))
    to_delete_from_nb = sorted(list(nb_interfaces_names.difference(dev_interfaces_names)))
    #logger.debug("\nAdd: {0}\nDel: {1}\nUpdate: {2}".format(to_add_to_netbox, to_delete_from_nb, to_check_for_updates))

    for curr_dev_interface in dev_interfaces:

        cleaned_params = {}
        for curr_param in ['bridge','description','lag','mac','mtu','name','parent','type']:
            try:
                if curr_dev_interface[curr_param] is None:
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
                elif k in ['bridge','lag','parent']:
                    if v:
                        try:
                            nb_parent_interfaces = nb.dcim.interfaces.filter(device=device_nb.name,name=v)
                            new_parent_desc = "{0}/{1}".format(nb_parent_interfaces[0].id, v)
                            new_parent = nb_parent_interfaces[0].id
                        except IndexError:
                            logger.error("Could not look up parent interface for '{0}".format(
                                curr_dev_interface
                            ))
                            continue
                    else: # The parent interface is None
                        new_parent_desc = "{0}".format(v)

                    
                    if k_attr := getattr(curr_nb_obj, k):
                        old_parent_desc = "{0}/{1}".format(k_attr.id, nb_parent_interfaces[0].name)
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
                logger.info("Updating '{0}' on '{1}' => {2}".format(curr_dev_interface['name'], device_nb.name, changed))
                curr_nb_obj.save()
        else:
            # Create interface
            if 'type' not in cleaned_params:
                # Type is mandatory
                cleaned_params['type'] = 'other'

            for master_interface in ['bridge','lag','parent']:
                if master_interface in cleaned_params and cleaned_params[master_interface] != None:
                        nb_parent_interfaces = nb.dcim.interfaces.filter(device=device_nb.name,name=cleaned_params[master_interface])
                        try:
                            cleaned_params[master_interface] = nb_parent_interfaces[0].id
                        except (IndexError, KeyError, AttributeError):
                            logger.error("Unable to fetch parent interface '{0}' => '{1}'".format(device_nb.name, cleaned_params[master_interface]))
                            cleaned_params[master_interface] = None

            logger.info("Creating '{0}' on '{1}' => {2}".format(curr_dev_interface['name'], device_nb.name, cleaned_params))
            try:
                nb.dcim.interfaces.create(device=device_nb.id, **cleaned_params)
            except pynetbox.core.query.RequestError as e:
                logger.error("Netbox API Error '{0}' creating interface {1}/{2}".format(e, cleaned_params, device_nb.name))
                continue
            except Exception as e:
                logger.error("Error '{0}' creating interface {1}/{2}".format(e, cleaned_params, device_nb.name))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                logger.error(pprint.pformat(traceback.format_exception(exc_type, exc_value, exc_traceback)))
            #TODO: Error checking?

    # Delete extra interfaces
    nb_interfaces_to_delete = filter(lambda x: x.name in to_delete_from_nb, nb_interfaces)
    for curr_int_to_delete in nb_interfaces_to_delete:
        curr_int_to_delete.delete()

    return

def create_ip_address(nb, curr_ip, nb_interface_dict) -> None:
    logger.info("Creating IP record: {0}".format(curr_ip))
    nb.ipam.ip_addresses.create(
        assigned_object_id=nb_interface_dict[curr_ip['interface']].id,
        assigned_object_type='dcim.interface',
        address=str(curr_ip['address']),
        status=curr_ip['status'],
        vrf=curr_ip['vrf'],
    )
    return

def update_ip_address(curr_ip, nb_ip_record, nb_interface_dict) -> None:
    logger.debug("Checking IP record for changes: {0}".format(curr_ip))
    if len(nb_ip_record) == 1:
        changed = False

        if nb_ip_record[0].assigned_object_id != nb_interface_dict[curr_ip['interface']].id or \
            nb_ip_record[0].assigned_object_type != 'dcim.interface':
            logger.info("Updating IP interface from '{2}': {0} -> {1}".format(
                nb_ip_record[0].assigned_object_id,
                nb_interface_dict[curr_ip['interface']].id,
                nb_ip_record[0].assigned_object_type,
            ))
            nb_ip_record[0].assigned_object_id = nb_interface_dict[curr_ip['interface']].id
            nb_ip_record[0].assigned_object_type = 'dcim.interface'
            changed = True

        if nb_ip_record[0].status.value != curr_ip['status']:
            logger.info("Updating status: {0} -> {1}".format(nb_ip_record[0].status.value, curr_ip['status']))
            nb_ip_record[0].status = curr_ip['status']
            changed = True

        if nb_ip_record[0].vrf != curr_ip['vrf']:
            nb_ip_record[0].vrf = curr_ip['vrf']
            logger.info("Updating vrf")
            changed = True

        if changed:
            logger.info("Updating IP record: {0} -> {1}".format(curr_ip, changed))
            nb_ip_record[0].save()
    else:
        logger.error("Multiple IPs found for: {0}".format(curr_ip['address']))

    return

def sync_ips(nb, device_nb, device_conn) -> None:
    '''
    
    '''

    # - IP Addresses - The matching interfaces should already exist (create the matching prefixes)
    dev_ips = device_conn.get_ipaddresses()
    logger.debug("Raw IP data for '{0}'\n{1}".format(device_nb.name, pprint.pformat(dev_ips, width=200)))

    # We need the interfaces to map the interface name to the netbox id.
    nb_ipaddresses = nb.ipam.ip_addresses.filter(device=device_nb.name)
    nb_ipaddresses_dict = {ipaddress.ip_interface(v.address):v for v in nb_ipaddresses}
    nb_interfaces = nb.dcim.interfaces.filter(device=device_nb.name)
    nb_interface_dict = {v.name:v for v in nb_interfaces}
    nb_interface_id_list = list(map(lambda x: x.id, nb_interfaces))

    for curr_ip in dev_ips:
        logger.debug("Processing IP address: {0}".format(curr_ip))
        if curr_ip['interface'] not in nb_interface_dict:
            logger.error("Missing interface for IP: {0}".format(curr_ip))
            continue

        nb_ip_network = nb.ipam.prefixes.filter(prefix=str(curr_ip['address'].network))
        if not nb_ip_network:
            logger.error("Creating prefix: {0}".format(curr_ip['address'].network))
            nb.ipam.prefixes.create(
                prefix="{0}".format(curr_ip['address'].network),
                vrf=curr_ip['vrf'],
                status='active',
            )

        
        if nb_ip_record := nb.ipam.ip_addresses.filter(address=curr_ip['address']):
            # We only want to update if its on the same device.
            if nb_ip_record[0].assigned_object_type == 'dcim.interface' \
                and nb_ip_record[0].assigned_object_id in nb_interface_id_list:
                update_ip_address(curr_ip, nb_ip_record, nb_interface_dict)
            else:
                create_ip_address(nb, curr_ip, nb_interface_dict)
        else:
            create_ip_address(nb, curr_ip, nb_interface_dict)

    # Now we need to check for those that need to be removed from netbox
    to_del = set(nb_ipaddresses_dict.keys()).difference(set(map(lambda x: x['address'], dev_ips)))
    for curr_to_del in to_del:
        logger.info("Deleting IP record: {0}".format(nb_ipaddresses_dict[curr_to_del]))
        nb_ipaddresses_dict[curr_to_del].delete()

    return

def main() -> None:
    '''
    '''

    BASIC_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    # Upstream libraries
    logging.getLogger('ncclient').setLevel(logging.ERROR)
    logging.getLogger('paramiko.transport').setLevel(logging.ERROR)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    # Internal modules
    logging.getLogger('__main__').setLevel(logging.INFO)
    logging.getLogger('drivers.edgeos').setLevel(logging.DEBUG)
    logging.basicConfig(level = logging.INFO, format=BASIC_FORMAT)

    # How best to make this dynamic (likely factory method)
    # Drivers for use to fetch the data from devices:
    # - EdgeRouter
    platform_to_driver = {
        'JunOS':            drivers.junos.JunOS,
        'RouterOS':         drivers.routeros.RouterOS,
        'Ubiquiti EdgeOS':  drivers.edgeos.EdgeOS,
    }

    nb = pynetbox.api(config.NB_URL, token=config.NB_TOKEN, threading = True)

    device_credentials = utils.parse_device_parameters(config)

    # Fetch and process the devices from netbox.
    devices = nb.dcim.devices.all()

    for device_nb in devices:
        logger.info("Processing device: {0:04}/{1} => {2} => {3}".format(
            device_nb.id, device_nb.name, device_nb.platform,
            device_nb.primary_ip,
        ))

        if device_nb.platform is None:
            continue

        if device_nb.status.value not in ['active']:
            continue

        try:
            driver = platform_to_driver[str(device_nb.platform)]
        except KeyError:
            logger.error("Unsupported platform '{0}'".format(device_nb.platform))
            continue

        # if device_nb.name not in []:
        #     continue

        if device_nb.primary_ip is None:
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

        try:
            # Now to sync the data
            sync_interfaces(nb, device_nb, device_conn)
            sync_ips(nb, device_nb, device_conn)

            # sync_vlans()
            # sync_routes(nb, device_nb, device_conn)
            # sync_neighbours(nb, device_nb, device_conn)
        except Exception as e:
            logger.error("There was an error syncing '{2}': {0}, {1}".format(e.__class__, e, device_ip))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logger.error(pprint.pformat(traceback.format_exception(exc_type, exc_value, exc_traceback)))
        
        # To Sync
        # - Vlans - Only for devices in charge of the vlan domain
        # - Static routes - Use to update prefixes
        # - Neighbour data (LLDP / CDP) - For building neighbour relations and rough cable plant.

        del device_conn

    logger.info("Done")


main()
