'''





'''


import logging
import pynetbox

import config

import drivers.junos
import drivers.routeros

platform_to_driver = {
    'junos': drivers.junos,
    'routeros': drivers.routeros,
}

logger = logging.getLogger(__name__)

def main() -> None:
    '''
    '''

    BASIC_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    #logging.getLogger('pyzabbix').setLevel(logging.ERROR)
    #logging.getLogger('paramiko.transport').setLevel(logging.ERROR)
    #logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)
    #logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
    logging.basicConfig(level = logging.DEBUG, format=BASIC_FORMAT)

    nb = pynetbox.api(config.NB_URL, token=config.NB_TOKEN, threading = True)

    devices = nb.dcim.devices.all()

    for device in devices:
        logger.info("Processing device: {0} => {1}".format(device.name, device.platform))

        # To Sync
        # - Interfaces:
        # -- flag the routing instance / logical systems (use VRF to keep track of this)
        # -- On SRXes use tags to flag the security-zones
        # - IP Addresses - The matching interfaces should already exist (create the matching prefixes)
        # - Vlans - Only for devices in charge of the vlan domain
        # - Static routes - Use to update prefixes
        # - Neighbour data (LLDP / CDP) - For building neighbour relations and rough cable plant.
        # 
        # Drivers for use to fetch the data from devices:
        # - Mikrotik
        # - JunOS
        # - EdgeRouter


main()
