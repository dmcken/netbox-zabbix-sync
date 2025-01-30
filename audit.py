
# System imports
import datetime
import logging
import os
import pprint

# External imports
import pynetbox
import pyzabbix

# Local imports
import utils

logger = logging.getLogger(__name__)

def audit() -> None:
    '''Run audit tasks
    '''

    # Get CLI args
    arguments = utils.parse_args()

    utils.setup_logging(logger, arguments, 'audit')

    config = utils.fetch_sync_config()

    # Connect to netbox & zabbix
    zabbix = utils.connect_zabbix(config)
    netbox = utils.connect_netbox(config)

    # Get hosts with 'Not Available' status
    hosts = zabbix.host.get(
        output=['active_available','hostid', 'name', 'status'],
        selectTags=['tag', 'value'],
        selectInterfaces=['available','type']
    )

    for host in hosts:
        interface_statuses = set(map(lambda x: x['available'], host['interfaces']))
        if interface_statuses == set('2'):
            logger.error(f"Unavailable host ID: {host['hostid']}, Host Name: {host['name']}")
            continue

        if 'tags' in host:
            tags_dict = utils.parse_tags(host['tags'])
            logger.error(f"Host: {host}\nTags: {tags_dict}")
            #print(f"")


if __name__ == '__main__':
    audit()
