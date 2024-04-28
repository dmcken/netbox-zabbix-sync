'''
General utilities
'''
# System imports
import argparse
import functools

def rsetattr(obj, attr, val):
    '''Recursive setattr'''
    pre, _, post = attr.rpartition('.')
    return setattr(rgetattr(obj, pre) if pre else obj, post, val)

# using wonder's beautiful simplification:
# https://stackoverflow.com/questions/31174295/getattr-and-setattr-on-nested-objects/31174427?noredirect=1#comment86638618_31174427

def rgetattr(obj, attr, *args):
    '''Recursive getattr'''
    def _getattr(obj, attr):
        return getattr(obj, attr, *args)
    return functools.reduce(_getattr, [obj] + attr.split('.'))

def parse_args():
    '''Parse CLI args and return the results.
    '''
    # Arguments parsing
    parser = argparse.ArgumentParser(
        description='A script to sync Zabbix with Netbox device data.'
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Turn on debugging.",
        action="store_true",
    )
    parser.add_argument(
        "-c", "--cluster",
        action="store_true",
        help=(
            "Only add the primary node of a cluster to Zabbix. Useful when a "
            "shared virtual IP is used for the control plane."
        ),
    )
    parser.add_argument(
        "-t", "--tenant",
        action="store_true",
        help="Add Tenant name to the Zabbix hostgroup name scheme.",
    )
    parser.add_argument(
        "-p", "--proxy_power",
        action="store_true",
        help=(
            "USE WITH CAUTION. If there is a proxy configured in Zabbix but "
            "not in Netbox, sync the device and remove the host - proxy "
            "link in Zabbix."
        ),
    )
    parser.add_argument(
        "-j", "--journal",
        action="store_true",
        help="Create journal entries in Netbox at write actions"
    )
    return parser.parse_args()
