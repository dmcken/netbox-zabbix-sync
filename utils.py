'''
General utilities
'''
# System imports
import argparse
import datetime
import functools
import logging
import os
import sys

# External imports
import dotenv
import pynetbox
import pyzabbix

# Local imports
from exceptions import *

logger = logging.getLogger(__name__)

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

def setup_logging(caller_logger, arguments, file_prefix) -> None:
    '''Setup logging for application.

    '''
    log_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    lgout = logging.StreamHandler(stream=sys.stdout)
    lgout.setFormatter(log_format)
    lgout.setLevel(logging.DEBUG)

    lgfile = logging.FileHandler(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            f"{file_prefix}-{datetime.datetime.now().strftime('%Y-%m-%d')}.log",
        )
    )
    lgfile.setFormatter(log_format)
    lgfile.setLevel(logging.DEBUG)

    caller_logger.addHandler(lgout)
    caller_logger.addHandler(lgfile)
    caller_logger.setLevel(logging.WARNING)

    # Change log level based on CLI arguments
    if arguments.verbose:
        caller_logger.warning("Setting log level to debug")
        caller_logger.setLevel(logging.DEBUG)

def connect_netbox(config: dict):

    netbox = pynetbox.api(
        url       = config["NETBOX_HOST"],
        token     = config["NETBOX_TOKEN"],
        threading = True,
    )
    return netbox


def connect_zabbix(config):
    '''Connect to zabbix API.

    Use token if present or username and password if not.

    Fails if neither are present
    '''
    try:
        connect_params = {}
        if config['ZABBIX_TOKEN']:
            connect_params['api_token'] = config['ZABBIX_TOKEN']
        elif config['ZABBIX_USER'] and config['ZABBIX_PASS']:
            connect_params['user']     = config['ZABBIX_USER']
            connect_params['password'] = config['ZABBIX_PASS']
        else:
            raise EnvironmentVarError("ZABBIX_TOKEN or the combination of "
                "ZABBIX_USER and ZABBIX_PASS must be defined")

        zabbix = pyzabbix.ZabbixAPI(config["ZABBIX_HOST"])
        zabbix.login(**connect_params)
    except pyzabbix.ZabbixAPIException as exc:
        exc_msg = f"Zabbix returned the following error: {str(exc)}."
        logger.error(exc_msg)

    return zabbix

def fetch_sync_config():
    '''Fetches config parameters for the netbox to zabbix sync.

    Checks for missing environment variable first
    '''
    dotenv.load_dotenv()

    config = {}
    env_vars = [
        "ZABBIX_HOST",
        "ZABBIX_USER",
        "ZABBIX_PASS",
        "ZABBIX_TOKEN",
        "NETBOX_HOST",
        "NETBOX_TOKEN",
        "NETBOX_ROLE_IGNORE",
    ]
    for var in env_vars:
        config[var] = os.environ.get(var, None)

    # Parse the config entries that require it.
    if config["NETBOX_ROLE_IGNORE"] is not None:
        parts = config["NETBOX_ROLE_IGNORE"].split(',')
        config["NETBOX_ROLE_IGNORE"] = parts

    return config

def parse_tags(tags_list: list[dict]) -> dict:
    """Parse zabbix tags to a dictionary.

    Args:
        tags_list (list[dict]): _description_

    Returns:
        dict: _description_
    """
    return {tag['tag']:tag['value'] for tag in tags_list}
