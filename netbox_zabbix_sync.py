#!/usr/bin/python3
"""
Sync Netbox devices to Zabbix for monitoring.



"""

# System imports
import argparse
import datetime
import logging
import os
import pprint

# External imports
import dotenv
import pynetbox
import pyzabbix

# Local imports
import utils

# Setup logging
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
lgout = logging.StreamHandler()
lgout.setFormatter(log_format)
lgout.setLevel(logging.DEBUG)

lgfile = logging.FileHandler(
    os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        f"sync-{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.log",
    )
)
lgfile.setFormatter(log_format)
lgfile.setLevel(logging.DEBUG)

logger = logging.getLogger("netbox-zabbix-sync")
logger.addHandler(lgout)
logger.addHandler(lgfile)
logger.setLevel(logging.WARNING)

# Set template and device Netbox "custom field" names
TEMPLATE_CF = "zabbix_template"
DEVICE_CF = "zabbix_hostid"

# Netbox to Zabbix device state convertion
zabbix_device_removal = ["Decommissioning", "Inventory"]
zabbix_device_disable = ["Offline", "Planned", "Staged", "Failed"]

# Exceptions
class SyncError(Exception):
    '''Any errors when sync'ing a device'''

class SyncExternalError(SyncError):
    pass

class SyncInventoryError(SyncError):
    pass

class SyncDuplicateError(SyncError):
    pass

class EnvironmentVarError(SyncError):
    pass

class InterfaceConfigError(SyncError):
    pass

class ProxyConfigError(SyncError):
    pass

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

def main(arguments):
    """Run the sync process.
    """
    # set environment variables
    if arguments.verbose:
        logger.warning("Setting log level to debug")
        logger.setLevel(logging.DEBUG)

    config = fetch_sync_config()

    zabbix = connect_zabbix(config)

    # Set Netbox API and fetch data
    netbox = pynetbox.api(
        url       = config["NETBOX_HOST"],
        token     = config["NETBOX_TOKEN"],
        threading = True,
    )

    # Fetch zabbix data
    zabbix_templates = zabbix.template.get(output=['name'])
    zabbix_proxys    = zabbix.proxy.get(output=['host'])

    # Fetch netbox data
    netbox_devices  = netbox.dcim.devices.all()
    netbox_journals = netbox.extras.journal_entries

    # Go through all Netbox devices
    for nb_device in netbox_devices:
        try:
            # Ignore rules
            if nb_device.device_role.slug in config['NETBOX_ROLE_IGNORE']:
                logger.debug(f"Skipping host: {nb_device.name}")
                continue

            # Lets start dealing with the device
            device = NetworkDevice(
                nb_device,
                zabbix,
                netbox_journals,
                arguments.journal
            )
            # Checks if device is part of cluster.
            # Requires the cluster argument.
            if device.isCluster() and arguments.cluster:
                # Check if device is master or slave
                if device.promoteMasterDevice():
                    err_msg = f"Device {device.name} is part of " +\
                        "cluster and primary."
                    logger.info(err_msg)
                else:
                    # Device is secondary in cluster.
                    # Don't continue with this device.
                    err_msg = f"Device {device.name} is part of cluster " \
                              f"but not primary. Skipping this host..."
                    logger.info(err_msg)
                    continue

            # Checks if device is in cleanup state
            if device.status in zabbix_device_removal:
                if device.zabbix_id :
                    # Delete device from Zabbix
                    # and remove hostID from Netbox.
                    device.cleanup()
                    logger.info(f"Cleaned up host {device.name}.")

                else:
                    # Device has been added to Netbox
                    # but is not in Activate state
                    logger.info(
                        f"Skipping host {device.name} since its "
                        f"not in the active state."
                    )
                continue
            elif device.status in zabbix_device_disable:
                device.zabbix_state = 1

            # Setup the host groups, wasteful for the time being
            # to handle the creation of new groups, might just be best to
            # query the groups I want for this host in the create hostgroups function
            zabbix_groups    = zabbix.hostgroup.get(output=['name'])
            zabbix_groups_map = {v['name']:v for v in zabbix_groups}
            host_group_data = device.create_zabbix_hostgroups(zabbix_groups_map)

            zabbix_groups    = zabbix.hostgroup.get(output=['groupid', 'name'])
            zabbix_groups_map = {v['name']:v for v in zabbix_groups}

            if device.zabbix_id: # Update Zabbix
                device.consistency_check(
                    zabbix_groups_map,
                    zabbix_templates,
                    zabbix_proxys,
                    arguments.proxy_power,
                )
            else: # Add to Zabbix
                device.create_in_zabbix(
                    zabbix_groups,
                    zabbix_groups_map,
                    zabbix_templates,
                    zabbix_proxys
                )
        except SyncError:
            pass

class NetworkDevice():
    """
    Represents Network device.
    INPUT: (Netbox device class, ZabbixAPI class, journal flag, NB journal class)
    """

    def __init__(self, nb_device, zabbix, nb_journal_class, journal=None):
        self.nb = nb_device
        self.id = nb_device.id
        self.name = nb_device.name
        self.status = nb_device.status.label
        self.zabbix = zabbix
        self.zabbix_id = None
        self.tenant = nb_device.tenant
        self.template_id = None
        self.hostgroup = None # Should no longer be needed
        self.hostgroups = []
        self.zbxproxy = "0"
        self.zabbix_state = 0
        self.hg_format = [ # Should no longer be needed
            self.nb.site.name,
            self.nb.device_type.manufacturer.name,
            self.nb.device_role.name
        ]
        self.journal = journal
        self.nb_journals = nb_journal_class
        self._setBasics()
        self.setHostgroup()
        self.set_host_groups()

        logger.info(f"Host groups: {pprint.pformat(self.hostgroups)}")

    def _setBasics(self):
        """
        Sets basic information like IP address.
        """
        # Return error if device does not have primary IP.
        if self.nb.primary_ip:
            self.cidr = self.nb.primary_ip.address
            self.ip = self.cidr.split("/")[0]
        else:
            e = f"Device {self.name}: no primary IP."
            logger.warning(e)
            raise SyncInventoryError(e)

        # Check if device_type has custom field
        device_type_cf = self.nb.device_type.custom_fields
        if TEMPLATE_CF in device_type_cf:
            self.template_name = device_type_cf[TEMPLATE_CF]
        else:
            e = (f"Custom field {TEMPLATE_CF} not "
                 f"found for {self.nb.device_type.name}.")
            logger.warning(e)
            raise SyncInventoryError(e)

        # Check if device has custom field
        if DEVICE_CF in self.nb.custom_fields:
            self.zabbix_id = self.nb.custom_fields[DEVICE_CF]
        else:
            e = f"Custom field {TEMPLATE_CF} not found for {self.name}."
            logger.warning(e)
            raise SyncInventoryError(e)

    def setHostgroup(self):
        """Sets hostgroup to a string with hg_format parameters.

        Depreciated
        """
        self.hostgroup = "/".join(self.hg_format)

    def set_host_groups(self):
        '''
        Sets the various hostgroups desired

        These will be of the format:
        Location - [Location Name]
        Rack - [Rack Name]
        Site - [Site Name]
        Role - [Device Role]
        Tenant - [Tenant Name]

        '''
        groups = {
            'Location': 'location.name',
            'Rack': 'rack.name',
            'Site': 'site.name',
            'Role': 'device_role.name',
            'Tenant': 'tenant.name',
        }
        for name, loc in groups.items():
            value = utils.rgetattr(self.nb, loc, None)
            if value:
                self.hostgroups.append(f"{name} - {value}")

    def create_zabbix_hostgroups(self, zabbix_groups_map):
        """Creates Zabbix host group based on hostgroup format.
        """
        group_data = []
        for curr_hostgroup in self.hostgroups:
            try:
                # test if the group exists.
                if curr_hostgroup in zabbix_groups_map:
                    # The group already exists
                    continue
                groupid = self.zabbix.hostgroup.create(name=curr_hostgroup)
                logger.info(f"Added hostgroup '{self.hostgroup}'.")
                group_data.append({
                    'groupid': groupid["groupids"][0],
                    'name': self.hostgroup
                })
            except pyzabbix.ZabbixAPIException as exc:
                exc_msg = f"Couldn't add hostgroup {curr_hostgroup}, Zabbix returned {str(exc)}."
                logger.error(exc_msg)
                raise SyncExternalError(exc_msg) from exc

        return group_data

    def isCluster(self):
        """
        Checks if device is part of cluster.
        """
        if self.nb.virtual_chassis:
            return True
        else:
            return False

    def getClusterMaster(self):
        """
        Returns chassis master ID.
        """
        if not self.isCluster():
            e = f"Unable to proces {self.name} for cluster calculation: not part of a cluster."
            logger.warning(e)
            raise SyncInventoryError(e)
        else:
            return self.nb.virtual_chassis.master.id

    def promoteMasterDevice(self):
        """
        If device is Primary in cluster,
        promote device name to the cluster name.
        Returns True if succesfull, returns False if device is secondary.
        """
        masterid = self.getClusterMaster()
        if masterid == self.id:
            logger.debug(f"Device {self.name} is primary cluster member. "
                         f"Modifying hostname from {self.name} to " +
                         f"{self.nb.virtual_chassis.name}.")
            self.name = self.nb.virtual_chassis.name

            return True
        else:
            logger.debug(f"Device {self.name} is non-primary cluster member.")
            return False

    def getZabbixTemplate(self, templates):
        """
        Returns Zabbix template ID
        INPUT: list of templates
        OUTPUT: True
        """
        if not self.template_name:
            e = (
                f"Device template '{self.nb.device_type.display}' "
                "has no Zabbix template defined."
            )
            logger.info(e)
            raise SyncInventoryError()
        for template in templates:
            if template['name'] == self.template_name:
                self.template_id = template['templateid']
                e = (f"Found template ID {str(template['templateid'])} "
                     f"for host {self.name}.")
                logger.debug(e)
                return True
        else:
            err_msg = (
                f"Unable to find template {self.template_name} "
                f"for host {self.name} in Zabbix."
            )
            logger.warning(err_msg)
            raise SyncInventoryError(err_msg)

    def getZabbixGroup(self, groups):
        """
        Returns Zabbix group ID
        INPUT: list of hostgroups
        OUTPUT: True / False
        """
        # Go through all groups
        for group in groups:
            if group['name'] == self.hostgroup:
                self.group_id = group['groupid']
                e = (f"Found group {group['name']} for host {self.name}.")
                logger.debug(e)
                return True
        else:
            err_msg = (
                f"Unable to find group '{self.hostgroup}' "
                f"for host {self.name} in Zabbix."
            )
            logger.warning(err_msg)
            raise SyncInventoryError(err_msg)

    def cleanup(self):
        """
        Removes device from external resources.
        Resets custom fields in Netbox.
        """
        if self.zabbix_id:
            try:
                self.zabbix.host.delete(self.zabbix_id)
                self.nb.custom_fields[DEVICE_CF] = None
                self.nb.save()
                e = f"Deleted host {self.name} from Zabbix."
                logger.info(e)
                self.create_journal_entry("warning", "Deleted host from Zabbix")
            except pyzabbix.ZabbixAPIException as exc:
                err_msg = f"Zabbix returned the following error: {str(exc)}."
                logger.error(err_msg)
                raise SyncExternalError(err_msg) from exc

    def _zabbixHostnameExists(self):
        """
        Checks if hostname exists in Zabbix.
        """
        host = self.zabbix.host.get(filter={'name': self.name}, output=[])
        if host:
            return True
        else:
            return False

    def setInterfaceDetails(self):
        """
        Checks interface parameters from Netbox and
        creates a model for the interface to be used in Zabbix.
        """
        try:
            # Initiate interface class
            interface = ZabbixInterface(self.nb.config_context, self.ip)
            # Check if Netbox has device context.
            # If not fall back to old config.
            if interface.get_context():
                # If device is SNMP type, add aditional information.
                if interface.interface["type"] == 2:
                    interface.set_snmp()
            else:
                interface.set_default()
            return [interface.interface]
        except InterfaceConfigError as e:
            e = f"{self.name}: {e}"
            logger.warning(e)
            raise SyncInventoryError(e)

    def setProxy(self, proxy_list):
        # check if Zabbix Proxy has been defined in config context
        if "zabbix" in self.nb.config_context:
            if "proxy" in self.nb.config_context["zabbix"]:
                proxy = self.nb.config_context["zabbix"]["proxy"]
                # Try matching proxy
                for px in proxy_list:
                    if px["host"] == proxy:
                        self.zbxproxy = px["proxyid"]
                        logger.debug(f"Found proxy {proxy}"
                                     f" for {self.name}.")
                        return True
                else:
                    err_msg = f"{self.name}: Defined proxy {proxy} not found."
                    logger.warning(err_msg)
                    return False

    def create_in_zabbix(self, groups, zabbix_groups_map, templates, proxys,
                       description="Host added by Netbox sync script."):
        """
        Creates Zabbix host object with parameters from Netbox object.
        """
        # Check if hostname is already present in Zabbix
        if not self._zabbixHostnameExists():
            # Get group IDs for host
            n_host_group_ids = []
            for curr_group in self.hostgroups:
                try:
                    n_host_group_ids.append(zabbix_groups_map[curr_group]['groupid'])
                except KeyError:
                    logger.error(f"Missing 'groupid' on: {curr_group}")
                    raise
            n_host_group_ids = sorted(map(lambda x: int(x), n_host_group_ids))
            groups = list(map(lambda x: {'groupid': x}, n_host_group_ids))

            # Set template IDs
            self.getZabbixTemplate(templates)

            # Set interface, group and template configuration
            interfaces = self.setInterfaceDetails()
            templates = [{"templateid": self.template_id}]

            # Set Zabbix proxy if defined
            self.setProxy(proxys)

            # Add host to Zabbix
            try:
                host = self.zabbix.host.create(
                    host=self.name,
                    status=self.zabbix_state,
                    interfaces=interfaces,
                    groups=groups,
                    templates=templates,
                    proxy_hostid=self.zbxproxy,
                    description=description,
                )
                self.zabbix_id = host["hostids"][0]
            except pyzabbix.ZabbixAPIException as exc:
                err_msg = f"Couldn't add {self.name}, Zabbix returned {str(exc)}."
                logger.error(err_msg)
                raise SyncExternalError(err_msg) from exc
            # Set Netbox custom field to hostID value.
            self.nb.custom_fields[DEVICE_CF] = int(self.zabbix_id)
            self.nb.save()
            msg = f"Created host {self.name} in Zabbix."
            logger.info(msg)
            self.create_journal_entry("success", msg)
        else:
            logger.warning(f"Unable to add {self.name} to Zabbix: host already present.")

    def createZabbixHostgroup(self):
        """
        Creates Zabbix host group based on hostgroup format.
        """
        try:
            groupid = self.zabbix.hostgroup.create(name=self.hostgroup)
            e = f"Added hostgroup '{self.hostgroup}'."
            logger.info(e)
            data = {'groupid': groupid["groupids"][0], 'name': self.hostgroup}
            return data
        except pyzabbix.ZabbixAPIException as exc:
            err_msg = f"Couldn't add hostgroup, Zabbix returned {str(exc)}."
            logger.error(err_msg)
            raise SyncExternalError(err_msg) from exc

    def updateZabbixHost(self, **kwargs):
        """
        Updates Zabbix host with given parameters.
        INPUT: Key word arguments for Zabbix host object.
        """
        try:
            self.zabbix.host.update(hostid=self.zabbix_id, **kwargs)
        except pyzabbix.ZabbixAPIException as exc:
            err_msg = f"Zabbix returned the following error: {str(exc)}."
            logger.error(err_msg)
            raise SyncExternalError(err_msg) from exc
        logger.info(f"Updated host {self.name} with data {kwargs}.")
        self.create_journal_entry("info", "Updated host in Zabbix with latest NB data.")

    def consistency_check(self, zabbix_groups_map, templates, proxys, proxy_power):
        """
        Checks if Zabbix object is still valid with Netbox parameters.
        """
        self.getZabbixTemplate(templates)
        self.setProxy(proxys)
        host = self.zabbix.host.get(
            filter={'hostid': self.zabbix_id},
            selectInterfaces=[
                'type',
                'ip',
                'port',
                'details',
                'interfaceid',
            ],
            selectGroups=["id"],
            selectParentTemplates=["id"]
        )
        if len(host) > 1:
            err_msg = (
                f"Got {len(host)} results for Zabbix hosts "
                f"with ID {self.zabbix_id} - hostname {self.name}."
            )
            logger.error(err_msg)
            raise SyncInventoryError(err_msg)
        elif len(host) == 0:
            e = (
                f"No Zabbix host found for {self.name}. "
                f"This is likely the result of a deleted Zabbix host "
                f"without zeroing the ID field in Netbox."
            )
            logger.error(e)
            raise SyncInventoryError(e)
        else:
            host = host[0]

        if host["host"] == self.name:
            logger.debug(f"Device {self.name}: hostname in-sync.")
        else:
            logger.warning(
                f"Device {self.name}: hostname OUT of sync. "
                f"Received value: {host['host']}"
            )
            self.updateZabbixHost(host=self.name)

        for template in host["parentTemplates"]:
            if template["templateid"] == self.template_id:
                logger.debug(f"Device {self.name}: template in-sync.")
                break
        else:
            logger.warning(f"Device {self.name}: template OUT of sync.")
            self.updateZabbixHost(templates=self.template_id)

        # Sync the host groups
        n_host_group_ids = []
        for curr_group in self.hostgroups:
            n_host_group_ids.append(zabbix_groups_map[curr_group]['groupid'])
        n_host_group_ids = sorted(map(lambda x: int(x), n_host_group_ids))
        z_host_group_ids = sorted(map(lambda x: int(x['groupid']), host['groups']))

        logger.debug(f"Groups z: {z_host_group_ids} - n: {n_host_group_ids}")

        if z_host_group_ids != n_host_group_ids:
            group_list = list(map(lambda x: {'groupid': x}, n_host_group_ids))
            logger.debug(f"Updating host '{self.name}' with groups {group_list}")
            self.updateZabbixHost(groups=group_list)
        else:
            logger.debug(f"Device {self.name}: hostgroups in-sync.")

        # Update host status
        if int(host["status"]) == self.zabbix_state:
            logger.debug(f"Device {self.name}: status in-sync.")
        else:
            logger.warning(f"Device {self.name}: status OUT of sync.")
            self.updateZabbixHost(status=str(self.zabbix_state))

        # Check if a proxy has been defined
        if self.zbxproxy != "0":
            # Check if expected proxyID matches with configured proxy
            if host["proxy_hostid"] == self.zbxproxy:
                logger.debug(f"Device {self.name}: proxy in-sync.")
            else:
                # Proxy diff, update value
                logger.warning(f"Device {self.name}: proxy OUT of sync.")
                self.updateZabbixHost(proxy_hostid=self.zbxproxy)
        else:
            if not host["proxy_hostid"] == "0":
                if proxy_power:
                    # If the -p flag has been issued,
                    # delete the proxy link in Zabbix
                    self.updateZabbixHost(proxy_hostid=self.zbxproxy)
                else:
                    # Instead of deleting the proxy config in zabbix and
                    # forcing potential data loss,
                    # an error message is displayed.
                    logger.error(f"Device {self.name} is configured "
                                 f"with proxy in Zabbix but not in Netbox. The"
                                 " -p flag was ommited: no "
                                 "changes have been made.")
        # If only 1 interface has been found
        if len(host['interfaces']) == 1:
            updates = {}
            # Go through each key / item and check if it matches Zabbix
            for key, item in self.setInterfaceDetails()[0].items():
                # Check if Netbox value is found in Zabbix
                if key in host["interfaces"][0]:
                    # If SNMP is used, go through nested dict
                    # to compare SNMP parameters
                    if type(item) == dict and key == "details":
                        for k, i in item.items():
                            if k in host["interfaces"][0][key]:
                                # Set update if values don't match
                                if host["interfaces"][0][key][k] != str(i):
                                    # If dict has not been created, add it
                                    if key not in updates:
                                        updates[key] = {}
                                    updates[key][k] = str(i)
                                    # If SNMP version has been changed
                                    # break loop and force full SNMP update
                                    if k == "version":
                                        break
                        # Force full SNMP config update
                        # when version has changed.
                        if key in updates:
                            if "version" in updates[key]:
                                for k, i in item.items():
                                    updates[key][k] = str(i)
                        continue
                    # Set update if values don't match
                    if host["interfaces"][0][key] != str(item):
                        updates[key] = item
            if updates:
                # If interface updates have been found: push to Zabbix
                logger.warning(f"Device {self.name}: Interface OUT of sync.")
                if "type" in updates:
                    # Changing interface type not supported. Raise exception.
                    e = (f"Device {self.name}: changing interface type to "
                         f"{str(updates['type'])} is not supported.")
                    logger.error(e)
                    raise InterfaceConfigError(e)
                # Set interfaceID for Zabbix config
                updates["interfaceid"] = host["interfaces"][0]['interfaceid']
                try:
                    # API call to Zabbix
                    self.zabbix.hostinterface.update(updates)
                    e = f"Solved {self.name} interface conflict."
                    logger.info(e)
                    self.create_journal_entry("info", e)
                except pyzabbix.ZabbixAPIException as exc:
                    err_msg = f"Zabbix returned the following error: {str(exc)}."
                    logger.error(err_msg)
                    raise SyncExternalError(err_msg)
            else:
                # If no updates are found, Zabbix interface is in-sync
                debug_msg = f"Device {self.name}: interface in-sync."
                logger.debug(debug_msg)
        else:
            err_msg = (
                f"Device {self.name} has unsupported interface configuration."
                f" Host has total of {len(host['interfaces'])} interfaces. "
                "Manual interfention required."
            )
            logger.error(err_msg)
            SyncInventoryError(err_msg)

    def create_journal_entry(self, severity, message):
        '''
        Send a new Journal entry to Netbox. Usefull for viewing actions
        in Netbox without having to look in Zabbix or the script log output
        '''
        if self.journal:
            # Check if the severity is valid
            if severity not in ["info", "success", "warning", "danger"]:
                logger.warning(f"Value {severity} not valid for NB journal entries.")
                return False
            journal = {
                "assigned_object_type": "dcim.device",
                "assigned_object_id":   self.id,
                "kind":                 severity,
                "comments":             message,
            }
            try:
                self.nb_journals.create(journal)
                return True
                logger.debug(f"Crated journal entry in NB for host {self.name}")
            except pynetbox.RequestError as exc:
                logger.warning(
                    "Unable to create journal entry for "
                    f"{self.name}: NB returned {exc}"
                )


class ZabbixInterface():
    """Class that represents a Zabbix interface."""

    def __init__(self, context, ip):
        self.context = context
        self.ip = ip
        self.skelet = {"main": "1", "useip": "1", "dns": "", "ip": self.ip}
        self.interface = self.skelet

    def get_context(self):
        '''Check if Netbox custom context has been defined.'''
        if "zabbix" in self.context:
            zabbix = self.context["zabbix"]
            if "interface_type" in zabbix and "interface_port" in zabbix:
                self.interface["type"] = zabbix["interface_type"]
                self.interface["port"] = zabbix["interface_port"]
                return True
            else:
                return False
        else:
            return False

    def set_snmp(self):
        '''
        Check if interface is type SNMP
        '''
        if self.interface["type"] == 2:
            # Checks if SNMP settings are defined in Netbox
            if "snmp" in self.context["zabbix"]:
                snmp = self.context["zabbix"]["snmp"]
                self.interface["details"] = {}
                # Checks if bulk config has been defined
                if snmp.get("bulk"):
                    self.interface["details"]["bulk"] = str(snmp.pop("bulk"))
                else:
                    # Fallback to bulk enabled if not specified
                    self.interface["details"]["bulk"] = "1"
                # SNMP Version config is required in Netbox config context
                if snmp.get("version"):
                    self.interface["details"]["version"] = str(snmp.pop("version"))
                else:
                    e = "SNMP version option is not defined."
                    raise InterfaceConfigError(e)
                # If version 2 is used, get community string
                if self.interface["details"]["version"] == '2':
                    if "community" in snmp:
                        community = snmp["community"]
                        self.interface["details"]["community"] = str(community)
                    else:
                        e = ("No SNMP community string "
                             "defined in custom context.")
                        raise InterfaceConfigError(e)
                # If version 3 has been used, get all
                # SNMPv3 Netbox related configs
                elif self.interface["details"]["version"] == '3':
                    items = ["securityname", "securitylevel", "authpassphrase",
                             "privpassphrase", "authprotocol", "privprotocol",
                             "contextname"]
                    for key, item in snmp.items():
                        if key in items:
                            self.interface["details"][key] = str(item)
                else:
                    raise InterfaceConfigError("Unsupported SNMP version.")
            else:
                raise InterfaceConfigError("Interface type SNMP but no parameters provided.")
        else:
            raise InterfaceConfigError("Interface type is not SNMP, unable to set SNMP details")

    def set_default(self):
        '''Set default config to SNMPv2,port 161 and community macro.'''
        self.interface = self.skelet
        self.interface["type"] = "2"
        self.interface["port"] = "161"
        self.interface["details"] = {
            "version": "2",
            "community": "{$SNMP_COMMUNITY}",
            "bulk": "1"
        }


if __name__ == "__main__":
    # Arguments parsing
    parser = argparse.ArgumentParser(
        description='A script to sync Zabbix with Netbox device data.'
    )
    parser.add_argument("-v", "--verbose", help="Turn on debugging.",
                        action="store_true")
    parser.add_argument("-c", "--cluster", action="store_true",
                        help=("Only add the primary node of a cluster "
                              "to Zabbix. Usefull when a shared virtual IP is "
                              "used for the control plane."))
    parser.add_argument("-t", "--tenant", action="store_true",
                        help=("Add Tenant name to the Zabbix "
                              "hostgroup name scheme."))
    parser.add_argument("-p", "--proxy_power", action="store_true",
                        help=("USE WITH CAUTION. If there is a proxy "
                              "configured in Zabbix but not in Netbox, sync "
                              "the device and remove the host - proxy "
                              "link in Zabbix."))
    parser.add_argument("-j", "--journal", action="store_true",
                        help="Create journal entries in Netbox at write actions")
    args = parser.parse_args()

    main(args)
