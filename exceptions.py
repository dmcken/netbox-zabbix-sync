'''Exceptions used throughout this codebase.

'''

# Custom Exceptions
class SyncError(Exception):
    '''Any errors when sync'ing a device'''

class SyncExternalError(SyncError):
    '''An error from an external system'''

class SyncInventoryError(SyncError):
    '''To determine'''

class SyncDuplicateError(SyncError):
    '''A duplicate was found when attempting to sync'''

class EnvironmentVarError(SyncError):
    '''To determine'''

class InterfaceConfigError(SyncError):
    '''Error configuring the interface on zabbix'''

class ProxyConfigError(SyncError):
    '''Error setting the proxy on zabbix.'''
