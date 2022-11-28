# Installation procedure.


1. Download a copy of the code (zip or git clone).
2. Install pre-requisites:  
   pip3 install -r requirements.txt
3. Create .env file with the environment variables applicable to your environment (see below).
4. In your netbox installation create the custom fields (see below).
5. Done

## Netbox custom fields:
Use the following custom fields in Netbox to map the Zabbix URL:
* Model(s): dcim > device
* Type: Integer
* Name: zabbix_hostid
* Required: False
* Default: null

And this field for the Zabbix template
* Model(s): dcim > device_type
* Type: Text
* Name: zabbix_template
* Required: False
* Default: null

## Enviroment variables:
| ENV variable | Example Value | Description |
| ------------ | ------------- | ----------- |
| NETBOX_HOST | https://netbox.local | Base URL to access netbox web interface, is a full URL and can include a path. |
| NETBOX_TOKEN |   | Token to login to the netbox API with |
| NETBOX_ROLE_IGNORE | patch-panel,media-converter | A comma-separated list of device role slugs of device roles that should be ignored, usually because they are unmanaged devices |
| ZABBIX_HOST | https://zabbix.local/zabbix | Base URL to access zabbix web interface, is a full URL and can include a path. |
| ZABBIX_USER |   | Username to login to zabbix with |
| ZABBIX_PASS |   | Password to login to zabbix with |
| ZABBIX_TOKEN |   | Named Token to login to zabbix with instead of the username and password (Zabbix 5.4+) |

