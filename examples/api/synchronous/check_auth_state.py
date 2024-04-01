# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import ZabbixAPI

# Zabbix server details and authentication credentials
ZABBIX_AUTH = {
    "url": "127.0.0.1",    # Zabbix server URL or IP address
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}

# Create an instance of the ZabbixAPI class with the specified authentication details
api = ZabbixAPI(**ZABBIX_AUTH)

# Some actions when your session can be released
# For example, api.logout()

# Check if authentication is still valid
if api.check_auth():
    # Retrieve a list of hosts from the Zabbix server, including their host ID and name
    hosts = api.host.get(
        output=['hostid', 'name']
    )

    # Print the names of the retrieved hosts
    for host in hosts:
        print(host['name'])

    # Logout to release the Zabbix API session
    api.logout()
