# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import ZabbixAPI

# Zabbix server details and authentication credentials
ZABBIX_SERVER = "127.0.0.1"     # Zabbix server URL or IP address
ZABBIX_USER = "Admin"           # Zabbix user name for authentication
ZABBIX_PASSWORD = "zabbix"      # Zabbix user password for authentication

# Use a context manager for automatic logout upon completion of the request.
# Each time it's created it performs "login" and "apiinfo.version".
# Highly recommended not to use it many times in a single script.
with ZabbixAPI(url=ZABBIX_SERVER) as api:
    # Authenticate with the Zabbix API using the provided user credentials
    api.login(user=ZABBIX_USER, password=ZABBIX_PASSWORD)

    # Retrieve a list of hosts from the Zabbix server, including their host ID and name
    hosts = api.host.get(
        output=['hostid', 'name']
    )

    # Print the names of the retrieved hosts
    for host in hosts:
        print(host['name'])

# Automatic logout occurs when the code block exits due to the context manager.
