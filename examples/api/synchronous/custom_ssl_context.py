# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
from zabbix_utils import ZabbixAPI

# Create a default SSL context for secure connections
# Load a custom certificate from the specified file path to verify the server
ctx = ssl.create_default_context()
ctx.load_verify_locations("/path/to/certificate.crt")

# Create an instance of the ZabbixAPI class with the Zabbix server URL
# Set ssl_context value for Zabbix API requests.
ZABBIX_AUTH = {
    "url": "https://example.com",
    "user": "Admin",
    "password": "zabbix",
    "ssl_context": ctx
}

# Login to the Zabbix API using provided user credentials
api = ZabbixAPI(**ZABBIX_AUTH)

# Retrieve a list of hosts from the Zabbix server, including their host ID and name
hosts = api.host.get(
    output=['hostid', 'name']
)

# Print the names of the retrieved hosts
for host in hosts:
    print(host['name'])

# Logout to release the Zabbix API session
api.logout()
