# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncZabbixAPI


# Zabbix server URL or IP address
ZABBIX_SERVER = "127.0.0.1"

# Zabbix server authentication credentials
ZABBIX_AUTH = {
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the AsyncZabbixAPI class
    api = AsyncZabbixAPI(ZABBIX_SERVER)

    # Authenticating with Zabbix API using the provided username and password.
    await api.login(**ZABBIX_AUTH)

    # Some actions when your session can be released
    # For example, api.logout()

    # Check if authentication is still valid
    if await api.check_auth():
        # Retrieve a list of hosts from the Zabbix server, including their host ID and name
        hosts = await api.host.get(
            output=['hostid', 'name']
        )

        # Print the names of the retrieved hosts
        for host in hosts:
            print(host['name'])

        # Logout to release the Zabbix API session and close asynchronous connection
        await api.logout()

# Run the main coroutine
asyncio.run(main())
