# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncZabbixAPI, APIRequestError

# Zabbix server URL or IP address
ZABBIX_SERVER = "127.0.0.1"

# Zabbix server authentication credentials
ZABBIX_AUTH = {
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}

# Item IDs to be deleted
ITEM_IDS = [70060]


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the AsyncZabbixAPI class
    api = AsyncZabbixAPI(ZABBIX_SERVER)

    # Authenticating with Zabbix API using the provided username and password.
    await api.login(**ZABBIX_AUTH)

    # Delete items with specified IDs
    try:
        await api.item.delete(ITEM_IDS)

        # Alternative way to do the same:
        # await api.item.delete(*ITEM_IDS)
    except APIRequestError as e:
        print(f"An error occurred when attempting to delete items: {e}")
    else:
        # Logout to release the Zabbix API session
        await api.logout()

# Run the main coroutine
asyncio.run(main())
