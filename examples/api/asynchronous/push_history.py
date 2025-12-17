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

# IDs and values of items to push
ITEM_VALUES = [
    {
        "itemid": 70060,
        "value": 55
    },
    {
        "itemid": 70061,
        "value": 1.8,
        "clock": 1690891294,
        "ns": 45440940
    },
    {
        "itemid": 70062,
        "value": 123,
        "clock": 1690891295
    }
]


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the AsyncZabbixAPI class
    api = AsyncZabbixAPI(ZABBIX_SERVER)

    # Authenticating with Zabbix API using the provided username and password.
    await api.login(**ZABBIX_AUTH)

    # Clear history for items with specified IDs
    try:
        await api.history.push(ITEM_VALUES)

        # A way to do the same for versions prior to v2.0.2:
        # await api.history.push(*ITEM_VALUES)
    except APIRequestError as e:
        print(f"An error occurred when attempting to delete items: {e}")
    else:
        # Logout to release the Zabbix API session
        await api.logout()

# Run the main coroutine
asyncio.run(main())
