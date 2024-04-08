# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncZabbixAPI


# Zabbix server URL or IP address.
ZABBIX_SERVER = "127.0.0.1"

# Use an authentication token generated via the web interface or
# API instead of standard authentication by username and password.
ZABBIX_TOKEN = "8jF7sGh2Rp4TlQ1ZmXo0uYv3Bc6AiD9E"


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the AsyncZabbixAPI class.
    api = AsyncZabbixAPI(ZABBIX_SERVER)

    # Authenticating with Zabbix API using the provided token.
    await api.login(token=ZABBIX_TOKEN)

    # Retrieve a list of users, including their user ID and name
    users = await api.user.get(
        output=['userid', 'name']
    )

    # Print the names of the retrieved users
    for user in users:
        print(user['name'])

    # Close asynchronous connection
    await api.logout()

# Run the main coroutine
asyncio.run(main())
