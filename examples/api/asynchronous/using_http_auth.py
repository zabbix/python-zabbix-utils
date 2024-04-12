# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncZabbixAPI


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the AsyncZabbixAPI class with the Zabbix server URL
    # Set Basic Authentication credentials for Zabbix API requests
    # Basic Authentication - a simple authentication mechanism used in HTTP.
    # It involves sending a username and password with each HTTP request.
    api = AsyncZabbixAPI(
        url="http://127.0.0.1",
        http_user="user",
        http_password="p@$sw0rd"
    )

    # Login to the Zabbix API using provided user credentials
    await api.login(user="Admin", password="zabbix")

    # Retrieve a list of users from the Zabbix server, including their user ID and name
    users = await api.user.get(
        output=['userid', 'name']
    )

    # Print the names of the retrieved users
    for user in users:
        print(user['name'])

    # Logout to release the Zabbix API session
    await api.logout()

# Run the main coroutine
asyncio.run(main())
