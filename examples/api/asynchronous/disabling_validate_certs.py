# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncZabbixAPI


# SSL certificate verification will be ignored.
# This can be useful in some cases, but it also poses security risks because
# it makes the connection susceptible to man-in-the-middle attacks.
ZABBIX_PARAMS = {
    "url": "127.0.0.1",
    "validate_certs": False
}

# Zabbix server authentication credentials.
ZABBIX_AUTH = {
    "user": "Admin",
    "password": "zabbix"
}


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the AsyncZabbixAPI class with the specified authentication details.
    # Note: Ignoring SSL certificate validation may expose the connection to security risks.
    api = AsyncZabbixAPI(**ZABBIX_PARAMS)

    # Authenticating with Zabbix API using the provided username and password.
    await api.login(**ZABBIX_AUTH)

    # Retrieve a list of users from the Zabbix server, including their user ID and name.
    users = await api.user.get(
        output=['userid', 'name']
    )

    # Print the names of the retrieved users.
    for user in users:
        print(user['name'])

    # Logout to release the Zabbix API session.
    await api.logout()

# Run the main coroutine
asyncio.run(main())
