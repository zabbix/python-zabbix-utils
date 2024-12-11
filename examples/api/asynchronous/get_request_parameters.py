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

    # There are only three ways to pass parameters of type dictionary:
    #
    # 1. Specifying values directly with their keys:
    problems = await api.problem.get(tags=[{"tag": "scope", "value": "notice", "operator": "0"}])
    #
    # 2. Unpacking dictionary keys and values using `**`:
    # request_params = {"tags": [{"tag": "scope", "value": "notice", "operator": "0"}]}
    # problems = await api.problem.get(**request_params)
    #
    # 3. Passing the dictionary directly as an argument (since v2.0.2):
    # request_params = {"tags": [{"tag": "scope", "value": "notice", "operator": "0"}]}
    # problems = await api.problem.get(request_params)

    # Print the names of the retrieved users
    for problem in problems:
        print(problem['name'])

    # Logout to release the Zabbix API session
    await api.logout()

# Run the main coroutine
asyncio.run(main())
