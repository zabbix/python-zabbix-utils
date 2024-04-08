# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncGetter


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create a AsyncGetter instance with specified parameters
    # Parameters: (host, port, source_ip)
    agent = AsyncGetter("127.0.0.1", 10050, source_ip="10.10.1.5")

    # Send a Zabbix agent query for system information (e.g., uname)
    resp = await agent.get('system.uname')

    # Check if there was an error in the response
    if resp.error:
        # Print the error message
        print("An error occurred while trying to get the value:", resp.error)
    else:
        # Print the value obtained for the specified item key item
        print("Received value:", resp.value)

# Run the main coroutine
asyncio.run(main())
