# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncSender


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # You can create an instance of AsyncSender using the default configuration file path
    # (typically '/etc/zabbix/zabbix_agentd.conf')
    #
    # sender = AsyncSender(use_config=True)
    #
    # Or you can create an instance of AsyncSender using a custom configuration file path
    sender = AsyncSender(use_config=True, config_path='/etc/zabbix/zabbix_agent2.conf')

    # Send a value to a Zabbix server/proxy with specified parameters
    # Parameters: (host, key, value, clock)
    response = await sender.send_value('host', 'item.key', 'value', 1695713666)

    # Check if the value sending was successful
    if response.failed == 0:
        # Print a success message along with the response time
        print(f"Value sent successfully in {response.time}")
    elif response.details:
        # Iterate through the list of responses from Zabbix server/proxy.
        for node, chunks in response.details.items():
            # Iterate through the list of chunks.
            for resp in chunks:
                # Check if the value sending was successful
                if resp.failed == 0:
                    # Print a success message along with the response time
                    print(f"Value sent successfully to {node} in {resp.time}")
                else:
                    # Print a failure message
                    print(f"Failed to send value to {node} at chunk step {resp.chunk}")
    else:
        # Print a failure message
        print("Failed to send value")

# Run the main coroutine
asyncio.run(main())
