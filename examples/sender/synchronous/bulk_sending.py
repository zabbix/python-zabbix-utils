# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import ItemValue, Sender

# List of ItemValue instances representing items to be sent
items = [
    ItemValue('host1', 'item.key1', 10),
    ItemValue('host1', 'item.key2', 'test message'),
    ItemValue('host2', 'item.key1', -1, 1695713666),
    ItemValue('host3', 'item.key1', '{"msg":"test message"}'),
    ItemValue('host2', 'item.key1', 0, 1695713666, 100)
]

# Create an instance of the Sender class with the specified server details
sender = Sender("127.0.0.1", 10051)

# Send multiple items to the Zabbix server/proxy and receive response
response = sender.send(items)

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
