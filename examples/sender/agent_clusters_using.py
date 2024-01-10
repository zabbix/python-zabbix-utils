# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import ItemValue, Sender

# You can create an instance of Sender specifying server address and port:
#
# sender = Sender(server='127.0.0.1', port=10051)
#
# Or you can create an instance of Sender specifying a list of Zabbix clusters:
zabbix_clusters = [
    ['zabbix.cluster1.node1', 'zabbix.cluster1.node2:10051'],
    ['zabbix.cluster2.node1:10051', 'zabbix.cluster2.node2:20051', 'zabbix.cluster2.node3']
]
sender = Sender(clusters=zabbix_clusters)
# You can also specify Zabbix clusters at the same time with server address and port:
#
# sender = Sender(server='127.0.0.1', port=10051, clusters=zabbix_clusters)
#
# In such case, specified server address and port will be appended to the cluster list
# as a cluster of a single node

# List of ItemValue instances representing items to be sent
items = [
    ItemValue('host1', 'item.key1', 10),
    ItemValue('host1', 'item.key2', 'test message'),
    ItemValue('host2', 'item.key1', -1, 1695713666),
    ItemValue('host3', 'item.key1', '{"msg":"test message"}'),
    ItemValue('host2', 'item.key1', 0, 1695713666, 100)
]

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
