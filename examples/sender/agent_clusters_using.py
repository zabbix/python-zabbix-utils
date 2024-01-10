# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import Sender

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

# Send a value to a Zabbix server/proxy with specified parameters
# Parameters: (host, key, value, clock)
responses = sender.send_value('host', 'item.key', 'value', 1695713666)

for node, resp in responses.items():
    # Check if the value sending was successful
    if resp.failed == 0:
        # Print a success message along with the response time
        print(f"Value sent successfully to {node} in {resp.time}")
    else:
        # Print a failure message
        print(f"Failed to send value to {node}")
