# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import Sender

# Toy can create an instance of Sender using the default configuration file path
# (typically '/etc/zabbix/zabbix_agentd.conf')
#
# sender = Sender(use_config=True)
#
# Or you can create an instance of Sender using a custom configuration file path
sender = Sender(use_config=True, config_path='/etc/zabbix/zabbix_agent2.conf')

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
