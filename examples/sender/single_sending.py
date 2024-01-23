# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import Sender

# Zabbix server/proxy details for Sender
ZABBIX_SERVER = {
    "server": "127.0.0.1",  # Zabbix server/proxy IP address or hostname
    "port": 10051           # Zabbix server/proxy port for Sender
}

# Create an instance of the Sender class with the specified server details
sender = Sender(**ZABBIX_SERVER)

# Send a value to a Zabbix server/proxy with specified parameters
# Parameters: (host, key, value, clock, ns)
response = sender.send_value('host', 'item.key', 'value', 1695713666, 30)

# Check if the value sending was successful
if response.failed == 0:
    # Print a success message along with the response time
    print(f"Value sent successfully in {response.time}")
else:
    # Print a failure message
    print("Failed to send value")
