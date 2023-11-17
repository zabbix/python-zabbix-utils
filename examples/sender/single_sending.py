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
responses = sender.send_value('host', 'item.key', 'value', 1695713666, 30)

for node, resp in responses.items():
    # Check if the value sending was successful
    if resp.failed == 0:
        # Print a success message along with the response time
        print(f"Value sent successfully to {node} in {resp.time}")
    else:
        # Print a failure message
        print(f"Failed to send value to {node}")
