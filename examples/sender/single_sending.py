from zabbix_utils import ZabbixSender

# Zabbix server/proxy details for ZabbixSender
ZABBIX_SERVER = {
    "server": "127.0.0.1",  # Zabbix server/proxy IP address or hostname
    "port": 10051           # Zabbix server/proxy port for ZabbixSender
}

# Create an instance of the ZabbixSender class with the specified server details
sender = ZabbixSender(**ZABBIX_SERVER)

# Send a value to a Zabbix server/proxy with specified parameters
# Parameters: (host, key, value, clock, ns)
resp = sender.send_value('host', 'item.key', 'value', 1695713666, 30)

# Check if the value sending was successful
if resp.failed == 0:
    # Print a success message along with the response time
    print(f"Value sent successfully in {resp.time}")
else:
    # Print a failure message
    print("Failed to send value")
