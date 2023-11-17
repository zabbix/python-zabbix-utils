from zabbix_utils import Sender

# Create an instance of the Sender class with specified parameters
# Parameters: (server, port, source_ip)
sender = Sender("127.0.0.1", 10051, source_ip="10.10.1.5")

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
