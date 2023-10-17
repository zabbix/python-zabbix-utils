from zabbix_utils import ZabbixItem, ZabbixSender

# List of ZabbixItem instances representing items to be sent
items = [
    ZabbixItem('host1', 'item.key1', 10),
    ZabbixItem('host1', 'item.key2', 'test message'),
    ZabbixItem('host2', 'item.key1', -1, 1695713666),
    ZabbixItem('host3', 'item.key1', '{"msg":"test message"}'),
    ZabbixItem('host2', 'item.key1', 0, 1695713666, 100)
]

# Create an instance of the ZabbixSender class with the specified server details
sender = ZabbixSender("127.0.0.1", 10051)

# Send multiple items to the Zabbix server/proxy and receive response
bulk_resp = sender.send(items)

# Iterate through the response for each item in the bulk
for resp in bulk_resp:
    # Check if the value sending was successful
    if resp.failed == 0:
        # Print a success message along with the response time
        print(f"Value sent successfully in {resp.time} in {resp.chunk} chunk")
    else:
        # Print a failure message
        print(f"Failed to send value in {resp.chunk} chunk")
