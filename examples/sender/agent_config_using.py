from zabbix_utils import ZabbixSender

# Toy can create an instance of ZabbixSender using the default configuration file path
# (typically '/etc/zabbix/zabbix_agentd.conf')
#
# sender = ZabbixSender(use_config=True)
#
# Or you can create an instance of ZabbixSender using a custom configuration file path
sender = ZabbixSender(use_config=True, config_path='/etc/zabbix/zabbix_agent2.conf')

# Send a value to a Zabbix server/proxy with specified parameters
# Parameters: (host, key, value, clock)
resp = sender.send_value('host', 'item.key', 'value', 1695713666)

# Check if the value sending was successful
if resp.failed == 0:
    # Print a success message along with the response time
    print(f"Value sent successfully in {resp.time}")
else:
    # Print a failure message
    print("Failed to send value")
