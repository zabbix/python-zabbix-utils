import sys
import json
from zabbix_utils import Getter

# Create a Getter instance for querying Zabbix agent
agent = Getter(host='127.0.0.1', port=10050)

# Send a Zabbix agent query for network interface discovery
resp = agent.get('net.if.discovery')

try:
    # Attempt to parse the JSON response
    resp_list = json.loads(resp)
except json.decoder.JSONDecodeError:
    print("Agent response decoding fails")
    # Exit the script if JSON decoding fails
    sys.exit()

# Iterate through the discovered network interfaces and print their names
for interface in resp_list:
    print(interface['{#IFNAME}'])
