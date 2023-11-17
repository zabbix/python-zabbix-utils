from zabbix_utils import Getter

# Create a Getter instance with specified parameters
# Parameters: (host, port, source_ip)
agent = Getter("127.0.0.1", 10050, source_ip="10.10.1.5")

# Send a Zabbix agent query for system information (e.g., uname)
resp = agent.get('system.uname')

# Print the response received from the Zabbix agent
print(resp)
