from zabbix_utils import ZabbixAPI

# Zabbix server details and authentication credentials
ZABBIX_SERVER = "127.0.0.1"                         # Zabbix server URL or IP address
ZABBIX_USER = "Admin"                               # Zabbix user name for authentication
ZABBIX_PASSWORD = "zabbix"                          # Zabbix user password for authentication
ZABBIX_TOKEN = "8jF7sGh2Rp4TlQ1ZmXo0uYv3Bc6AiD9E"   # Authentication token for API access

# Create an instance of the ZabbixAPI class with the specified Zabbix server URL
api = ZabbixAPI(url=ZABBIX_SERVER)

# Check Zabbix API version and authenticate accordingly
# Zabbix API version can be compared with version expressed in float (major) or
# string (full, i.e. "major.minor").
if api.version >= 5.4:
    # If Zabbix API version is 5.4 or newer, use token-based authentication
    api.login(token=ZABBIX_TOKEN)
else:
    # If Zabbix API version is older than 5.4, use traditional username and password authentication
    api.login(user=ZABBIX_USER, password=ZABBIX_PASSWORD)

# Retrieve a list of users from the Zabbix server, including their user ID and alias
users = api.user.get(
    output=['userid', 'alias']
)

# Print the aliases of the retrieved users
for user in users:
    print(user['alias'])

# Logout to release the Zabbix API session
api.logout()
