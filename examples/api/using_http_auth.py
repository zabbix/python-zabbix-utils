from zabbix_utils import ZabbixAPI

# Create an instance of the ZabbixAPI class with the Zabbix server URL
# Set Basic Authentication credentials for Zabbix API requests
# Basic Authentication - a simple authentication mechanism used in HTTP.
# It involves sending a username and password with each HTTP request.
api = ZabbixAPI(
    url="http://127.0.0.1",
    http_user="user",
    http_password="p@$sw0rd"
)

# Login to the Zabbix API using provided user credentials
api.login(user="Admin", password="zabbix")

# Retrieve a list of users from the Zabbix server, including their user ID and alias
users = api.user.get(
    output=['userid', 'alias']
)

# Print the aliases of the retrieved users
for user in users:
    print(user['alias'])

# Logout to release the Zabbix API session
api.logout()
