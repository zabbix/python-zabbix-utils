from zabbix_utils import ZabbixAPI

# Use an authentication token generated via the web interface or
# API instead of standard authentication by username and password.
ZABBIX_AUTH = {
    "url": "127.0.0.1",
    "token": "8jF7sGh2Rp4TlQ1ZmXo0uYv3Bc6AiD9E"
}

# Create an instance of the ZabbixAPI class with the specified authentication details
api = ZabbixAPI(**ZABBIX_AUTH)

# Retrieve a list of users, including their user ID and name
users = api.user.get(
    output=['userid', 'name']
)

# Print the names of the retrieved users
for user in users:
    print(user['name'])
