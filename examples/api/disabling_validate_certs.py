from zabbix_utils import ZabbixAPI

# SSL certificate verification will be ignored.
# This can be useful in some cases, but it also poses security risks because
# it makes the connection susceptible to man-in-the-middle attacks.
ZABBIX_AUTH = {
    "url": "127.0.0.1",
    "user": "Admin",
    "password": "zabbix",
    "validate_certs": False
}

# Create an instance of the ZabbixAPI class with the specified authentication details
# Note: Ignoring SSL certificate validation may expose the connection to security risks.
api = ZabbixAPI(**ZABBIX_AUTH)

# Retrieve a list of users from the Zabbix server, including their user ID and alias
users = api.user.get(
    output=['userid', 'alias']
)

# Print the aliases of the retrieved users
for user in users:
    print(user['alias'])

# Logout to release the Zabbix API session
api.logout()
