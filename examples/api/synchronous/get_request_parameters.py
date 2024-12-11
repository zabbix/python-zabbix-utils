# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import ZabbixAPI

# Zabbix server details and authentication credentials
ZABBIX_AUTH = {
    "url": "127.0.0.1",    # Zabbix server URL or IP address
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}

# Create an instance of the ZabbixAPI class with the specified authentication details
api = ZabbixAPI(**ZABBIX_AUTH)

# There are only three ways to pass parameters of type dictionary:
#
# 1. Specifying values directly with their keys:
problems = api.problem.get(tags=[{"tag": "scope", "value": "notice", "operator": "0"}])
#
# 2. Unpacking dictionary keys and values using `**`:
# request_params = {"tags": [{"tag": "scope", "value": "notice", "operator": "0"}]}
# problems = api.problem.get(**request_params)
#
# 3. Passing the dictionary directly as an argument (since v2.0.2):
# request_params = {"tags": [{"tag": "scope", "value": "notice", "operator": "0"}]}
# problems = api.problem.get(request_params)

# Print the names of the retrieved users
for problem in problems:
    print(problem['name'])

# Logout to release the Zabbix API session
api.logout()
