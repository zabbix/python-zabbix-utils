# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

from zabbix_utils import ZabbixAPI, APIRequestError

# Zabbix server details and authentication credentials
ZABBIX_AUTH = {
    "url": "127.0.0.1",    # Zabbix server URL or IP address
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}

# IDs and values of items to push
ITEM_VALUES = [
    {
        "itemid": 70060,
        "value": 55
    },
    {
        "itemid": 70061,
        "value": 1.8,
        "clock": 1690891294,
        "ns": 45440940
    },
    {
        "itemid": 70062,
        "value": 123,
        "clock": 1690891295
    }
]

# Create an instance of the ZabbixAPI class with the specified authentication details
api = ZabbixAPI(**ZABBIX_AUTH)

# Push history for the list of item IDs and values
try:
    api.history.push(ITEM_VALUES)

    # A way to do the same for versions prior to v2.0.2:
    # api.history.push(*ITEM_VALUES)
except APIRequestError as e:
    print(f"An error occurred when attempting to clear items' history: {e}")

# Logout to release the Zabbix API session
api.logout()
