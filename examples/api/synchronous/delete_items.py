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

# Item IDs to be deleted
ITEM_IDS = [70060]

# Create an instance of the ZabbixAPI class with the specified authentication details
api = ZabbixAPI(**ZABBIX_AUTH)

# Delete items with specified IDs
try:
    api.item.delete(*ITEM_IDS)

    # Alternative way to do the same (since v2.0.2):
    # api.item.delete(ITEM_IDS)
except APIRequestError as e:
    print(f"An error occurred when attempting to delete items: {e}")

# Logout to release the Zabbix API session
api.logout()
