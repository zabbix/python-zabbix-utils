#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import time

sys.path.append('.')
from zabbix_utils import ZabbixAPI, APIRequestError

for x in range(20):
    try:
        zapi = ZabbixAPI(url="localhost", user="Admin", password="zabbix")
    except APIRequestError as error:
        print(f'Zabbix API is not ready... Data: {error}', flush=True)
        time.sleep(5)
    else:
        zapi.logout()
        sys.exit(0)
sys.exit('Failed to wait for Zabbix API to be ready')
