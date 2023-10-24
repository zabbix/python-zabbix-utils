#!/usr/bin/env python
import sys
import time

sys.path.append('.')
from zabbix_utils import ZabbixAPI, ZabbixAPIException

for x in range(20):
    try:
        zapi = ZabbixAPI(url="localhost", user="Admin", password="zabbix")
    except ZabbixAPIException as error:
        print(f'Zabbix API is not ready... Data: {error}', flush=True)
        time.sleep(5)
    else:
        zapi.logout()
        sys.exit(0)
sys.exit('Failed to wait for Zabbix API to be ready')
