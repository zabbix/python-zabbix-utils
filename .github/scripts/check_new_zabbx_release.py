#!/usr/bin/env python
import sys
import requests

sys.path.append('.')
from zabbix_utils.version import __max_supported__


BRANCHES_URL = "https://git.zabbix.com/rest/api/latest/projects\
/ZBX/repos/zabbix/branches?limit=100&filterText=release"

sver = __max_supported__

try:
    branches = requests.get(BRANCHES_URL, timeout=5).json()['values']
except Exception as error:
    print(f'Branches list getting failed... Data: {error}', flush=True)
    sys.exit(error)

versions = []

for branch in branches:
    version = branch['displayId'].split('/')[-1]
    try:
        version = float(version)
    except:
        continue
    versions.append(version)

if sver < max(versions):
    print(f"""New Zabbix version was found in https://git.zabbix.com.
The zabbix_utils library supports <{sver} but the latest version of Zabbix is {max(versions)}
""", flush=True)
    sys.exit()
