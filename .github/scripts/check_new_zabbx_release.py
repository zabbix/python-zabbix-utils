#!/usr/bin/env python
import os
import sys
import requests

sys.path.append('.')
from zabbix_utils.version import __max_supported__

BRANCHES_URL = os.environ.get("BRANCHES_URL")
LIBREPO_URL = os.environ.get("LIBREPO_URL")
MANUAL_REPO = os.environ.get("MANUAL_REPO")

for key in ["BRANCHES_URL", "LIBREPO_URL", "MANUAL_REPO"]:
    if not os.environ.get(key):
        print(f"Please set environmental variable \"{key}\"")
        sys.exit(1)

sver = __max_supported__

try:
    branches = requests.get(str(BRANCHES_URL), timeout=5).json()['values']
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
    error = f"""New Zabbix version was found in https://git.zabbix.com.
The <a href="{LIBREPO_URL}">zabbix_utils library</a> supports &lt;={sver} but the latest version of Zabbix is {max(versions)}.
What to do next? Look at the manual: {MANUAL_REPO}.
"""
    sys.exit(error)
