# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import asyncio
from zabbix_utils import AsyncZabbixAPI


# Zabbix server URL or IP address
ZABBIX_SERVER = "127.0.0.1"

# Zabbix server authentication credentials
ZABBIX_AUTH = {
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}

# Template IDs to be exported
TEMPLATE_IDS = [10050]

# File path and format for exporting configuration
FILE_PATH = "templates_export_example.{}"


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of the ZabbixAPI class with the specified authentication details
    api = AsyncZabbixAPI(ZABBIX_SERVER)

    # Authenticating with Zabbix API using the provided token.
    await api.login(**ZABBIX_AUTH)

    # Determine the export file format based on the Zabbix API version
    export_format = "yaml"
    if api.version < 5.4:
        export_format = "xml"

    # Export configuration for specified template IDs
    configuration = await api.configuration.export(
        options={
            "templates": TEMPLATE_IDS
        },
        format=export_format
    )

    # Write the exported configuration to a file
    with open(FILE_PATH.format(export_format), mode='w', encoding='utf-8') as f:
        f.write(configuration)

    # Logout to release the Zabbix API session
    await api.logout()

# Run the main coroutine
asyncio.run(main())
