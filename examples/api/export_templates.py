from zabbix_utils import ZabbixAPI

# Zabbix server details and authentication credentials
ZABBIX_AUTH = {
    "url": "127.0.0.1",    # Zabbix server URL or IP address
    "user": "Admin",       # Zabbix user name for authentication
    "password": "zabbix"   # Zabbix user password for authentication
}

# Template IDs to be exported
TEMPLATE_IDS = [10050]

# File path and format for exporting configuration
FILE_PATH = "templates_export_example.{}"

# Create an instance of the ZabbixAPI class with the specified authentication details
api = ZabbixAPI(**ZABBIX_AUTH)

# Determine the file extension based on the Zabbix API version
FILE_EXTENSION = "yaml"
if api.version < 5.4:
    FILE_EXTENSION = "xml"

# Export configuration for specified template IDs
configuration = api.configuration.export(
    options={
        "templates": TEMPLATE_IDS
    },
    format=FILE_EXTENSION
)

# Write the exported configuration to a file
with open(FILE_PATH.format(FILE_EXTENSION), mode='w', encoding='utf-8') as f:
    f.write(configuration)

# Logout to release the Zabbix API session
api.logout()
