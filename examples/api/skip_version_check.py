from zabbix_utils import ZabbixAPI

# Use ZabbixAPI with skipping the version check
# This can be useful in some cases when your Zabbix API version is
# unsupported by the zabbix_utils, but you're sure it will work properly.
with ZabbixAPI(url="127.0.0.1", skip_version_check=True) as api:
    # Authenticate with the Zabbix API using provided user credentials
    api.login(user="Admin", password="zabbix")

    # Print the full Zabbix API version
    print(api.version)

    # Print the major version component
    print(api.version.major)

    # Print the minor version component
    print(api.version.minor)

    # Check if the Zabbix API version is a Long Term Support (LTS) release
    print(api.version.is_lts())

# Use ZabbixAPI with the default behavior (version check enabled)
# Default behavior is that ZabbixNotSupported exception will
# be raised for unsupported Zabbix API versions.
with ZabbixAPI(url="127.0.0.1") as api:
    # Authenticate with the Zabbix API using provided user credentials
    api.login(user="Admin", password="zabbix")

    # Print the full Zabbix API version
    print(api.version)

    # Print the major version component
    print(api.version.major)

    # Print the minor version component
    print(api.version.minor)

    # Check if the Zabbix API version is a Long Term Support (LTS) release
    print(api.version.is_lts())
