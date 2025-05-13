# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
from zabbix_utils import Sender

# !!! IMPORTANT
# The code example below is supported only from Python version 3.13 onwards.

# Zabbix server details
ZABBIX_SERVER = "zabbix-server.example.com"
ZABBIX_PORT = 10051


# PSK wrapper function for SSL connection
def psk_wrapper(sock, config):
    psk = None
    psk_identity = config.get('tlspskidentity').encode('utf-8')
    psk_file = config.get('tlspskfile')

    # Read PSK from file if specified
    if psk_file:
        with open(psk_file, encoding='utf-8') as f:
            psk = bytes.fromhex(f.read())

    # Check if both PSK and PSK identity are available
    if psk and psk_identity:
        # Create an SSL context for TLS client
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Disable hostname verification
        context.check_hostname = False

        # Set the verification mode to require a valid certificate
        context.verify_mode = ssl.CERT_NONE

        # Set the maximum allowed version of the TLS protocol to TLS 1.2
        context.maximum_version = ssl.TLSVersion.TLSv1_2

        # Set the ciphers to use for the connection
        context.set_ciphers('PSK')

        # Set up the callback function to provide the PSK and identity when requested
        context.set_psk_client_callback(lambda hint: (psk_identity, psk))

        # Wrap the socket to establish an SSL connection with PSK
        return context.wrap_socket(sock)

    # Return original socket if PSK or PSK identity is missing
    return sock


# Create a Sender instance with PSK support
sender = Sender(
    server=ZABBIX_SERVER,
    port=ZABBIX_PORT,
    use_config=True,
    socket_wrapper=psk_wrapper
)

# Send a value to a Zabbix server/proxy with specified parameters
# Parameters: (host, key, value, clock, ns)
response = sender.send_value('host', 'item.key', 'value', 1695713666, 30)

# Check if the value sending was successful
if response.failed == 0:
    # Print a success message along with the response time
    print(f"Value sent successfully in {response.time}")
else:
    # Print a failure message
    print("Failed to send value")
