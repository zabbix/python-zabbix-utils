# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
from zabbix_utils import Getter

# !!! IMPORTANT
# The code example below is supported only from Python version 3.13 onwards.

# Zabbix agent parameters
ZABBIX_AGENT = "127.0.0.1"
ZABBIX_PORT = 10050


# PSK wrapper function for SSL connection
def psk_wrapper(sock):
    # Pre-Shared Key (PSK) and PSK Identity
    psk = bytes.fromhex('608b0a0049d41fdb35a824ef0a227f24e5099c60aa935e803370a961c937d6f7')
    psk_identity = b'PSKID'

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


# Create a Getter instance with PSK support
agent = Getter(
    host=ZABBIX_AGENT,
    port=ZABBIX_PORT,
    socket_wrapper=psk_wrapper
)

# Send a Zabbix agent query for system information (e.g., uname)
resp = agent.get('system.uname')

# Check if there was an error in the response
if resp.error:
    # Print the error message
    print("An error occurred while trying to get the value:", resp.error)
else:
    # Print the value obtained for the specified item key item
    print("Received value:", resp.value)
