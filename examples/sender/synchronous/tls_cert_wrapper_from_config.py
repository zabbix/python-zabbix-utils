# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
from zabbix_utils import Sender

# Zabbix server details
ZABBIX_SERVER = "zabbix-server.example.com"
ZABBIX_PORT = 10051


# Define a function for wrapping the socket with TLS
def tls_wrapper(sock, config):

    # Try to get paths to certificate and key files
    ca_path = config.get('tlscafile')
    cert_path = config.get('tlscertfile')
    key_path = config.get('tlskeyfile')

    # Create an SSL context for TLS client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Load the client certificate and private key
    context.load_cert_chain(cert_path, keyfile=key_path)

    # Load the certificate authority bundle file
    context.load_verify_locations(cafile=ca_path)

    # Disable hostname verification
    context.check_hostname = False

    # Set the verification mode to require a valid certificate
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED

    # Wrap the socket with TLS using the created context
    return context.wrap_socket(sock, server_hostname=ZABBIX_SERVER)


# Create an instance of Sender with TLS configuration
sender = Sender(
    server=ZABBIX_SERVER,
    port=ZABBIX_PORT,
    # Use the defined tls_wrapper function for socket wrapping
    socket_wrapper=tls_wrapper
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
