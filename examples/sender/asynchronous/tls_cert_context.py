# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
import asyncio
from zabbix_utils import AsyncSender

# Zabbix server details
ZABBIX_SERVER = "zabbix-server.example.com"
ZABBIX_PORT = 10051

# Paths to certificate and key files
CA_PATH = 'path/to/cabundle.pem'
CERT_PATH = 'path/to/agent.crt'
KEY_PATH = 'path/to/agent.key'


# Create and configure an SSL context for secure communication with the Zabbix server.
def custom_context(*args, **kwargs) -> ssl.SSLContext:

    # Create an SSL context for TLS client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Load the client certificate and private key
    context.load_cert_chain(CERT_PATH, keyfile=KEY_PATH)

    # Load the certificate authority bundle file
    context.load_verify_locations(cafile=CA_PATH)

    # Disable hostname verification
    context.check_hostname = False

    # Set the verification mode to require a valid certificate
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED

    # Return created context
    return context


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of AsyncSender with SSL context
    sender = AsyncSender(
        server=ZABBIX_SERVER,
        port=ZABBIX_PORT,
        ssl_context=custom_context
    )

    # Send a value to a Zabbix server/proxy with specified parameters
    # Parameters: (host, key, value, clock, ns)
    response = await sender.send_value('host', 'item.key', 'value', 1695713666, 30)

    # Check if the value sending was successful
    if response.failed == 0:
        # Print a success message along with the response time
        print(f"Value sent successfully in {response.time}")
    else:
        # Print a failure message
        print("Failed to send value")

# Run the main coroutine
asyncio.run(main())
