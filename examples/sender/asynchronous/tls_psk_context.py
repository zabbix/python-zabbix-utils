# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
import asyncio
from zabbix_utils import AsyncSender

# !!! IMPORTANT
# The code example below is supported only from Python version 3.13 onwards.

# Zabbix server details
ZABBIX_SERVER = "zabbix-server.example.com"
ZABBIX_PORT = 10051

# Pre-Shared Key (PSK) and PSK Identity
PSK_KEY = bytes.fromhex('608b0a0049d41fdb35a824ef0a227f24e5099c60aa935e803370a961c937d6f7')
PSK_IDENTITY = b'PSKID'


# Create and configure an SSL context for secure communication with the Zabbix server.
def custom_context(*args, **kwargs) -> ssl.SSLContext:
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
    context.set_psk_client_callback(lambda hint: (PSK_IDENTITY, PSK_KEY))

    # Return the customized SSL context
    return context


async def main():
    """
    The main function to perform asynchronous tasks.
    """

    # Create an instance of AsyncSender with a custom SSL context
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
