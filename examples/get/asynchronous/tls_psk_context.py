# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file to you under the MIT License.
# See the LICENSE file in the project root for more information.

import ssl
import asyncio
from zabbix_utils import AsyncGetter

# !!! IMPORTANT
# The code example below is supported only from Python version 3.13 onwards.

# Pre-Shared Key (PSK) and PSK Identity
PSK_KEY = bytes.fromhex('608b0a0049d41fdb35a824ef0a227f24e5099c60aa935e803370a961c937d6f7')
PSK_IDENTITY = b'PSKID'

# Zabbix agent parameters
ZABBIX_AGENT = "127.0.0.1"
ZABBIX_PORT = 10050


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

    # Create a AsyncGetter instance with a custom SSL context
    agent = AsyncGetter(
        host=ZABBIX_AGENT,
        port=ZABBIX_PORT,
        ssl_context=custom_context
    )

    # Send a Zabbix agent query for system information (e.g., uname)
    resp = await agent.get('system.uname')

    # Check if there was an error in the response
    if resp.error:
        # Print the error message
        print("An error occurred while trying to get the value:", resp.error)
    else:
        # Print the value obtained for the specified item key item
        print("Received value:", resp.value)


# Run the main coroutine
asyncio.run(main())
