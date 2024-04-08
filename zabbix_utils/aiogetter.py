# zabbix_utils
#
# Copyright (C) 2001-2023 Zabbix SIA
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import ssl
import socket
import asyncio
import logging
from typing import Callable, Optional

from .logger import EmptyHandler
from .types import AgentResponse
from .common import ZabbixProtocol
from .exceptions import ProcessingError

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class AsyncGetter():
    """Zabbix get asynchronous implementation.

    Args:
        host (str, optional): Zabbix agent address. Defaults to `'127.0.0.1'`.

        port (int, optional): Zabbix agent port. Defaults to `10050`.

        timeout (int, optional): Connection timeout value. Defaults to `10`.

        source_ip (str, optional): IP from which to establish connection. Defaults to `None`.

        ssl_context (Callable, optional): Func(), returned prepared ssl.SSLContext. \
Defaults to `None`.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 10050, timeout: int = 10,
                 source_ip: Optional[str] = None, ssl_context: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.source_ip = source_ip

        self.ssl_context = ssl_context
        if self.ssl_context:
            if not isinstance(self.ssl_context, Callable):
                raise TypeError('Value "ssl_context" should be a function.')

    async def __get_response(self, reader: asyncio.StreamReader) -> Optional[str]:
        result = await ZabbixProtocol.parse_async_packet(reader, log, ProcessingError)

        log.debug('Received data: %s', result)

        return result

    async def get(self, key: str) -> Optional[str]:
        """Gets item value from Zabbix agent by specified key.

        Args:
            key (str): Zabbix item key.

        Returns:
            str: Value from Zabbix agent for specified key.
        """

        packet = ZabbixProtocol.create_packet(key, log)

        connection_params = {
            "host": self.host,
            "port": self.port
        }

        if self.source_ip:
            connection_params['local_addr'] = (self.source_ip, 0)

        if self.ssl_context:
            connection_params['ssl'] = self.ssl_context()
            if not isinstance(connection_params['ssl'], ssl.SSLContext):
                raise TypeError(
                    'Function "ssl_context" must return "ssl.SSLContext".') from None

        connection = asyncio.open_connection(**connection_params)

        try:
            reader, writer = await asyncio.wait_for(connection, timeout=self.timeout)
            writer.write(packet)
            await writer.drain()
        except asyncio.TimeoutError as err:
            log.error(
                'The connection to %s timed out after %d seconds',
                f"{self.host}:{self.port}",
                self.timeout
            )
            raise err
        except (ConnectionRefusedError, socket.gaierror) as err:
            log.error(
                'An error occurred while trying to connect to %s: %s',
                f"{self.host}:{self.port}",
                getattr(err, 'msg', str(err))
            )
            raise err
        except (OSError, socket.error) as err:
            log.warning(
                'An error occurred while trying to send to %s: %s',
                f"{self.host}:{self.port}",
                getattr(err, 'msg', str(err))
            )
            raise err

        try:
            response = await self.__get_response(reader)
        except (ConnectionResetError, asyncio.exceptions.IncompleteReadError) as err:
            log.debug('Get value error: %s', err)
            log.warning('Check access restrictions in Zabbix agent configuration.')
            raise err
        log.debug('Response from [%s:%s]: %s', self.host, self.port, response)

        writer.close()
        await writer.wait_closed()

        return AgentResponse(response)
