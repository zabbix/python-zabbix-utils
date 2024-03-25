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

import socket
import logging
from typing import Callable, Union

from .logger import EmptyHandler
from .types import AgentResponse
from .common import ZabbixProtocol
from .exceptions import ProcessingError

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class Getter():
    """Zabbix get synchronous implementation.

    Args:
        host (str, optional): Zabbix agent address. Defaults to `'127.0.0.1'`.

        port (int, optional): Zabbix agent port. Defaults to `10050`.

        timeout (int, optional): Connection timeout value. Defaults to `10`.

        use_ipv6 (bool, optional): Specifying IPv6 use instead of IPv4. Defaults to `False`.

        source_ip (str, optional): IP from which to establish connection. Defaults to `None`.

        socket_wrapper (Callable, optional): Func(`conn`) to wrap socket. Defaults to `None`.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 10050, timeout: int = 10,
                 use_ipv6: bool = False, source_ip: Union[str, None] = None,
                 socket_wrapper: Union[Callable, None] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ipv6 = use_ipv6
        self.source_ip = source_ip

        self.socket_wrapper = socket_wrapper
        if self.socket_wrapper:
            if not isinstance(self.socket_wrapper, Callable):
                raise TypeError('Value "socket_wrapper" should be a function.')

    def __get_response(self, conn: socket) -> Union[str, None]:
        result = ZabbixProtocol.parse_sync_packet(conn, log, ProcessingError)

        log.debug('Received data: %s', result)

        return result

    def get(self, key: str) -> Union[str, None]:
        """Gets item value from Zabbix agent by specified key.

        Args:
            key (str): Zabbix item key.

        Returns:
            str: Value from Zabbix agent for specified key.
        """

        packet = ZabbixProtocol.create_packet(key, log)

        try:
            if self.use_ipv6:
                connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            raise ProcessingError(
                f"Error creating socket for {self.host}:{self.port}") from None

        connection.settimeout(self.timeout)

        if self.source_ip:
            connection.bind((self.source_ip, 0,))

        try:
            connection.connect((self.host, self.port))
            if self.socket_wrapper is not None:
                connection = self.socket_wrapper(connection)
            connection.sendall(packet)
        except (TimeoutError, socket.timeout) as err:
            log.error(
                'The connection to %s timed out after %d seconds',
                f"{self.host}:{self.port}",
                self.timeout
            )
            connection.close()
            raise err
        except (ConnectionRefusedError, socket.gaierror) as err:
            log.error(
                'An error occurred while trying to connect to %s: %s',
                f"{self.host}:{self.port}",
                getattr(err, 'msg', str(err))
            )
            connection.close()
            raise err
        except (OSError, socket.error) as err:
            log.warning(
                'An error occurred while trying to send to %s: %s',
                f"{self.host}:{self.port}",
                getattr(err, 'msg', str(err))
            )
            connection.close()
            raise err

        try:
            response = self.__get_response(connection)
        except ConnectionResetError as err:
            log.debug('Get value error: %s', err)
            log.warning('Check access restrictions in Zabbix agent configuration.')
            raise err
        log.debug('Response from [%s:%s]: %s', self.host, self.port, response)

        try:
            connection.close()
        except socket.error:
            pass

        return AgentResponse(response)
