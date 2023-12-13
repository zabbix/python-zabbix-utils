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

import struct
import socket
import logging
from typing import Callable, Union

from .logger import EmptyHandler
from .exceptions import ProcessingError

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class Getter():
    """Zabbix get implementation.

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

        # Validate and store the socket_wrapper function if provided.
        self.socket_wrapper = socket_wrapper
        if self.socket_wrapper:
            if not isinstance(self.socket_wrapper, Callable):
                raise TypeError('Value "socket_wrapper" should be a function.')

    def __create_packet(self, data: str) -> bytes:
        # Create a Zabbix packet from the provided data.
        data = data.encode("utf-8")
        packet = struct.pack('<4sBII', b'ZBXD', 0x01, len(data), 0) + data
        log.debug('Content of the packet: %s', packet)

        return packet

    def __receive(self, conn: socket, size: int) -> bytes:
        buf = b''

        # Receive data from the socket until the specified size is reached.
        while True:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk

        return buf

    def __get_response(self, conn: socket) -> Union[str, None]:
        # Receive and parse the response from the Zabbix agent.
        header_size = 13
        response_header = self.__receive(conn, header_size)
        log.debug('Zabbix response header: %s', response_header)

        # Check if the received header is a valid Zabbix response.
        if (not response_header.startswith(b'ZBXD') or
                len(response_header) != header_size):
            log.debug('Unexpected response was received from Zabbix.')
            raise ProcessingError('Unexpected response was received from Zabbix.')

        # Unpack the header to extract information about the response.
        flags, datalen, reserved = struct.unpack('<BII', response_header[4:])

        # Determine the length of the response body based on the flags.
        if flags & 0x01:
            response_len = datalen
        elif flags & 0x02:
            response_len = reserved
        elif flags & 0x04:
            raise ProcessingError(
                'A large packet flag was received. '
                'Current module doesn\'t support large packets.'
            )
        else:
            raise ProcessingError(
                'Unexcepted flags were received. '
                'Check debug log for more information.'
            )

        # Receive the response body from the Zabbix agent.
        # and decode to a UTF-8 string
        response_body = self.__receive(conn, response_len)
        result = response_body.decode("utf-8")

        log.debug('Zabbix response body: %s', result)

        return result

    def get(self, key: str) -> Union[str, None]:
        """Gets item value from Zabbix agent by specified key.

        Args:
            key (str): Zabbix item key.

        Returns:
            str: Value from Zabbix agent for specified key.
        """

        packet = self.__create_packet(key)

        # Create a socket based on the IP version specified.
        try:
            if self.use_ipv6:
                connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            # Handle an error if there's an issue creating the socket.
            raise ProcessingError(
                f"Error creating socket for {self.host}:{self.port}") from None

        connection.settimeout(self.timeout)

        if self.source_ip:
            connection.bind((self.source_ip, 0,))

        # Connect to the Zabbix agent and send the packet.
        try:
            connection.connect((self.host, self.port))
            if self.socket_wrapper is not None:
                connection = self.socket_wrapper(connection)
            connection.sendall(packet)
        except (TimeoutError, socket.timeout) as err:
            # Handle a timeout error during the connection.
            log.error(
                'The connection to %s timed out after %d seconds',
                f"{self.host}:{self.port}",
                self.timeout
            )
            connection.close()
            raise err
        except (ConnectionRefusedError, socket.gaierror) as err:
            # Handle an error when the connection is refused.
            log.error(
                'An error occurred while trying to connect to %s: %s',
                f"{self.host}:{self.port}",
                getattr(err, 'msg', str(err))
            )
            connection.close()
            raise err
        except (OSError, socket.error) as err:
            # Handle a general socket error during the connection.
            log.warning(
                'An error occurred while trying to send to %s: %s',
                f"{self.host}:{self.port}",
                getattr(err, 'msg', str(err))
            )
            connection.close()
            raise err

        # Retrieve and handle the response from the Zabbix agent.
        try:
            response = self.__get_response(connection)
        except ConnectionResetError as err:
            log.debug('Get value error: %s', err)
            log.warning('Check access restrictions in Zabbix agent configuration.')
            raise err
        log.debug('Response from [%s:%s]: %s', self.host, self.port, response)

        # Close the connection to the Zabbix agent.
        try:
            connection.close()
        except socket.error:
            pass

        return response
