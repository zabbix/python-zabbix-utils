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
from .exceptions import ProcessingException

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class ZabbixGet():
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
                 use_ipv6: bool = False, **kwargs):

        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ipv6 = use_ipv6
        self.source_ip = kwargs.get('source_ip')

        self.socket_wrapper = kwargs.get('socket_wrapper')
        if self.socket_wrapper:
            if not isinstance(self.socket_wrapper, Callable):
                raise TypeError('Value "socket_wrapper" should be a function.')

    def __create_packet(self, data: str, compressed_size: Union[int, None] = None) -> bytes:

        flags = 0x01
        if compressed_size is None:
            datalen = len(data)
            reserved = 0
        else:
            flags = 0x02
            datalen = compressed_size
            reserved = len(data)

        header = struct.pack('<4sBII', b'ZBXD', flags, datalen, reserved)
        packet = header + data.encode("utf-8")

        log.debug('Content of the packet: %s', packet)

        return packet

    def __receive(self, conn: socket, size: int) -> bytes:

        buf = b''

        while True:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk

        return buf

    def __get_response(self, conn: socket) -> Union[str, None]:

        result = None
        header_size = 13

        response_header = self.__receive(conn, header_size)

        log.debug('Zabbix response header: %s', response_header)

        if (not response_header.startswith(b'ZBXD') or
                len(response_header) != header_size):
            log.debug('Unexpected response was received from Zabbix.')
            raise ProcessingException('Unexpected response was received from Zabbix.')
        else:
            flags, datalen, reserved = struct.unpack('<BII', response_header[4:])
            if flags == 0x01:
                response_len = datalen
            elif flags == 0x02:
                response_len = reserved
            elif flags == 0x04:
                raise ProcessingException(
                    'A large packet flag was received. '
                    'Current module doesn\'t support large packets.'
                )
            else:
                raise ProcessingException(
                    'Unexcepted flags were received. '
                    'Check debug log for more information.'
                )
            response_body = self.__receive(conn, response_len)
            result = response_body.decode("utf-8")

        log.debug('Zabbix response body: %s', result)

        try:
            conn.close()
        except socket.error:
            pass

        return result

    def __data_get(self, data: str) -> Union[str, None]:

        packet = self.__create_packet(data)

        try:
            if self.use_ipv6:
                connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            raise ProcessingException(
                f"Error creating socket for {self.host}:{self.port}") from None

        connection.settimeout(self.timeout)

        if self.source_ip:
            connection.bind((self.source_ip, 0,))

        try:
            connection.connect((self.host, self.port))
            connection = self.socket_wrapper(connection) if self.socket_wrapper else connection
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

        if connection:
            try:
                response = self.__get_response(connection)
            except ConnectionResetError as err:
                log.debug('Get value error: %s', err)
                log.warning('Check access restrictions in Zabbix agent configuration.')
                raise err
            log.debug('Response from [%s:%s]: %s', self.host, self.port, response)

        return response

    def get(self, key: str) -> Union[str, None]:
        """Gets item value from Zabbix agent by specified key.

        Args:
            key (str): Zabbix item key.

        Returns:
            str: Value from Zabbix agent for specified key.
        """

        return self.__data_get(key)
