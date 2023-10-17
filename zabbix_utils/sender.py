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

import re
import json
import socket
import struct
import logging
import configparser
from decimal import Decimal
from typing import Callable, Union

from .logger import EmptyHandler
from .exceptions import ProcessingException

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class ZabbixResponse():
    """Contains response from Zabbix.

    Args:
        chunk (int, optional): Current chunk number. Defaults to `0`.
    """

    def __init__(self, chunk: int = 1):
        self.__processed = 0
        self.__failed = 0
        self.__total = 0
        self.__time = 0
        self.__chunk = chunk

    def __repr__(self) -> str:
        result = {}
        for key, value in self.__dict__.items():
            result[
                key[len(f"_{self.__class__.__name__}__"):]
            ] = str(value) if isinstance(value, Decimal) else value

        return json.dumps(result)

    def parse(self, response: dict) -> None:
        """Parse response from Zabbix.

        Args:
            response (dict): Raw response from Zabbix.

        Raises:
            ProcessingException: Raises if unexpected response received
        """

        fields = {
            "processed": ('[Pp]rocessed', r'\d+'),
            "failed": ('[Ff]ailed', r'\d+'),
            "total": ('[Tt]otal', r'\d+'),
            "time": ('[Ss]econds spent', r'\d+\.\d+')
        }

        pattern = re.compile(
            r";\s+?".join([rf"{r[0]}:\s+?(?P<{k}>{r[1]})" for k, r in fields.items()])
        )

        info = response.get('info')
        if not info:
            log.debug('Received unexpected response: %s', response)
            raise ProcessingException(f"Received unexpected response: {response}")

        res = pattern.search(info).groupdict()
        res['chunk'] = str(self.__chunk)
        for k, v in res.items():
            setattr(
                self,
                f"_{self.__class__.__name__}__{k}",
                Decimal(v) if '.' in v else int(v)
            )

    @property
    def processed(self) -> int:
        """Returns number of processed packets.

        Returns:
            int: Number of processed packets.
        """

        return self.__processed

    @property
    def failed(self) -> int:
        """Returns number of failed packets.

        Returns:
            int: Number of failed packets.
        """

        return self.__failed

    @property
    def total(self) -> int:
        """Returns total number of packets.

        Returns:
            int: Total number of packets.
        """

        return self.__total

    @property
    def time(self) -> int:
        """Returns value of spent time.

        Returns:
            int: Spent time for the packets sending.
        """

        return self.__time

    @property
    def chunk(self) -> int:
        """Returns current chunk number.

        Returns:
            int: Number of the current chunk.
        """

        return self.__chunk


class ZabbixItem():
    """Contains one Zabbix sender item.

    Args:
        host (str): Specify host name the item belongs to (as registered in Zabbix frontend).

        key (str): Specify item key to send value to.

        value (str): Specify item value.

        clock (int, optional): Specify time in Unix timestamp format. Defaults to `None`.

        ns (int, optional): Specify time expressed in nanoseconds. Defaults to `None`.
    """

    def __init__(self, host: str, key: str, value: str,
                 clock: Union[int, float, None] = None, ns: Union[int, None] = None):
        self.host = str(host)
        self.key = str(key)
        self.value = str(value)

        try:
            self.clock = int(clock) if clock else clock
        except ValueError:
            raise ValueError(
                'The clock value must be expressed in the Unix Timestamp format') from None

        try:
            self.ns = int(ns) if ns else ns
        except ValueError:
            raise ValueError(
                'The ns value must be expressed in the integer value of nanoseconds') from None

    def __to_string(self) -> str:
        return json.dumps(self.to_json())

    def __str__(self) -> str:
        return self.__to_string()

    def __repr__(self) -> str:
        return self.__str__()

    def to_json(self) -> dict:
        """Represents ZabbixItem object in dictionary for json.

        Returns:
            dict: Object attributes in dictionary.
        """

        return {k: v for k, v in self.__dict__.items() if v is not None}


class ZabbixNode():
    """Contains one Zabbix node object.

    Args:
        addr (str): Listen address of Zabbix server.

        port (str): Listen port of Zabbix server.

    Raises:
        TypeError: Raises if not integer value was received.
    """

    def __init__(self, addr: str, port: Union[str, int]):
        self.address = addr if addr != '0.0.0.0/0' else '127.0.0.1'
        try:
            self.port = int(port)
        except ValueError:
            raise TypeError('Port must be an integer value') from None

    def __iter__(self) -> list:
        return iter([self.address, self.port])

    def __str__(self) -> str:
        return json.dumps(f"{self.address}:{self.port}")

    def __repr__(self) -> str:
        return self.__str__()


class ZabbixCluster():
    """Contains Zabbix node objects in a cluster object.

    Args:
        addr (str): Raw string with node addresses.
    """

    def __init__(self, addr: str):
        self.__nodes = self.__parse_ha_node(addr)

    def __parse_ha_node(self, string: str) -> list:
        nodes = []
        for node_item in string.split(';'):
            if ':' in node_item:
                nodes.append(ZabbixNode(*node_item.split(':')))
            else:
                nodes.append(ZabbixNode(node_item, '10051'))

        return nodes

    def __str__(self) -> str:
        return json.dumps(list(map(list, self.__nodes)))

    def __repr__(self) -> str:
        return self.__str__()

    @property
    def nodes(self) -> ZabbixNode:
        """Returns ZabbixNode objects.

        Yields:
            ZabbixNode: One Zabbix node object
        """

        for node in self.__nodes:
            yield node


class ZabbixSender():
    """Zabbix sender implementation.

    Args:
        server (str, optional): Zabbix server address. Defaults to `'127.0.0.1'`.

        port (int, optional): Zabbix server port. Defaults to `10051`.

        use_config (bool, optional): Specifying configuration use. Defaults to `False`.

        timeout (int, optional): Connection timeout value. Defaults to `10`.

        use_ipv6 (bool, optional): Specifying IPv6 use instead of IPv4. Defaults to `False`.

        source_ip (str, optional): IP from which to establish connection. Defaults to `None`.

        chunk_size (int, optional): Number of packets in one chunk. Defaults to `250`.

        socket_wrapper (Callable, optional): Func(`conn`,`tls`) to wrap socket. Defaults to `None`.

        config_path (str, optional): Path to Zabbix agent configuration file. Defaults to `None`.
    """

    def __init__(self, server: str = '127.0.0.1', port: int = 10051, use_config: bool = False,
                 timeout: int = 10, use_ipv6: bool = False, **kwargs):

        self.timeout = timeout
        self.use_ipv6 = use_ipv6
        self.tls = {}

        self.source_ip = kwargs.get('source_ip')
        self.chunk_size = kwargs.get('chunk_size', 250)

        self.socket_wrapper = kwargs.get('socket_wrapper')
        if self.socket_wrapper:
            if not isinstance(self.socket_wrapper, Callable):
                raise TypeError('Value "socket_wrapper" should be a function.')

        if use_config:
            self.clusters = []
            self.__load_config(kwargs.get('config_path') or '/etc/zabbix/zabbix_agentd.conf')
        else:
            self.clusters = [ZabbixCluster(f"{server}:{port}")]

    def __read_config(self, config: configparser.ConfigParser) -> None:
        if 'ServerActive' in config['root']:
            server_row = config.get('root', 'ServerActive')
        elif 'Server' in config['root']:
            server_row = config.get('root', 'Server')
        else:
            server_row = '127.0.0.1:10051'

        for cluster in server_row.split(','):
            self.clusters.append(ZabbixCluster(cluster))

        if 'SourceIP' in config['root']:
            self.source_ip = config.get('root', 'SourceIP')

        for key in config['root']:
            if key.startswith('tls'):
                self.tls[key] = config.get('root', key)

    def __load_config(self, filepath: str) -> None:

        config = configparser.ConfigParser(strict=False)

        with open(filepath, 'r', encoding='utf-8') as cfg:
            config.read_string('[root]\n' + cfg.read())

        self.__read_config(config)

    def __receive(self, conn: socket, size: int) -> bytes:

        buf = b''

        while len(buf) < size:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk

        return buf

    def __get_response(self, conn: socket) -> Union[dict, None]:

        result = None
        header_size = 13
        response_header = self.__receive(conn, header_size)

        log.debug('Zabbix response header: %s', response_header)

        if (not response_header.startswith(b'ZBXD\x01') or
                len(response_header) != header_size):
            log.debug('Unexpected response was received from Zabbix.')
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
            response_body = conn.recv(response_len)

            try:
                result = json.loads(response_body.decode("utf-8"))
            except json.decoder.JSONDecodeError as err:
                log.debug('Unexpected response was received from Zabbix.')
                raise err

            log.debug('Received data: %s', result)

        try:
            conn.close()
        except socket.error:
            pass

        return result

    def __create_packet(self, items: list, compressed_size: Union[int, None] = None) -> bytes:

        request = json.dumps({
            "request": "sender data",
            "data": [i.to_json() for i in items]
        })

        flags = 0x01
        if compressed_size is None:
            datalen = len(request)
            reserved = 0
        else:
            flags |= 0x02
            datalen = compressed_size
            reserved = len(request)

        header = struct.pack('<4sBII', b'ZBXD', flags, datalen, reserved)
        packet = header + request.encode("utf-8")

        log.debug('Content of the packet: %s', packet)

        return packet

    def __chunk_send(self, items: list) -> Union[dict, None]:

        packet = self.__create_packet(items)

        for cluster in self.clusters:
            failed_conn = True
            active_node = None
            response = None

            for node in cluster.nodes:

                log.debug('Trying to send data to %s', node)

                try:
                    if self.use_ipv6:
                        connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    else:
                        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                except socket.error:
                    raise ProcessingException(f"Error creating socket for {node}") from None

                connection.settimeout(self.timeout)

                if self.source_ip:
                    connection.bind((self.source_ip, 0,))

                try:
                    connection.connect(tuple(node))
                except (TimeoutError, socket.timeout):
                    log.debug(
                        'The connection to %s timed out after %d seconds',
                        node,
                        self.timeout
                    )
                except (ConnectionRefusedError, socket.gaierror) as err:
                    log.debug(
                        'An error occurred while trying to connect to %s: %s',
                        node,
                        getattr(err, 'msg', str(err))
                    )
                else:
                    failed_conn = False
                    active_node = node
                    break

            if failed_conn:
                log.error(
                    'Couldn\'t connect to all of cluster nodes: %s',
                    str(list(cluster.nodes))
                )
                connection.close()
                raise ProcessingException(
                    f"Couldn't connect to all of cluster nodes: {list(cluster.nodes)}"
                )

            connection = self.socket_wrapper(
                connection, self.tls) if self.socket_wrapper else connection

            try:
                connection.sendall(packet)
            except (TimeoutError, socket.timeout) as err:
                log.error(
                    'The connection to %s timed out after %d seconds while trying to send',
                    active_node,
                    self.timeout
                )
                connection.close()
                raise err
            except (OSError, socket.error) as err:
                log.warning(
                    'An error occurred while trying to send to %s: %s',
                    active_node,
                    getattr(err, 'msg', str(err))
                )
                connection.close()
                raise err

            if connection:
                response = self.__get_response(connection)
                log.debug('Response from %s: %s', active_node, response)

            if response and response.get('response') != 'success':
                raise socket.error(response)

        return response

    def send_value(self, *args, **kwargs) -> dict:
        """Sends one value and receives an answer from Zabbix.

        Args:
            host (str): Specify host name the item belongs to (as registered in Zabbix frontend).

            key (str): Specify item key to send value to.

            value (str): Specify item value.

            clock (int, optional): Specify time in Unix timestamp format. Defaults to `None`.

            ns (int, optional): Specify time expressed in nanoseconds. Defaults to `None`.

        Returns:
            list: List of ZabbixResponse objects.
        """

        resp = ZabbixResponse()
        resp.parse(self.__chunk_send([ZabbixItem(*args, **kwargs)]))

        return resp

    def send(self, items: list) -> list:
        """Sends packets and receives an answer from Zabbix.

        Args:
            items (list): List of ZabbixItem objects.

        Returns:
            list: List of ZabbixResponse objects.
        """

        result = []
        for chunk in range(0, len(items), self.chunk_size):
            resp = ZabbixResponse(int(chunk/self.chunk_size+1))
            resp.parse(self.__chunk_send(items[chunk:chunk + self.chunk_size]))
            result.append(resp)
        return result
