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
# For Python less 3.11 compatibility
try:
    from typing import Self  # type: ignore
except ImportError:
    from typing_extensions import Self

from .logger import EmptyHandler
from .common import ZabbixProtocol
from .exceptions import ProcessingError

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class TrapperResponse():
    """Contains response from Zabbix server/proxy.

    Args:
        chunk (int, optional): Current chunk number. Defaults to `1`.
    """

    def __init__(self, chunk: int = 1):
        self.__processed = 0
        self.__failed = 0
        self.__total = 0
        self.__time = 0
        self.__chunk = chunk

    def __repr__(self) -> str:
        # Represent the object as a JSON-formatted string.
        result = {}
        for key, value in self.__dict__.items():
            result[
                key[len(f"_{self.__class__.__name__}__"):]
            ] = str(value) if isinstance(value, Decimal) else value

        return json.dumps(result)

    def parse(self, response: dict) -> dict:
        """Parse response from Zabbix.

        Args:
            response (dict): Raw response from Zabbix.

        Raises:
            ProcessingError: Raises if unexpected response received
        """

        # Define patterns for extracting information from the response.
        fields = {
            "processed": ('[Pp]rocessed', r'\d+'),
            "failed": ('[Ff]ailed', r'\d+'),
            "total": ('[Tt]otal', r'\d+'),
            "time": ('[Ss]econds spent', r'\d+\.\d+')
        }

        # Create a regular expression pattern based on the defined fields.
        pattern = re.compile(
            r";\s+?".join([rf"{r[0]}:\s+?(?P<{k}>{r[1]})" for k, r in fields.items()])
        )

        # Extract 'info' field from the Zabbix response.
        info = response.get('info')
        if not info:
            log.debug('Received unexpected response: %s', response)
            raise ProcessingError(f"Received unexpected response: {response}")

        # Use regular expression to match and extract information from 'info'.
        res = pattern.search(info).groupdict()

        return res

    def add(self, response: dict, chunk: Union[int, None] = None) -> Self:
        """Add and merge response data from Zabbix.

        Args:
            response (dict): Raw response from Zabbix.
            chunk (Union[int, None], optional): Chunk number. Defaults to `None`.
        """

        resp = self.parse(response)

        def add_value(cls, key, value):
            setattr(
                cls,
                key,
                getattr(cls, key) + value
            )

        # Convert values to appropriate types and set them as attributes.
        for k, v in resp.items():
            add_value(
                self,
                f"_{self.__class__.__name__}__{k}",
                Decimal(v) if '.' in v else int(v)
            )
        if chunk is not None:
            self.__chunk = chunk

        return self

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


class ItemValue():
    """Contains data of a single item value.

    Args:
        host (str): Specify host name the item belongs to (as registered in Zabbix frontend).
        key (str): Specify item key to send value to.
        value (str): Specify item value.
        clock (int, optional): Specify time in Unix timestamp format. Defaults to `None`.
        ns (int, optional): Specify time expressed in nanoseconds. Defaults to `None`.
    """

    def __init__(self, host: str, key: str, value: str,
                 clock: Union[int, None] = None, ns: Union[int, None] = None):
        self.host = str(host)
        self.key = str(key)
        self.value = str(value)
        self.clock = None
        self.ns = None

        # Validate and set clock value if provided.
        if clock is not None:
            try:
                self.clock = int(clock)
            except ValueError:
                raise ValueError(
                    'The clock value must be expressed in the Unix Timestamp format') from None

        # Validate and set ns value if provided.
        if ns is not None:
            try:
                self.ns = int(ns)
            except ValueError:
                raise ValueError(
                    'The ns value must be expressed in the integer value of nanoseconds') from None

    def __to_string(self) -> str:
        # Convert ItemValue to a JSON-formatted string.
        return json.dumps(self.to_json(), ensure_ascii=False)

    def __str__(self) -> str:
        # Convert ItemValue to a string using the to_string method.
        return self.__to_string()

    def __repr__(self) -> str:
        # Represent ItemValue as a string.
        return self.__str__()

    def to_json(self) -> dict:
        """Represents ItemValue object in dictionary for json.

        Returns:
            dict: Object attributes in dictionary.
        """

        # Convert ItemValue attributes to a dictionary, excluding None values.
        return {k: v for k, v in self.__dict__.items() if v is not None}


class Node():
    """Contains one Zabbix node object.

    Args:
        addr (str): Listen address of Zabbix server.
        port (int, str): Listen port of Zabbix server.

    Raises:
        TypeError: Raises if not integer value was received.
    """

    def __init__(self, addr: str, port: Union[int, str]):
        # If the address is '0.0.0.0/0', set it to '127.0.0.1'.
        self.address = addr if addr != '0.0.0.0/0' else '127.0.0.1'
        # Validate and set the port as an integer value.
        try:
            self.port = int(port)
        except ValueError:
            raise TypeError('Port must be an integer value') from None

    def __str__(self) -> str:
        # Convert Node object to a string.
        return f"{self.address}:{self.port}"

    def __repr__(self) -> str:
        # Represent Node object as a string.
        return self.__str__()


class Cluster():
    """Contains Zabbix node objects in a cluster object.

    Args:
        addr (str): Raw string with node addresses.
    """

    def __init__(self, addr: str):
        self.__nodes = self.__parse_ha_node(addr)

    def __parse_ha_node(self, string: str) -> list:
        # Parse the raw string of node addresses into a list of Node objects.
        nodes = []
        for node_item in string.split(';'):
            node_item = node_item.strip()
            # If ':' is present, split and create a Node with address and port.
            # Else, create a Node with the address and default port '10051'.
            if ':' in node_item:
                nodes.append(Node(*node_item.split(':')))
            else:
                nodes.append(Node(node_item, '10051'))

        return nodes

    def __str__(self) -> str:
        # Convert Cluster object to a JSON-formatted string.
        return json.dumps([(node.address, node.port) for node in self.__nodes])

    def __repr__(self) -> str:
        # Represent Cluster object as a string.
        return self.__str__()

    @property
    def nodes(self) -> list:
        """Returns list of Node objects.

        Returns:
            list List of Node objects
        """

        return self.__nodes


class Sender():
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
        compression (bool, optional): Specifying compression use. Defaults to `False`.
        config_path (str, optional): Path to Zabbix agent configuration file. Defaults to \
`/etc/zabbix/zabbix_agentd.conf`.
    """

    def __init__(self, server: str = '127.0.0.1', port: int = 10051,
                 use_config: bool = False, timeout: int = 10, use_ipv6: bool = False,
                 source_ip: Union[str, None] = None, chunk_size: int = 250,
                 socket_wrapper: Union[Callable, None] = None, compression: bool = False,
                 config_path: Union[str, None] = '/etc/zabbix/zabbix_agentd.conf'):
        self.timeout = timeout
        self.use_ipv6 = use_ipv6
        self.tls = {}

        self.source_ip = None
        self.chunk_size = chunk_size
        self.compression = compression

        # Validate and store the socket_wrapper function if provided.
        if socket_wrapper is not None:
            if not isinstance(socket_wrapper, Callable):
                raise TypeError('Value "socket_wrapper" should be a function.')
        self.socket_wrapper = socket_wrapper

        # Load clusters from configuration or use default cluster parameters.
        if use_config:
            self.clusters = []
            self.__load_config(config_path)
        else:
            self.clusters = [Cluster(f"{server}:{port}")]

        # Specify the source_ip value if provided.
        if source_ip is not None:
            self.source_ip = source_ip

    def __read_config(self, config: configparser.SectionProxy) -> None:
        # Read server configuration from the provided SectionProxy object.
        server_row = config.get('ServerActive') or config.get('Server') or '127.0.0.1:10051'

        # Iterate through comma-separated server addresses and create Cluster objects.
        for cluster in server_row.split(','):
            self.clusters.append(Cluster(cluster.strip()))

        # Read and set the 'SourceIP' attribute if present in the configuration.
        if 'SourceIP' in config:
            self.source_ip = config.get('SourceIP')

        # Read and set TLS attributes if present in the configuration.
        for key in config:
            if key.startswith('tls'):
                self.tls[key] = config.get(key)

    def __load_config(self, filepath: str) -> None:
        # Create a ConfigParser object for parsing the configuration.
        config = configparser.ConfigParser(strict=False)

        # Read the content of the configuration file.
        with open(filepath, 'r', encoding='utf-8') as cfg:
            config.read_string('[root]\n' + cfg.read())

        # Read configurations from the root section of ConfigParser object.
        self.__read_config(config['root'])

    def __receive(self, conn: socket, size: int) -> bytes:
        buf = b''

        # Receive data from the socket until the specified size is reached.
        while len(buf) < size:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk

        return buf

    def __get_response(self, conn: socket) -> Union[str, None]:
        # Receive and parse the response from the Zabbix server/proxy.
        try:
            result = json.loads(
                ZabbixProtocol.parse_packet(conn, log, self.__receive, ProcessingError)
            )
        except json.decoder.JSONDecodeError as err:
            log.debug('Unexpected response was received from Zabbix.')
            raise err

        log.debug('Received data: %s', result)

        return result

    def __create_packet(self, items: list) -> bytes:
        request = json.dumps({
            "request": "sender data",
            "data": [i.to_json() for i in items]
        }, ensure_ascii=False)

        return ZabbixProtocol.create_packet(request.encode("utf-8"), log, self.compression)

    def __chunk_send(self, items: list) -> dict:
        responses = {}

        packet = self.__create_packet(items)

        for cluster in self.clusters:
            active_node = None

            for i, node in enumerate(cluster.nodes):

                log.debug('Trying to send data to %s', node)

                try:
                    if self.use_ipv6:
                        connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    else:
                        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                except socket.error:
                    raise ProcessingError(f"Error creating socket for {node}") from None

                connection.settimeout(self.timeout)

                if self.source_ip:
                    connection.bind((self.source_ip, 0,))

                try:
                    connection.connect((node.address, node.port))
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
                    # Connection succeeded
                    if i > 0:
                        cluster.nodes[0], cluster.nodes[i] = cluster.nodes[i], cluster.nodes[0]
                    active_node = node
                    break

            if active_node is None:
                log.error(
                    'Couldn\'t connect to all of cluster nodes: %s',
                    str(list(cluster.nodes))
                )
                connection.close()
                raise ProcessingError(
                    f"Couldn't connect to all of cluster nodes: {list(cluster.nodes)}"
                )

            # Wrap the socket if a socket wrapper function is specified.
            if self.socket_wrapper is not None:
                connection = self.socket_wrapper(connection, self.tls)

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

            try:
                response = self.__get_response(connection)
            except ConnectionResetError as err:
                log.debug('Get value error: %s', err)
                raise err
            log.debug('Response from %s: %s', active_node, response)

            if response and response.get('response') != 'success':
                raise socket.error(response)

            responses[active_node] = response

            try:
                connection.close()
            except socket.error:
                pass

        return responses

    def send_value(self, host: str, key: str, value: str,
                   clock: Union[int, None] = None, ns: Union[int, None] = None) -> dict:
        """Sends one value and receives an answer from Zabbix.

        Args:
            host (str): Specify host name the item belongs to (as registered in Zabbix frontend).
            key (str): Specify item key to send value to.
            value (str): Specify item value.
            clock (int, optional): Specify time in Unix timestamp format. Defaults to `None`.
            ns (int, optional): Specify time expressed in nanoseconds. Defaults to `None`.

        Returns:
            dict: Dictionary of TrapperResponse object for each Node object.
        """

        result = {}

        resp_by_node = self.__chunk_send([ItemValue(host, key, value, clock, ns)])

        for cluster, resp in resp_by_node.items():
            if cluster not in result:
                result[cluster] = TrapperResponse()
            result[cluster].add(resp)

        return result

    def send(self, items: list, merge_responses: bool = True) -> dict:
        """Sends packets and receives an answer from Zabbix.

        Args:
            items (list): List of ItemValue objects.
            merge_responses (bool, optional): Whether to merge all responses data \
to a single one. Defaults to `True`.

        Returns:
            dict: Dictionary of TrapperResponse objects for each Node object.
        """

        result = {}

        if not all(isinstance(item, ItemValue) for item in items):
            log.debug('Received unexpected item list. It must be a list of ItemValue objects: %s',
                      json.dumps(items))
            raise ProcessingError(f"Received unexpected item list. \
It must be a list of ItemValue objects: {json.dumps(items)}")

        # Split the list of items into chunks of size self.chunk_size.
        chunks = [items[i:i + self.chunk_size] for i in range(0, len(items), self.chunk_size)]
        for i, chunk in enumerate(chunks):

            resp_by_node = self.__chunk_send(chunk)

            for node, resp in resp_by_node.items():
                if merge_responses:
                    # Merge responses into a single TrapperResponse object for each node.
                    if node not in result:
                        result[node] = TrapperResponse()
                    result[node].add(resp, i + 1)
                else:
                    # Store responses as a list of TrapperResponse objects for each node.
                    if node not in result:
                        result[node] = []
                    result[node].append(TrapperResponse(i+1).add(resp))

        return result
