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

import json
import socket
import logging
import configparser

from typing import Callable, Optional, Union, Tuple

from .logger import EmptyHandler
from .common import ZabbixProtocol
from .exceptions import ProcessingError
from .types import TrapperResponse, ItemValue, Cluster, Node

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class Sender():
    """Zabbix sender synchronous implementation.

    Args:
        server (str, optional): Zabbix server address. Defaults to `'127.0.0.1'`.
        port (int, optional): Zabbix server port. Defaults to `10051`.
        use_config (bool, optional): Specifying configuration use. Defaults to `False`.
        timeout (int, optional): Connection timeout value. Defaults to `10`.
        use_ipv6 (bool, optional): Specifying IPv6 use instead of IPv4. Defaults to `False`.
        source_ip (str, optional): IP from which to establish connection. Defaults to `None`.
        chunk_size (int, optional): Number of packets in one chunk. Defaults to `250`.
        clusters (tuple|list, optional): List of Zabbix clusters. Defaults to `None`.
        socket_wrapper (Callable, optional): Func(`conn`,`tls`) to wrap socket. Defaults to `None`.
        compression (bool, optional): Specifying compression use. Defaults to `False`.
        config_path (str, optional): Path to Zabbix agent configuration file. Defaults to \
`/etc/zabbix/zabbix_agentd.conf`.
    """

    def __init__(self, server: Optional[str] = None, port: int = 10051,
                 use_config: bool = False, timeout: int = 10,
                 use_ipv6: bool = False, source_ip: Optional[str] = None,
                 chunk_size: int = 250, clusters: Union[tuple, list] = None,
                 socket_wrapper: Optional[Callable] = None, compression: bool = False,
                 config_path: Optional[str] = '/etc/zabbix/zabbix_agentd.conf'):
        self.timeout = timeout
        self.use_ipv6 = use_ipv6
        self.tls = {}

        self.source_ip = None
        self.chunk_size = chunk_size
        self.compression = compression

        if socket_wrapper is not None:
            if not isinstance(socket_wrapper, Callable):
                raise TypeError('Value "socket_wrapper" should be a function.') from None
        self.socket_wrapper = socket_wrapper

        if source_ip is not None:
            self.source_ip = source_ip

        if use_config:
            self.clusters = []
            self.__load_config(config_path)
            return

        if clusters is not None:
            if not (isinstance(clusters, tuple) or isinstance(clusters, list)):
                raise TypeError('Value "clusters" should be a tuple or a list.') from None

            clusters = clusters.copy()

            if server is not None:
                clusters.append([f"{server}:{port}"])

            self.clusters = [Cluster(c) for c in clusters]
        else:
            self.clusters = [Cluster([f"{server or '127.0.0.1'}:{port}"])]

    def __read_config(self, config: configparser.SectionProxy) -> None:
        server_row = config.get('ServerActive') or config.get('Server') or '127.0.0.1:10051'

        for cluster in server_row.split(','):
            self.clusters.append(Cluster(cluster.strip().split(';')))

        if 'SourceIP' in config:
            self.source_ip = config.get('SourceIP')

        for key in config:
            if key.startswith('tls'):
                self.tls[key] = config.get(key)

    def __load_config(self, filepath: str) -> None:
        config = configparser.ConfigParser(strict=False)

        with open(filepath, 'r', encoding='utf-8') as cfg:
            config.read_string('[root]\n' + cfg.read())
        self.__read_config(config['root'])

    def __get_response(self, conn: socket) -> Optional[dict]:
        try:
            result = json.loads(
                ZabbixProtocol.parse_sync_packet(conn, log, ProcessingError)
            )
        except json.decoder.JSONDecodeError as err:
            log.debug('Unexpected response was received from Zabbix.')
            raise err

        log.debug('Received data: %s', result)

        return result

    def __create_request(self, items: list) -> dict:
        return {
            "request": "sender data",
            "data": [i.to_json() for i in items]
        }

    def __send_to_cluster(self, cluster: Cluster, packet: bytes) -> Optional[Tuple[Node, dict]]:
        active_node = None
        active_node_idx = 0
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
                active_node_idx = i
                if i > 0:
                    cluster.nodes[0], cluster.nodes[i] = cluster.nodes[i], cluster.nodes[0]
                    active_node_idx = 0
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
            if response.get('redirect'):
                print(response)
                log.debug(
                    'Packet was redirected from %s to %s. Proxy group revision: %s.',
                    active_node,
                    response['redirect']['address'],
                    response['redirect']['revision']
                )
                cluster.nodes[active_node_idx] = Node(*response['redirect']['address'].split(':'))
                active_node, response = self.__send_to_cluster(cluster, packet)
            else:
                raise socket.error(response)

        try:
            connection.close()
        except socket.error:
            pass

        return active_node, response

    def __chunk_send(self, items: list) -> dict:
        responses = {}

        packet = ZabbixProtocol.create_packet(self.__create_request(items), log, self.compression)

        for cluster in self.clusters:
            active_node, response = self.__send_to_cluster(cluster, packet)
            responses[active_node] = response

        return responses

    def send(self, items: list) -> TrapperResponse:
        """Sends packets and receives an answer from Zabbix.

        Args:
            items (list): List of ItemValue objects.

        Returns:
            TrapperResponse: Response from Zabbix server/proxy.
        """

        # Split the list of items into chunks of size self.chunk_size.
        chunks = [items[i:i + self.chunk_size] for i in range(0, len(items), self.chunk_size)]

        # Merge responses into a single TrapperResponse object.
        try:
            result = TrapperResponse()
        except ProcessingError as err:
            log.debug(err)
            raise ProcessingError(err) from err

        # TrapperResponse details for each node and chunk.
        result.details = {}

        for i, chunk in enumerate(chunks):

            if not all(isinstance(item, ItemValue) for item in chunk):
                log.debug('Received unexpected item list. It must be a list of \
ItemValue objects: %s', json.dumps(chunk))
                raise ProcessingError(f"Received unexpected item list. \
It must be a list of ItemValue objects: {json.dumps(chunk)}")

            resp_by_node = self.__chunk_send(chunk)

            node_step = 1
            for node, resp in resp_by_node.items():
                try:
                    result.add(resp, (i + 1) * node_step)
                except ProcessingError as err:
                    log.debug(err)
                    raise ProcessingError(err) from None
                node_step += 1

                if node not in result.details:
                    result.details[node] = []
                result.details[node].append(TrapperResponse(i+1).add(resp))

        return result

    def send_value(self, host: str, key: str,
                   value: str, clock: Optional[int] = None,
                   ns: Optional[int] = None) -> TrapperResponse:
        """Sends one value and receives an answer from Zabbix.

        Args:
            host (str): Specify host name the item belongs to (as registered in Zabbix frontend).
            key (str): Specify item key to send value to.
            value (str): Specify item value.
            clock (int, optional): Specify time in Unix timestamp format. Defaults to `None`.
            ns (int, optional): Specify time expressed in nanoseconds. Defaults to `None`.

        Returns:
            TrapperResponse: Response from Zabbix server/proxy.
        """

        return self.send([ItemValue(host, key, value, clock, ns)])
