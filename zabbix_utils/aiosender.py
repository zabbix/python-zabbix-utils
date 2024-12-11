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
import json
import socket
import asyncio
import logging
import configparser

from typing import Callable, Union, Optional, Tuple

from .logger import EmptyHandler
from .common import ZabbixProtocol
from .exceptions import ProcessingError
from .types import TrapperResponse, ItemValue, Cluster, Node

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())


class AsyncSender():
    """Zabbix sender asynchronous implementation.

    Args:
        server (str, optional): Zabbix server address. Defaults to `'127.0.0.1'`.
        port (int, optional): Zabbix server port. Defaults to `10051`.
        use_config (bool, optional): Specifying configuration use. Defaults to `False`.
        timeout (int, optional): Connection timeout value. Defaults to `10`.
        use_ipv6 (bool, optional): Specifying IPv6 use instead of IPv4. Defaults to `False`.
        source_ip (str, optional): IP from which to establish connection. Defaults to `None`.
        chunk_size (int, optional): Number of packets in one chunk. Defaults to `250`.
        clusters (tuple|list, optional): List of Zabbix clusters. Defaults to `None`.
        ssl_context (Callable, optional): Func(`tls`), returned prepared ssl.SSLContext. \
Defaults to `None`.
        compression (bool, optional): Specifying compression use. Defaults to `False`.
        config_path (str, optional): Path to Zabbix agent configuration file. Defaults to \
`/etc/zabbix/zabbix_agentd.conf`.
    """

    def __init__(self, server: Optional[str] = None, port: int = 10051,
                 use_config: bool = False, timeout: int = 10,
                 use_ipv6: bool = False, source_ip: Optional[str] = None,
                 chunk_size: int = 250, clusters: Union[tuple, list] = None,
                 ssl_context: Optional[Callable] = None, compression: bool = False,
                 config_path: Optional[str] = '/etc/zabbix/zabbix_agentd.conf'):
        self.timeout = timeout
        self.use_ipv6 = use_ipv6
        self.tls = {}

        self.source_ip = None
        self.chunk_size = chunk_size
        self.compression = compression

        if ssl_context is not None:
            if not isinstance(ssl_context, Callable):
                raise TypeError('Value "ssl_context" should be a function.') from None
        self.ssl_context = ssl_context

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

    async def __get_response(self, reader: asyncio.StreamReader) -> Optional[str]:
        try:
            result = json.loads(
                await ZabbixProtocol.parse_async_packet(reader, log, ProcessingError)
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

    async def __send_to_cluster(self, cluster: Cluster, packet: bytes) -> Optional[Tuple[Node, dict]]:
        active_node = None
        active_node_idx = 0
        for i, node in enumerate(cluster.nodes):

            log.debug('Trying to send data to %s', node)

            connection_params = {
                "host": node.address,
                "port": node.port
            }

            if self.source_ip:
                connection_params['local_addr'] = (self.source_ip, 0)

            if self.ssl_context is not None:
                connection_params['ssl'] = self.ssl_context(self.tls)
                if not isinstance(connection_params['ssl'], ssl.SSLContext):
                    raise TypeError(
                        'Function "ssl_context" must return "ssl.SSLContext".') from None

            connection = asyncio.open_connection(**connection_params)

            try:
                reader, writer = await asyncio.wait_for(connection, timeout=self.timeout)
            except asyncio.TimeoutError:
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
            raise ProcessingError(
                f"Couldn't connect to all of cluster nodes: {list(cluster.nodes)}"
            )

        try:
            writer.write(packet)
            send_data = writer.drain()
            await asyncio.wait_for(send_data, timeout=self.timeout)
        except (asyncio.TimeoutError, socket.timeout) as err:
            log.error(
                'The connection to %s timed out after %d seconds while trying to send',
                active_node,
                self.timeout
            )
            writer.close()
            await writer.wait_closed()
            raise err
        except (OSError, socket.error) as err:
            log.warning(
                'An error occurred while trying to send to %s: %s',
                active_node,
                getattr(err, 'msg', str(err))
            )
            writer.close()
            await writer.wait_closed()
            raise err
        try:
            response = await self.__get_response(reader)
        except (ConnectionResetError, asyncio.exceptions.IncompleteReadError) as err:
            log.debug('Get value error: %s', err)
            raise err
        log.debug('Response from %s: %s', active_node, response)

        if response and response.get('response') != 'success':
            if response.get('redirect'):
                log.debug(
                    'Packet was redirected from %s to %s. Proxy group revision: %s.',
                    active_node,
                    response['redirect']['address'],
                    response['redirect']['revision']
                )
                cluster.nodes[active_node_idx] = Node(*response['redirect']['address'].split(':'))
                active_node, response = await self.__send_to_cluster(cluster, packet)
            else:
                raise ProcessingError(response) from None

        writer.close()
        await writer.wait_closed()

        return active_node, response

    async def __chunk_send(self, items: list) -> dict:
        responses = {}

        packet = ZabbixProtocol.create_packet(self.__create_request(items), log, self.compression)

        for cluster in self.clusters:
            active_node, response = await self.__send_to_cluster(cluster, packet)
            responses[active_node] = response

        return responses

    async def send(self, items: list) -> TrapperResponse:
        """Sends packets and receives an answer from Zabbix.

        Args:
            items (list): List of ItemValue objects.

        Returns:
            TrapperResponse: Response from Zabbix server/proxy.
        """

        # Split the list of items into chunks of size self.chunk_size.
        chunks = [items[i:i + self.chunk_size] for i in range(0, len(items), self.chunk_size)]

        # Merge responses into a single TrapperResponse object.
        result = TrapperResponse()

        # TrapperResponse details for each node and chunk.
        result.details = {}

        for i, chunk in enumerate(chunks):

            if not all(isinstance(item, ItemValue) for item in chunk):
                log.debug('Received unexpected item list. It must be a list of \
ItemValue objects: %s', json.dumps(chunk))
                raise ProcessingError(f"Received unexpected item list. \
It must be a list of ItemValue objects: {json.dumps(chunk)}")

            resp_by_node = await self.__chunk_send(chunk)

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

    async def send_value(self, host: str, key: str,
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

        return await self.send([ItemValue(host, key, value, clock, ns)])
