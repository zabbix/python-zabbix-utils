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
import asyncio
import unittest
import configparser
from unittest.mock import patch

from tests import common
from zabbix_utils.types import ItemValue, TrapperResponse
from zabbix_utils.aiosender import AsyncSender
from zabbix_utils.exceptions import ProcessingError
from zabbix_utils.common import ZabbixProtocol


DEFAULT_VALUES = common.SENDER_DEFAULTS
ZABBIX_CONFIG = common.ZABBIX_CONFIG


class TestAsyncSender(unittest.IsolatedAsyncioTestCase):
    """Test cases for AsyncSender object"""

    def test_init(self):
        """Tests creating of AsyncSender object"""

        test_cases = [
            {
                'input': {'source_ip': DEFAULT_VALUES['source_ip']},
                'clusters': json.dumps([[["127.0.0.1", DEFAULT_VALUES['port']]]]),
                'source_ip': DEFAULT_VALUES['source_ip']
            },
            {
                'input': {'server': DEFAULT_VALUES['server'], 'port': 10151},
                'clusters': json.dumps([[[DEFAULT_VALUES['server'], 10151]]]),
                'source_ip': None
            },
            {
                'input': {'server': DEFAULT_VALUES['server'], 'port': 10151, 'clusters': DEFAULT_VALUES['clusters']},
                'clusters': json.dumps([
                    [["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051]],
                    [["zabbix.cluster2.node1", 10051], ["zabbix.cluster2.node2", 10051]],
                    [["zabbix.domain", 10051]],
                    [["localhost", 10151]]
                ]),
                'source_ip': None
            },
            {
                'input': {'clusters': DEFAULT_VALUES['clusters']},
                'clusters': json.dumps([
                    [["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051]],
                    [["zabbix.cluster2.node1", 10051], ["zabbix.cluster2.node2", 10051]],
                    [["zabbix.domain", 10051]]
                ]),
                'source_ip': None
            },
            {
                'input': {'server': DEFAULT_VALUES['server'], 'port': 10151, 'use_config': True, 'config_path': ZABBIX_CONFIG[0]},
                'clusters': json.dumps([
                    [["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051]],
                    [["zabbix.cluster2.node1", 10051], ["zabbix.cluster2.node2", 10051]],
                    [["zabbix.domain", 10051]]
                ]),
                'source_ip': DEFAULT_VALUES['source_ip']
            },
            {
                'input': {'use_config': True, 'config_path': ZABBIX_CONFIG[1]},
                'clusters': json.dumps([[["localhost", 10051]]]),
                'source_ip': DEFAULT_VALUES['source_ip']
            },
            {
                'input': {'use_config': True, 'config_path': ZABBIX_CONFIG[2]},
                'clusters': json.dumps([[["127.0.0.1", 10051]]]),
                'source_ip': DEFAULT_VALUES['source_ip']
            }
        ]

        def mock_load_config(self, filepath):
            config = configparser.ConfigParser(strict=False)
            config.read_string(filepath)
            self._AsyncSender__read_config(config['root'])

        for case in test_cases:
            with patch.multiple(
                    AsyncSender,
                    _AsyncSender__load_config=mock_load_config):

                sender = AsyncSender(**case['input'])

                self.assertEqual(str(sender.clusters), case['clusters'],
                                 f"unexpected output with input data: {case['input']}")
                self.assertEqual(sender.source_ip, case['source_ip'],
                                 f"unexpected output with input data: {case['input']}")

                for cluster in sender.clusters:
                    for node in cluster.nodes:
                        self.assertEqual(str(node), repr(node),
                                         f"unexpected node value {node} with input data: {case['input']}")

                with self.assertRaises(TypeError,
                                   msg="expected TypeError exception hasn't been raised"):
                    sender = AsyncSender(ssl_context='wrapper', **case['input'])

        with self.assertRaises(TypeError,
                               msg="expected TypeError exception hasn't been raised"):
            sender = AsyncSender(server='localhost', port='test')

    async def test_get_response(self):
        """Tests __get_response method in different cases"""

        async def test_case(input_stream):
            sender = AsyncSender()
            reader = common.MockReader()
            reader.set_stream(input_stream)
            return await sender._AsyncSender__get_response(reader)

        test_cases = [
            {
                'input': b'ZBXD\x01\x53\x00\x00\x00\x00\x00\x00\x00{"request": "sender data", "data": \
[{"host": "test", "key": "test", "value": "0"}]}',
                'output': '{"request": "sender data", "data": [{"host": "test", "key": "test", "value": "0"}]}'
            },
            {
                'input': b'ZBXD\x01\x63\x00\x00\x00\x00\x00\x00\x00{"request": "sender data", "data": \
[{"host": "test", "key": "test_creating_packet", "value": "0"}]}',
                'output': '{"request": "sender data", "data": [{"host": "test", "key": "test_creating_packet", "value": "0"}]}'
            },
            {
                'input': b"ZBXD\x03Q\x00\x00\x00^\x00\x00\x00x\x9c\xabV*J-,M-.Q\
\xb2RP*N\xcdKI-RHI,IT\xd2QP\x02\xd3V\n\xd1\xd5J\x19\xf9\x10\x05% \x85@\x99\xec\xd4J\x187>)\
\xbf$#>-'1\xbd\x18$S\x96\x98S\x9a\n\x923P\xaa\x8d\xad\x05\x00\x9e\xb7\x1d\xdd",
                'output': '{"request": "sender data", "data": [{"host": "test", "key": "test_both_flags", "value": "0"}]}'
            }
        ]

        for case in test_cases:
            self.assertEqual(json.dumps(await test_case(case['input'])), case['output'],
                             f"unexpected output with input data: {case['input']}")

        with self.assertRaises(json.decoder.JSONDecodeError,
                               msg="expected JSONDecodeError exception hasn't been raised"):
            await test_case(b'ZBXD\x01\x04\x00\x00\x00\x04\x00\x00\x00test')

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            await test_case(b'test')

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            await test_case(b'ZBXD\x04\x04\x00\x00\x00\x04\x00\x00\x00test')

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            await test_case(b'ZBXD\x00\x04\x00\x00\x00\x04\x00\x00\x00test')

        # Compression check
        try:
            await test_case(b'ZBXD\x03\x10\x00\x00\x00\x02\x00\x00\x00x\x9c\xab\xae\x05\x00\x01u\x00\xf9')
        except json.decoder.JSONDecodeError:
            self.fail(f"raised unexpected JSONDecodeError during the compression check")

    async def test_send(self):
        """Tests send method in different cases"""

        test_cases = [
            {
                'input': {}, 'total': 5, 'failed': 2,
                'output': json.dumps({"processed": 3, "failed": 2, "total": 5, "time": "0.000100", "chunk": 1})
            },
            {
                'input': {'chunk_size': 10}, 'total': 25, 'failed': 4,
                'output': json.dumps({"processed": 21, "failed": 4, "total": 25, "time": "0.000300", "chunk": 3})
            }
        ]

        async def mock_chunk_send(self, items):
            return {"127.0.0.1:10051": common.response_gen(items)}

        for case in test_cases:
            with patch.multiple(
                    AsyncSender,
                    _AsyncSender__chunk_send=mock_chunk_send):

                items = []
                sender = AsyncSender(**case['input'])
                failed_counter = case['failed']
                for _ in range(case['total']):
                    if failed_counter > 0:
                        items.append(ItemValue('host', 'key', 'false'))
                        failed_counter -= 1
                    else:
                        items.append(ItemValue('host', 'key', 'true'))
                resp = await sender.send(items)

                self.assertEqual(str(resp), case['output'],
                                 f"unexpected output with input data: {case['input']}")

                self.assertEqual(str(resp), repr(resp),
                                 f"unexpected output with input data: {case['input']}")

                try:
                    processed = resp.processed
                    failed = resp.failed
                    total = resp.total
                    time = resp.time
                    chunk = resp.chunk
                except Exception:
                    self.fail(f"raised unexpected Exception for responce: {resp}")

                self.assertEqual(type(resp.details['127.0.0.1:10051']), list,
                                 f"unexpected output with input data: {case['input']}")

                for chunks in resp.details.values():
                    for chunk in chunks:
                        try:
                            processed = chunk.processed
                            failed = chunk.failed
                            total = chunk.total
                            time = chunk.time
                            chunk = chunk.chunk
                        except Exception:
                            self.fail(f"raised unexpected Exception for responce: {chunk}")

        async def mock_chunk_send_empty(self, items):
            result = {"127.0.0.1:10051": {
                'response': 'success',
                'info': 'processed: 1; failed: 0; total: 1; seconds spent: 0.000100'
            }}

            return result

        with patch.multiple(AsyncSender,
                            _AsyncSender__chunk_send=mock_chunk_send_empty):
            sender = AsyncSender()
            resp = await sender.send_value('test', 'test', 1)
            self.assertEqual(str(resp), '{"processed": 1, "failed": 0, "total": 1, "time": "0.000100", "chunk": 1}',
                                 f"unexpected output with input data: {case['input']}")

    async def test_send_value(self):
        """Tests send_value method in different cases"""

        request = {"host": "test_host", "key": "test_key", "value": "true", "clock": 1695713666, "ns": 100}
        output = common.response_gen([request])
        response = ZabbixProtocol.create_packet(output, common.MockLogger())

        test_cases = [
            {
                'connection': {'input_stream': response},
                'input': {'use_ipv6': False},
                'output': output,
                'raised': False
            },
            {
                'connection': {'input_stream': response},
                'input': {'use_ipv6': True},
                'output': output,
                'raised': False
            },
            {
                'connection': {'input_stream': response},
                'input': {'source_ip': DEFAULT_VALUES['source_ip']},
                'output': output,
                'raised': False
            },
            {
                'connection': {'input_stream': response},
                'input': {'ssl_context': common.ssl_context},
                'output': output,
                'raised': False
            },
            {
                'connection': {'input_stream': response, 'exception': TypeError},
                'input': {'ssl_context': lambda x: ''},
                'output': output,
                'raised': True
            },
            {
                'connection': {'input_stream': response, 'exception': ConnectionResetError},
                'input': {},
                'output': output,
                'raised': True
            },
            {
                'connection': {'input_stream': response, 'exception': socket.error},
                'input': {},
                'output': output,
                'raised': True
            },
            {
                'connection': {'input_stream': response, 'exception': asyncio.TimeoutError},
                'input': {},
                'output': output,
                'raised': True
            }
        ]

        for case in test_cases:

            async def mock_open_connection(*args, **kwargs):
                reader = common.MockReader()
                reader.set_stream(case['connection'].get('input_stream',''))
                writer = common.MockWriter()
                writer.set_exception(case['connection'].get('exception'))
                return reader, writer

            with unittest.mock.patch.multiple(
                    asyncio,
                    open_connection=mock_open_connection):

                sender = AsyncSender(**case['input'])

                try:
                    resp = await sender.send_value(**request)
                except case['connection'].get('exception', Exception):
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                else:
                    self.assertEqual(repr(resp), repr(TrapperResponse(1).add(case['output'])),
                                    f"unexpected output with input data: {case['input']}")

        for exc in [asyncio.TimeoutError, socket.gaierror]:

            async def mock_open_connection1(*args, **kwargs):
                reader = common.MockReader()
                reader.set_stream(response)
                reader.set_exception(exc)
                writer = common.MockWriter()
                return reader, writer

            async def mock_wait_for(conn, *args, **kwargs):
                await conn
                raise exc

            with unittest.mock.patch.multiple(
                asyncio,
                wait_for=mock_wait_for,
                open_connection=mock_open_connection1):

                sender = AsyncSender(**case['input'])

                with self.assertRaises(ProcessingError,
                                       msg="expected ProcessingError exception hasn't been raised"):
                    resp = await sender.send_value(**request)

    def test_create_request(self):
        """Tests create_packet method in different cases"""

        test_cases = [
            {
                'input': {'items':[ItemValue('test', 'glāžšķūņu rūķīši', 0)]},
                'compression': False,
                'output': b'ZBXD\x01i\x00\x00\x00\x00\x00\x00\x00{"request": "sender data", "data": \
[{"host": "test", "key": "gl\xc4\x81\xc5\xbe\xc5\xa1\xc4\xb7\xc5\xab\xc5\x86u r\xc5\xab\xc4\xb7\xc4\xab\xc5\xa1i", "value": "0"}]}'
            },
            {
                'input': {'items':[ItemValue('test', 'test_creating_packet', 0)]},
                'compression': False,
                'output': b'ZBXD\x01\x63\x00\x00\x00\x00\x00\x00\x00{"request": "sender data", "data": \
[{"host": "test", "key": "test_creating_packet", "value": "0"}]}'
            },
            {
                'input': {'items':[ItemValue('test', 'test_compression_flag', 0)]},
                'compression': True,
                'output': b"ZBXD\x03W\x00\x00\x00d\x00\x00\x00x\x9c\xabV*J-,M-.Q\xb2RP*N\
\xcdKI-RHI,IT\xd2QP\x02\xd3V\n\xd1\xd5J\x19\xf9\x10\x05% \x85@\x99\xec\xd4J\x187>9?\xb7\xa0\
(\xb5\xb883?/>-'1\x1d$_\x96\x98S\x9a\nRa\xa0T\x1b[\x0b\x00l\xbf o"
            }
        ]

        for case in test_cases:

            resp = ZabbixProtocol.create_packet(AsyncSender()._AsyncSender__create_request(**case['input']), common.MockLogger(), case['compression'])
            self.assertEqual(resp, case['output'],
                             f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()
