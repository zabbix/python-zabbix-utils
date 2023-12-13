import json
import socket
import unittest
import configparser
from unittest.mock import patch

from zabbix_utils.sender import Sender, Cluster, ItemValue
from zabbix_utils.exceptions import ProcessingError


DEFAULT_VALUES = {
    'server': 'localhost',
    'port': 10051,
    'source_ip': '192.168.1.1'
}

ZABBIX_CONFIG = [
    f"""[root]
ServerActive=zabbix.cluster.node1;zabbix.cluster.node2:20051,zabbix.cluster2.node1;zabbix.cluster2.node2,zabbix.domain
Server={DEFAULT_VALUES['server']}
SourceIP={DEFAULT_VALUES['source_ip']}
TLSConnect=unencrypted
TLSAccept=unencrypted
""",
    f"""[root]
Server={DEFAULT_VALUES['server']}
SourceIP={DEFAULT_VALUES['source_ip']}
""",
    f"""[root]
SourceIP={DEFAULT_VALUES['source_ip']}
"""
]

class TestSender(unittest.TestCase):
    """Test cases for Sender object"""

    def test_init(self):
        """Tests creating of Sender object"""

        test_cases = [
            {
                'input': {'source_ip': '10.10.0.0'},
                'clusters': json.dumps([[["127.0.0.1", 10051]]]),
                'source_ip': '10.10.0.0'
            },
            {
                'input': {'server':'localhost', 'port': 10151},
                'clusters': json.dumps([[["localhost", 10151]]]),
                'source_ip': None
            },
            {
                'input': {'server':'localhost', 'port': 10151, 'use_config': True, 'config_path': ZABBIX_CONFIG[0]},
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
            self._Sender__read_config(config['root'])

        for case in test_cases:
            with patch.multiple(
                    Sender,
                    _Sender__load_config=mock_load_config):

                sender = Sender(**case['input'])

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
                    sender = Sender(socket_wrapper='wrapper', **case['input'])

        with self.assertRaises(TypeError,
                               msg="expected TypeError exception hasn't been raised"):
            sender = Sender(server='localhost', port='test')

    def test_create_packet(self):
        """Tests __create_packet method in different cases"""

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

            sender = Sender(compression=case['compression'])
            self.assertEqual(sender._Sender__create_packet(**case['input']), case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_get_response(self):
        """Tests __get_response method in different cases"""

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

        class ConnectTest():
            def __init__(self, input):
                self.input = input
                self.stream = input
            def recv(self, len):
                resp = self.stream[0:len]
                self.stream = self.stream[len:]
                return resp
            def close(self):
                raise socket.error("test error")

        for case in test_cases:

            sender = Sender()
            conn = ConnectTest(case['input'])

            self.assertEqual(json.dumps(sender._Sender__get_response(conn)), case['output'],
                             f"unexpected output with input data: {case['input']}")

        with self.assertRaises(json.decoder.JSONDecodeError,
                               msg="expected JSONDecodeError exception hasn't been raised"):
            sender = Sender()
            conn = ConnectTest(b'ZBXD\x01\x04\x00\x00\x00\x04\x00\x00\x00test')
            sender._Sender__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            sender = Sender()
            conn = ConnectTest(b'test')
            sender._Sender__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            sender = Sender()
            conn = ConnectTest(b'ZBXD\x04\x04\x00\x00\x00\x04\x00\x00\x00test')
            sender._Sender__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            sender = Sender()
            conn = ConnectTest(b'ZBXD\x00\x04\x00\x00\x00\x04\x00\x00\x00test')
            sender._Sender__get_response(conn)

        # Compression check
        try:
            sender = Sender()
            conn = ConnectTest(b'ZBXD\x03\x10\x00\x00\x00\x02\x00\x00\x00x\x9c\xab\xae\x05\x00\x01u\x00\xf9')
            sender._Sender__get_response(conn)
        except json.decoder.JSONDecodeError:
            self.fail(f"raised unexpected JSONDecodeError during the compression check")

    def test_send(self):
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

        def mock_chunk_send(self, items):
            info = {
                'processed': len([json.loads(i.value) for i in items if json.loads(i.value)]),
                'failed': len([json.loads(i.value) for i in items if not json.loads(i.value)]),
                'total': len(items),
                'seconds spent': '0.000100'
            }
            result = {"127.0.0.1:10051": {
                'response': 'success',
                'info': '; '.join([f"{k}: {v}" for k,v in info.items()])
            }}

            return result

        for case in test_cases:
            with patch.multiple(
                    Sender,
                    _Sender__chunk_send=mock_chunk_send):

                items = []
                sender = Sender(**case['input'])
                failed_counter = case['failed']
                for _ in range(case['total']):
                    if failed_counter > 0:
                        items.append(ItemValue('host', 'key', 'false'))
                        failed_counter -= 1
                    else:
                        items.append(ItemValue('host', 'key', 'true'))
                resp = sender.send(items)

                self.assertEqual(str(resp['127.0.0.1:10051']), case['output'],
                                 f"unexpected output with input data: {case['input']}")

                self.assertEqual(str(resp), repr(resp),
                                 f"unexpected output with input data: {case['input']}")

                for item in resp.values():
                    try:
                        processed = item.processed
                        failed = item.failed
                        total = item.total
                        time = item.time
                        chunk = item.chunk
                    except Exception:
                        self.fail(f"raised unexpected Exception for responce: {item}")

        def mock_chunk_send_empty(self, items):
            return {}

        with patch.multiple(Sender,
                            _Sender__chunk_send=mock_chunk_send_empty):
            sender = Sender()
            resp = sender.send_value('test', 'test', 1)
            self.assertEqual(str(resp), '{}',
                                 f"unexpected output with input data: {case['input']}")

    def test_send_value(self):
        """Tests send_value method in different cases"""

        test_cases = [
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': 1695713666, 'ns': 100},
                'output': json.dumps(
                    {"processed": 1, "failed": 0, "total": 1, "time": "0.000100", "chunk": 1}
                )
            }
        ]

        def mock_chunk_send(self, items):
            info = {
                'processed': len([i for i in items if i]),
                'failed': len([i for i in items if not i]),
                'total': len(items),
                'seconds spent': '0.000100'
            }
            result = {"127.0.0.1:10051": {
                'response': 'success',
                'info': '; '.join([f"{k}: {v}" for k,v in info.items()])
            }}

            return result

        for case in test_cases:
            with patch.multiple(
                    Sender,
                    _Sender__chunk_send=mock_chunk_send):

                sender = Sender()
                resp = sender.send_value(**case['input'])

                self.assertEqual(str(resp['127.0.0.1:10051']), case['output'],
                                 f"unexpected output with input data: {case['input']}")


class TestCluster(unittest.TestCase):
    """Test cases for Zabbix Cluster object"""

    def test_parsing(self):
        """Tests creating of Zabbix Cluster object"""

        test_cases = [
            {
                'input': '127.0.0.1',
                'clusters': json.dumps([["127.0.0.1", 10051]])
            },
            {
                'input': 'localhost:10151',
                'clusters': json.dumps([["localhost", 10151]])
            },
            {
                'input': 'zabbix.cluster.node1;zabbix.cluster.node2:20051;zabbix.cluster.node3:30051',
                'clusters': json.dumps([
                    ["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051], ["zabbix.cluster.node3", 30051]
                ])
            }
        ]

        for case in test_cases:
            cluster = Cluster(case['input'])

            self.assertEqual(str(cluster), case['clusters'],
                             f"unexpected output with input data: {case['input']}")


class TestItemValue(unittest.TestCase):
    """Test cases for Zabbix Item object"""

    def test_parsing(self):
        """Tests creating of Zabbix Item object"""

        test_cases = [
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0},
                'output': json.dumps({"host": "test_host", "key": "test_key", "value": "0"}),
                'exception': ValueError,
                'raised': False
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': 1695713666},
                'output':  json.dumps({"host": "test_host", "key": "test_key", "value": "0", "clock": 1695713666}),
                'exception': ValueError,
                'raised': False
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': '123abc'},
                'output':  json.dumps({"host": "test_host", "key": "test_key", "value": "0", "clock": '123abc'}),
                'exception': ValueError,
                'raised': True
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': 1695713666, 'ns': 100},
                'output': json.dumps({"host": "test_host", "key": "test_key", "value": "0", "clock": 1695713666, "ns": 100}),
                'exception': ValueError,
                'raised': False
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'ns': '123abc'},
                'output': json.dumps({"host": "test_host", "key": "test_key", "value": "0", "ns": '123abc'}),
                'exception': ValueError,
                'raised': True
            }
        ]

        for case in test_cases:
            try:
                item = ItemValue(**case['input'])
            except ValueError:
                if not case['raised']:
                    self.fail(f"raised unexpected ValueError for input data: {case['input']}")
            else:
                if case['raised']:
                    self.fail(f"not raised expected ValueError for input data: {case['input']}")

                self.assertEqual(str(item), case['output'],
                                 f"unexpected output with input data: {case['input']}")
                
                self.assertEqual(str(item), repr(item),
                                 f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()
