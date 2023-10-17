import json
import unittest
import configparser
from unittest.mock import patch

from zabbix_utils.sender import ZabbixSender, ZabbixCluster, ZabbixItem


DEFAULT_VALUES = {
    'server': 'localhost',
    'port': 10051,
    'source_ip': '192.168.1.1'
}

ZABBIX_CONFIG = f"""[root]
ServerActive=zabbix.cluster.node1;zabbix.cluster.node2:20051,zabbix.cluster2.node1;zabbix.cluster2.node2,zabbix.domain
Server={DEFAULT_VALUES['server']}
SourceIP={DEFAULT_VALUES['source_ip']}
TLSConnect=unencrypted
TLSAccept=unencrypted
"""

class TestZabbixSender(unittest.TestCase):
    """Test cases for ZabbixSender object"""

    def test_init(self):
        """Tests creating of ZabbixSender object"""

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
                'input': {'server':'localhost', 'port': 10151, 'use_config': True},
                'clusters': json.dumps([
                    [["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051]],
                    [["zabbix.cluster2.node1", 10051], ["zabbix.cluster2.node2", 10051]],
                    [["zabbix.domain", 10051]]
                ]),
                'source_ip': DEFAULT_VALUES['source_ip']
            },
            {
                'input': {'use_config': True},
                'clusters': json.dumps([
                    [["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051]],
                    [["zabbix.cluster2.node1", 10051], ["zabbix.cluster2.node2", 10051]],
                    [["zabbix.domain", 10051]]
                ]),
                'source_ip': DEFAULT_VALUES['source_ip']
            }
        ]

        def mock_load_config(self, filepath):
            config = configparser.ConfigParser(strict=False)
            config.read_string(ZABBIX_CONFIG)
            self._ZabbixSender__read_config(config)

        for case in test_cases:
            with patch.multiple(
                    ZabbixSender,
                    _ZabbixSender__load_config=mock_load_config):

                sender = ZabbixSender(**case['input'])

                self.assertEqual(str(sender.clusters), case['clusters'],
                                 f"unexpected output with input data: {case['input']}")
                self.assertEqual(sender.source_ip, case['source_ip'],
                                 f"unexpected output with input data: {case['input']}")

    def test_send(self):
        """Tests send method in different cases"""

        test_cases = [
            {
                'input': {}, 'total': 5, 'failed': 2,
                'output': json.dumps([
                    {"processed": 3, "failed": 2, "total": 5, "time": "0.000100", "chunk": 1}
                ])
            },
            {
                'input': {'chunk_size': 10}, 'total': 25, 'failed': 4,
                'output': json.dumps([
                    {"processed": 6, "failed": 4, "total": 10, "time": "0.000100", "chunk": 1},
                    {"processed": 10, "failed": 0, "total": 10, "time": "0.000100", "chunk": 2},
                    {"processed": 5, "failed": 0, "total": 5, "time": "0.000100", "chunk": 3}
                ])
            }
        ]

        def mock_chunk_send(self, items):
            info = {
                'processed': len([i for i in items if i]),
                'failed': len([i for i in items if not i]),
                'total': len(items),
                'seconds spent': '0.000100'
            }
            result = {
                'response': 'success',
                'info': '; '.join([f"{k}: {v}" for k,v in info.items()])
            }

            return result

        for case in test_cases:
            with patch.multiple(
                    ZabbixSender,
                    _ZabbixSender__chunk_send=mock_chunk_send):

                items = []
                sender = ZabbixSender(**case['input'])
                failed_counter = case['failed']
                for _ in range(case['total']):
                    if failed_counter > 0:
                        items.append(False)
                        failed_counter -= 1
                    else:
                        items.append(True)
                resp = sender.send(items)

                self.assertEqual(str(resp), case['output'],
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
            result = {
                'response': 'success',
                'info': '; '.join([f"{k}: {v}" for k,v in info.items()])
            }

            return result

        for case in test_cases:
            with patch.multiple(
                    ZabbixSender,
                    _ZabbixSender__chunk_send=mock_chunk_send):

                sender = ZabbixSender()
                resp = sender.send_value(**case['input'])

                self.assertEqual(str(resp), case['output'],
                                 f"unexpected output with input data: {case['input']}")


class TestZabbixCluster(unittest.TestCase):
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
            cluster = ZabbixCluster(case['input'])

            self.assertEqual(str(cluster), case['clusters'],
                             f"unexpected output with input data: {case['input']}")


class TestZabbixItem(unittest.TestCase):
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
                item = ZabbixItem(**case['input'])
            except ValueError:
                if not case['raised']:
                    self.fail(f"raised unexpected ValueError for input data: {case['input']}")
            else:
                if case['raised']:
                    self.fail(f"not raised expected ValueError for input data: {case['input']}")

                self.assertEqual(str(item), case['output'],
                                 f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()
