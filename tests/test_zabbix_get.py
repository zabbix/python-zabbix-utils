import json
import socket
import unittest

from zabbix_utils.get import ZabbixGet
from zabbix_utils.exceptions import ZabbixProcessingException


DEFAULT_VALUES = {
    'host': 'localhost',
    'port': 10050,
    'source_ip': '192.168.1.1'
}

class TestZabbixGet(unittest.TestCase):
    """Test cases for ZabbixGet object"""

    def test_init(self):
        """Tests creating of ZabbixGet object"""

        test_cases = [
            {
                'input': {'source_ip': '10.10.0.0', 'timeout': 20},
                'output': json.dumps({
                    "host": "127.0.0.1", "port": 10050, "timeout": 20, "use_ipv6": False, "source_ip": "10.10.0.0", "socket_wrapper": None
                })
            },
            {
                'input': {'host':'localhost', 'use_ipv6': True},
                'output': json.dumps({
                    "host": "localhost", "port": 10050, "timeout": 10, "use_ipv6": True, "source_ip": None, "socket_wrapper": None
                })
            },
            {
                'input': {'host':'localhost', 'port': 10150},
                'output': json.dumps({
                    "host": "localhost", "port": 10150, "timeout": 10, "use_ipv6": False, "source_ip": None, "socket_wrapper": None
                })
            }
        ]

        for case in test_cases:

            agent = ZabbixGet(**case['input'])

            self.assertEqual(json.dumps(agent.__dict__), case['output'],
                             f"unexpected output with input data: {case['input']}")
            
            with self.assertRaises(TypeError,
                                   msg="expected TypeError exception hasn't been raised"):
                agent = ZabbixGet(socket_wrapper='wrapper', **case['input'])

    def test_create_packet(self):
        """Tests __create_packet method in different cases"""

        test_cases = [
            {'input': {'data':'test'}, 'output': b'ZBXD\x01\x04\x00\x00\x00\x00\x00\x00\x00test'},
            {'input': {'data':'test_creating_packet'}, 'output': b'ZBXD\x01\x14\x00\x00\x00\x00\x00\x00\x00test_creating_packet'},
            {'input': {'data':'test_compression_flag', 'compressed_size': 5}, 'output': b'ZBXD\x02\x05\x00\x00\x00\x15\x00\x00\x00test_compression_flag'}
        ]

        for case in test_cases:

            agent = ZabbixGet()

            self.assertEqual(agent._ZabbixGet__create_packet(**case['input']), case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_get_response(self):
        """Tests __get_response method in different cases"""

        test_cases = [
            {'input': b'ZBXD\x01\x04\x00\x00\x00\x04\x00\x00\x00test', 'output': 'test'},
            {'input': b'ZBXD\x01\x14\x00\x00\x00\x00\x00\x00\x00test_creating_packet', 'output': 'test_creating_packet'},
            {'input': b'ZBXD\x02\x00\x00\x00\x00\x15\x00\x00\x00test_compression_flag', 'output': 'test_compression_flag'}
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

            agent = ZabbixGet()
            conn = ConnectTest(case['input'])        

            self.assertEqual(agent._ZabbixGet__get_response(conn), case['output'],
                             f"unexpected output with input data: {case['input']}")

        with self.assertRaises(ZabbixProcessingException,
                               msg="expected ZabbixProcessingException exception hasn't been raised"):
            agent = ZabbixGet()
            conn = ConnectTest(b'test')
            agent._ZabbixGet__get_response(conn)

        with self.assertRaises(ZabbixProcessingException,
                               msg="expected ZabbixProcessingException exception hasn't been raised"):
            agent = ZabbixGet()
            conn = ConnectTest(b'ZBXD\x04\x04\x00\x00\x00\x04\x00\x00\x00test')
            agent._ZabbixGet__get_response(conn)

        with self.assertRaises(ZabbixProcessingException,
                               msg="expected ZabbixProcessingException exception hasn't been raised"):
            agent = ZabbixGet()
            conn = ConnectTest(b'ZBXD\x05\x04\x00\x00\x00\x04\x00\x00\x00test')
            agent._ZabbixGet__get_response(conn)



if __name__ == '__main__':
    unittest.main()
