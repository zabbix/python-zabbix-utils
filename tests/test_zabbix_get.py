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
import unittest

from zabbix_utils import Getter
from zabbix_utils import ProcessingError


DEFAULT_VALUES = {
    'host': 'localhost',
    'port': 10050,
    'source_ip': '192.168.1.1'
}

class TestGetter(unittest.TestCase):
    """Test cases for Getter object"""

    def test_init(self):
        """Tests creating of Getter object"""

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

            agent = Getter(**case['input'])

            self.assertEqual(json.dumps(agent.__dict__), case['output'],
                             f"unexpected output with input data: {case['input']}")
            
            with self.assertRaises(TypeError,
                                   msg="expected TypeError exception hasn't been raised"):
                agent = Getter(socket_wrapper='wrapper', **case['input'])

    def test_create_packet(self):
        """Tests __create_packet method in different cases"""

        test_cases = [
            {'input': {'data':'test'}, 'output': b'ZBXD\x01\x04\x00\x00\x00\x00\x00\x00\x00test'},
            {'input': {'data':'test_creating_packet'}, 'output': b'ZBXD\x01\x14\x00\x00\x00\x00\x00\x00\x00test_creating_packet'},
            {'input': {'data':'test_compression_flag'}, 'output': b'ZBXD\x01\x15\x00\x00\x00\x00\x00\x00\x00test_compression_flag'},
            {'input': {'data':'glāžšķūņu rūķīši'}, 'output': b'ZBXD\x01\x1a\x00\x00\x00\x00\x00\x00\x00gl\xc4\x81\xc5\xbe\xc5\xa1\xc4\xb7\xc5\xab\xc5\x86u r\xc5\xab\xc4\xb7\xc4\xab\xc5\xa1i'}
        ]

        for case in test_cases:

            getter = Getter()

            self.assertEqual(getter._Getter__create_packet(**case['input']), case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_get_response(self):
        """Tests __get_response method in different cases"""

        test_cases = [
            {'input': b'ZBXD\x01\x04\x00\x00\x00\x04\x00\x00\x00test', 'output': 'test'},
            {
                'input': b'ZBXD\x01\x14\x00\x00\x00\x00\x00\x00\x00test_creating_packet',
                'output': 'test_creating_packet'
            },
            {
                'input': b'ZBXD\x03\x1d\x00\x00\x00\x15\x00\x00\x00x\x9c+I-.\x89O\xce\xcf-(J-.\xce\xcc\xcf\x8bO\xcbIL\x07\x00a\xd1\x08\xcb',
                'output': 'test_compression_flag'
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

            getter = Getter()
            conn = ConnectTest(case['input'])        

            self.assertEqual(getter._Getter__get_response(conn), case['output'],
                             f"unexpected output with input data: {case['input']}")

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            getter = Getter()
            conn = ConnectTest(b'test')
            getter._Getter__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            getter = Getter()
            conn = ConnectTest(b'ZBXD\x04\x04\x00\x00\x00\x00\x00\x00\x00test')
            getter._Getter__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            getter = Getter()
            conn = ConnectTest(b'ZBXD\x00\x04\x00\x00\x00\x00\x00\x00\x00test')
            getter._Getter__get_response(conn)



if __name__ == '__main__':
    unittest.main()
