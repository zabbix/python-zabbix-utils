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

from tests import common
from zabbix_utils import Getter
from zabbix_utils import ProcessingError


DEFAULT_VALUES = common.GETTER_DEFAULTS


class TestGetter(unittest.TestCase):
    """Test cases for Getter object"""

    def test_init(self):
        """Tests creating of Getter object"""

        test_cases = [
            {
                'input': {'source_ip': DEFAULT_VALUES['source_ip'], 'timeout': 20},
                'output': json.dumps({
                    "host": "127.0.0.1", "port": DEFAULT_VALUES['port'], "timeout": 20, "use_ipv6": False, "source_ip": DEFAULT_VALUES['source_ip'], "socket_wrapper": None
                })
            },
            {
                'input': {'host':DEFAULT_VALUES['host']},
                'output': json.dumps({
                    "host": DEFAULT_VALUES['host'], "port": DEFAULT_VALUES['port'], "timeout": 10, "use_ipv6": False, "source_ip": None, "socket_wrapper": None
                })
            },
            {
                'input': {'host':DEFAULT_VALUES['host'], 'port': 10150},
                'output': json.dumps({
                    "host": DEFAULT_VALUES['host'], "port": 10150, "timeout": 10, "use_ipv6": False, "source_ip": None, "socket_wrapper": None
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

        for case in test_cases:

            getter = Getter()
            conn = common.MockConnector(case['input'])        

            self.assertEqual(getter._Getter__get_response(conn), case['output'],
                             f"unexpected output with input data: {case['input']}")

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            getter = Getter()
            conn = common.MockConnector(b'test')
            getter._Getter__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            getter = Getter()
            conn = common.MockConnector(b'ZBXD\x04\x04\x00\x00\x00\x00\x00\x00\x00test')
            getter._Getter__get_response(conn)

        with self.assertRaises(ProcessingError,
                               msg="expected ProcessingError exception hasn't been raised"):
            getter = Getter()
            conn = common.MockConnector(b'ZBXD\x00\x04\x00\x00\x00\x00\x00\x00\x00test')
            getter._Getter__get_response(conn)

    def test_get(self):
        """Tests get() method in different cases"""

        output = 'test_response'
        response = b'ZBXD\x01\r\x00\x00\x00\x00\x00\x00\x00' + output.encode('utf-8')

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
                'input': {'source_ip': '127.0.0.1'},
                'output': output,
                'raised': False
            },
            {
                'connection': {'input_stream': response},
                'input': {'socket_wrapper': common.socket_wrapper},
                'output': output,
                'raised': False
            },
            {
                'connection': {'input_stream': response, 'exception': socket.error},
                'input': {},
                'output': output,
                'raised': True
            },
            {
                'connection': {'input_stream': response, 'exception': socket.gaierror},
                'input': {},
                'output': output,
                'raised': True
            },
            {
                'connection': {'input_stream': response, 'exception': socket.timeout},
                'input': {},
                'output': output,
                'raised': True
            }
        ]

        for case in test_cases:
            with unittest.mock.patch('socket.socket') as mock_socket:
                test_connector = common.MockConnector(**case['connection'])
                mock_socket.return_value.recv = test_connector.recv
                mock_socket.return_value.sendall = test_connector.sendall
                getter = Getter(**case['input'])
                
                try:
                    resp = getter.get('system.uname')
                except case['connection'].get('exception', Exception):
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                else:
                    self.assertEqual(resp.value, case['output'],
                                    f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()
