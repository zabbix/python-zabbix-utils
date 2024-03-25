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

import unittest

from zabbix_utils.common import ModuleUtils, ZabbixProtocol


class TestModuleUtils(unittest.TestCase):
    """Test cases for ModuleUtils class"""

    def test_check_url(self):
        """Tests check_url method in different cases"""

        filename = ModuleUtils.JSONRPC_FILE

        test_cases = [
            {'input': '127.0.0.1', 'output': f"http://127.0.0.1/{filename}"},
            {'input': 'https://localhost', 'output': f"https://localhost/{filename}"},
            {'input': 'localhost/zabbix', 'output': f"http://localhost/zabbix/{filename}"},
            {'input': 'localhost/', 'output': f"http://localhost/{filename}"},
            {'input': f"127.0.0.1/{filename}", 'output': f"http://127.0.0.1/{filename}"}
        ]

        for case in test_cases:
            result = ModuleUtils.check_url(case['input'])
            self.assertEqual(result, case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_mask_secret(self):
        """Tests mask_secret method in different cases"""

        mask = ModuleUtils.HIDING_MASK

        test_cases = [
            {'input': {'string': 'lZSwaQ', 'show_len': 5}, 'output': mask},
            {'input': {'string': 'ZWvaGS5SzNGaR990f', 'show_len': 4}, 'output': f"ZWva{mask}990f"},
            {'input': {'string': 'KZneJzgRzdlWcUjJj', 'show_len': 10}, 'output': mask},
            {'input': {'string': 'g5imzEr7TPcBG47fa', 'show_len': 20}, 'output': mask},
            {'input': {'string': 'In8y4eGughjBNSqEGPcqzejToVUT3OA4q5', 'show_len':2}, 'output': f"In{mask}q5"},
            {'input': {'string': 'Z8pZom5EVbRZ0W5wz', 'show_len':0}, 'output': mask}
        ]

        for case in test_cases:
            result = ModuleUtils.mask_secret(**case['input'])
            self.assertEqual(result, case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_hide_private(self):
        """Tests hide_private method in different cases"""

        mask = ModuleUtils.HIDING_MASK

        test_cases = [
            {
                'input': [{"auth": "q2BTIw85kqmjtXl3","token": "jZAC51wHuWdwvQnx"}],
                'output': {"auth": mask, "token": mask}
            },
            {
                'input': [{"token": "jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"}],
                'output': {"token": f"jZAC{mask}R2uW"}
            },
            {
                'input': [{"auth": "q2BTIw85kqmjtXl3zCgSSR26gwCGVFMK"}],
                'output': {"auth": f"q2BT{mask}VFMK"}
            },
            {
                'input': [{"sessionid": "p1xqXSf2HhYWa2ml6R5R2uWwbP2T55vh"}],
                'output': {"sessionid": f"p1xq{mask}55vh"}
            },
            {
                'input': [{"password": "HlphkcKgQKvofQHP"}],
                'output': {"password": mask}
            },
            {
                'input': [{"result": "p1xqXSf2HhYWa2ml6R5R2uWwbP2T55vh"}],
                'output': {"result": f"p1xq{mask}55vh"}
            },
            {
                'input': [{"result": "6.0.0"}],
                'output': {"result": "6.0.0"}
            },
            {
                'input': [{"result": ["10"]}],
                'output': {"result": ["10"]}
            },
            {
                'input': [{"result": [{"token": "jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"}]}],
                'output': {"result": [{"token": f"jZAC{mask}R2uW"}]}
            },
            {
                'input': [{"result": [["10"],["15"]]}],
                'output': {"result": [["10"],["15"]]}
            },
            {
                'input': [{"result": [[{"token": "jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"}]]}],
                'output': {"result": [[{"token": f"jZAC{mask}R2uW"}]]}
            },
            {
                'input': [{"result": ["jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"]}],
                'output': {"result": [f"jZAC{mask}R2uW"]}
            },
            {
                'input': [{"result": {"passwords": ["HlphkcKgQKvofQHP"]}}],
                'output': {"result": {"passwords": [mask]}}
            },
            {
                'input': [{"result": {"passwords": ["HlphkcKgQKvofQHP"]}}, {}],
                'output': {"result": {"passwords": ["HlphkcKgQKvofQHP"]}}
            },
            {
                'input': [{"result": {"tokens": ["jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"]}}],
                'output': {"result": {"tokens": [f"jZAC{mask}R2uW"]}}
            },
            {
                'input': [{"result": ["jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"]}, {}],
                'output': {"result": [f"jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"]}
            }
        ]

        for case in test_cases:
            result = ModuleUtils.hide_private(*case['input'])
            self.assertEqual(result, case['output'],
                             f"unexpected output with input data: {case['input']}")


class TestZabbixProtocol(unittest.TestCase):
    """Test cases for ZabbixProtocol object"""

    def test_create_packet(self):
        """Tests create_packet method in different cases"""

        class Logger():
            def debug(self, *args, **kwargs):
                pass

        test_cases = [
            {
                'input': {'payload':'test', 'log':Logger()},
                'output': b'ZBXD\x01\x04\x00\x00\x00\x00\x00\x00\x00test'
            },
            {
                'input': {'payload':'test_creating_packet', 'log':Logger()},
                'output': b'ZBXD\x01\x14\x00\x00\x00\x00\x00\x00\x00test_creating_packet'
            },
            {
                'input': {'payload':'test_compression_flag', 'log':Logger()},
                'output': b'ZBXD\x01\x15\x00\x00\x00\x00\x00\x00\x00test_compression_flag'
            },
            {
                'input': {'payload':'glāžšķūņu rūķīši', 'log':Logger()},
                'output': b'ZBXD\x01\x1a\x00\x00\x00\x00\x00\x00\x00gl\xc4\x81\xc5\xbe\xc5\xa1\xc4\xb7\xc5\xab\xc5\x86u r\xc5\xab\xc4\xb7\xc4\xab\xc5\xa1i'
            }
        ]

        for case in test_cases:
            resp = ZabbixProtocol.create_packet(**case['input'])
            self.assertEqual(resp, case['output'],
                             f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()