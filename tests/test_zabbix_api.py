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
import unittest
from unittest.mock import patch

from zabbix_utils.api import ZabbixAPI, APIVersion
from zabbix_utils.common import ModuleUtils
from zabbix_utils.version import __min_supported__, __max_supported__
from zabbix_utils.exceptions import APINotSupported, ProcessingError


DEFAULT_VALUES = {
    'user': 'Admin',
    'password': 'zabbix',
    'token': 'oTmtWu',
    'session': 'cc364fb50199c5e305aa91785b7e49a0',
    'max_version': "{}.0".format(__max_supported__ + .2),
    'min_version': "{}.0".format(__min_supported__ - .2)
}


def mock_send_api_request(self, method, *args, **kwargs):
    """Mock for send_api_request method

    Args:
        method (str): Zabbix API method name.

        params (dict, optional): Params for request body. Defaults to {}.

        need_auth (bool, optional): Authorization using flag. Defaults to False.
    """
    result = {}
    if method == 'apiinfo.version':
        result = f"{__max_supported__}.0"
    elif method == 'user.login':
        result = DEFAULT_VALUES['session']
    elif method == 'user.logout':
        result = True
    elif method == 'user.checkAuthentication':
        result = {'userid': 42}
    return {'jsonrpc': '2.0', 'result': result, 'id': 1}


class TestZabbixAPI(unittest.TestCase):
    """Test cases for ZabbixAPI object"""

    def test_login(self):
        """Tests login in different auth cases"""

        test_cases = [
            {
                'input': {'token': DEFAULT_VALUES['token']},
                'output': DEFAULT_VALUES['token'],
                'exception': ProcessingError,
                'raised': False
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'user': DEFAULT_VALUES['user']},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'password': DEFAULT_VALUES['password']},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'output': 'cc364fb50199c5e305aa91785b7e49a0',
                'exception': ProcessingError,
                'raised': False
            },
            {
                'input': {'user': DEFAULT_VALUES['user']},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {'password': DEFAULT_VALUES['password']},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            }
        ]

        for case in test_cases:
            with patch.multiple(
                    ZabbixAPI,
                    send_api_request=mock_send_api_request):

                try:
                    zapi = ZabbixAPI(**case['input'])
                except case['exception']:
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                else:
                    self.assertEqual(zapi._ZabbixAPI__use_token, bool(case['input'].get('token')),
                                    f"unexpected output with input data: {case['input']}")
                self.assertEqual(zapi._ZabbixAPI__session_id, case['output'],
                                 f"unexpected output with input data: {case['input']}")

                with ZabbixAPI() as zapi:
                    try:
                        zapi.login(**case['input'])
                    except case['exception']:
                        if not case['raised']:
                            self.fail(f"raised unexpected Exception with input data: {case['input']}")
                    else:
                        if case['raised']:
                            self.fail(f"not raised expected Exception with input data: {case['input']}")

                        self.assertEqual(zapi._ZabbixAPI__session_id, case['output'],
                                        f"unexpected output with input data: {case['input']}")
                        self.assertEqual(zapi._ZabbixAPI__use_token, bool(case['input'].get('token')),
                                        f"unexpected output with input data: {case['input']}")

    def test_logout(self):
        """Tests logout in different auth cases"""

        test_cases = [
            {
                'input': {'token': DEFAULT_VALUES['token']},
                'output': None,
                'exception': ProcessingError,
                'raised': False
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'output': None,
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'output': None,
                'exception': ProcessingError,
                'raised': False
            }
        ]

        for case in test_cases:
            with patch.multiple(
                ZabbixAPI,
                send_api_request=mock_send_api_request):

                try:
                    zapi = ZabbixAPI(**case['input'])
                except case['exception']:
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                zapi.logout()
                self.assertEqual(zapi._ZabbixAPI__session_id, case['output'],
                                 f"unexpected output with input data: {case['input']}")

    def test_check_auth(self):
        """Tests check_auth method in different auth cases"""

        test_cases = [
            {
                'input': {'token': DEFAULT_VALUES['token']},
                'output': {'login': True, 'logout': False},
                'exception': ProcessingError,
                'raised': False
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'output': {'login': False, 'logout': False},
                'exception': ProcessingError,
                'raised': True
            },
            {
                'input': {'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'output': {'login': True, 'logout': False},
                'exception': ProcessingError,
                'raised': False
            }
        ]

        for case in test_cases:
            with patch.multiple(
                ZabbixAPI,
                send_api_request=mock_send_api_request):

                try:
                    zapi = ZabbixAPI(**case['input'])
                except case['exception']:
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                auth = zapi.check_auth()
                self.assertEqual(auth, case['output']['login'],
                                 f"unexpected output with input data: {case['input']}")
                zapi.logout()
                auth = zapi.check_auth()
                self.assertEqual(auth, case['output']['logout'],
                                 f"unexpected output with input data: {case['input']}")

    def test_check_version(self):
        """Tests __check_version method with different versions"""

        with patch.multiple(
                ZabbixAPI,
                api_version=lambda s: APIVersion(DEFAULT_VALUES['max_version'])):

            with self.assertRaises(APINotSupported,
                                   msg=f"version={DEFAULT_VALUES['max_version']}"):
                ZabbixAPI()

            try: 
                ZabbixAPI(skip_version_check=True)
            except Exception:
                self.fail(f"raised unexpected Exception for version: {DEFAULT_VALUES['max_version']}")

        with patch.multiple(
                ZabbixAPI,
                api_version=lambda s: APIVersion(DEFAULT_VALUES['min_version'])):

            with self.assertRaises(APINotSupported,
                                   msg=f"version={DEFAULT_VALUES['min_version']}"):
                ZabbixAPI()

            try: 
                ZabbixAPI(skip_version_check=True)
            except Exception:
                self.fail(f"raised unexpected Exception for version: {DEFAULT_VALUES['min_version']}")

    def test_version_conditions(self):
        """Tests behavior of ZabbixAPI object depending on different versions"""

        test_cases = [
            {
                'input': {'token': DEFAULT_VALUES['token']},
                'version': '5.2.0',
                'raised': {'APINotSupported': True, 'ProcessingError': True},
                'output': DEFAULT_VALUES['session']
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'version': '5.2.0',
                'raised': {'APINotSupported': True, 'ProcessingError': True},
                'output': DEFAULT_VALUES['session']
            },
            {
                'input': {'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'version': '5.2.0',
                'raised': {'APINotSupported': False, 'ProcessingError': False},
                'output': DEFAULT_VALUES['session']
            },
            {
                'input': {'token': DEFAULT_VALUES['token']},
                'version': '5.4.0',
                'raised': {'APINotSupported': False, 'ProcessingError': False},
                'output': DEFAULT_VALUES['token']
            },
            {
                'input': {'token': DEFAULT_VALUES['token'], 'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'version': '5.4.0',
                'raised': {'APINotSupported': False, 'ProcessingError': True},
                'output': DEFAULT_VALUES['token']
            },
            {
                'input': {'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                'version': '5.4.0',
                'raised': {'APINotSupported': False, 'ProcessingError': False},
                'output': DEFAULT_VALUES['session']
            }
        ]

        for case in test_cases:
            with patch.multiple(
                    ZabbixAPI,
                    send_api_request=mock_send_api_request,
                    api_version=lambda s: APIVersion(case['version'])):

                try:
                    zapi = ZabbixAPI(**case['input'])
                except ProcessingError:
                    if not case['raised']['ProcessingError']:
                        self.fail(f"raised unexpected Exception for version: {case['input']}")
                except APINotSupported:
                    if not case['raised']['APINotSupported']:
                        self.fail(f"raised unexpected Exception for version: {case['input']}")
                else:
                    if case['raised']['ProcessingError'] or case['raised']['APINotSupported']:
                        self.fail(f"not raised expected Exception for version: {case['version']}")

                    self.assertEqual(zapi._ZabbixAPI__session_id, case['output'],
                                         f"unexpected output with input data: {case['input']}")


class TestAPIVersion(unittest.TestCase):
    """Test cases for APIVersion object"""

    def test_init(self):
        """Tests creating of APIVersion object"""

        test_cases = [
            {'input': '7.0.0alpha', 'output': '7.0.0alpha', 'exception': TypeError, 'raised': True},
            {'input': '6.0.0', 'output': '6.0.0', 'exception': TypeError, 'raised': False},
            {'input': '6.0', 'output': None, 'exception': TypeError, 'raised': True},
            {'input': '7', 'output': None, 'exception': TypeError, 'raised': True}
        ]

        for case in test_cases:
            try:
                ver = APIVersion(case['input'])
            except ValueError:
                if not case['raised']:
                    self.fail(f"raised unexpected Exception with input data: {case['input']}")
            else:
                if case['raised']:
                    self.fail(f"not raised expected Exception with input data: {case['input']}")
                self.assertEqual(str(ver), case['output'],
                                 f"unexpected output with input data: {case['input']}")

    def test_major(self):
        """Tests getting the major version part of APIVersion"""

        test_cases = [
            {'input': '6.0.10', 'output': 6.0},
            {'input': '6.2.0', 'output': 6.2}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'])
            self.assertEqual(ver.major, case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_minor(self):
        """Tests getting the minor version part of APIVersion"""

        test_cases = [
            {'input': '6.0.10', 'output': 10},
            {'input': '6.2.0', 'output': 0}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'])
            self.assertEqual(ver.minor, case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_is_lts(self):
        """Tests is_lts method for different versions"""

        test_cases = [
            {'input': '6.0.10', 'output': True},
            {'input': '6.2.0', 'output': False},
            {'input': '6.4.5', 'output': False},
            {'input': '7.0.0', 'output': True},
            {'input': '7.0.30', 'output': True}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'])
            self.assertEqual(ver.is_lts(), case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_compare(self):
        """Tests version comparison for different version formats"""

        test_cases = [
            {'input': ['6.0.0','6.0.0'], 'operation': 'eq', 'output': True},
            {'input': ['6.0.0',6.0], 'operation': 'ne', 'output': False},
            {'input': ['6.0.0',6.0], 'operation': 'ge', 'output': True},
            {'input': ['6.0.0',7.0], 'operation': 'lt', 'output': True},
            {'input': ['6.4.1',6.4], 'operation': 'gt', 'output': False}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'][0])
            result = (getattr(ver, f"__{case['operation']}__")(case['input'][1]))
            self.assertEqual(result, case['output'],
                             f"unexpected output with input data: {case['input']}")

        ver = APIVersion('6.0.0')
        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver > {}

        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver < []

        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver < 6

        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver != 7

        with self.assertRaises(ValueError,
                               msg=f"input data={case['input']}"):
            ver <= '7.0'


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
                'input': {"auth": "q2BTIw85kqmjtXl3","token": "jZAC51wHuWdwvQnx"},
                'output': {"auth": mask, "token": mask}
            },
            {
                'input': {"token": "jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"},
                'output': {"token": f"jZAC{mask}R2uW"}
            },
            {
                'input': {"auth": "q2BTIw85kqmjtXl3zCgSSR26gwCGVFMK"},
                'output': {"auth": f"q2BT{mask}VFMK"}
            },
            {
                'input': {"sessionid": "p1xqXSf2HhYWa2ml6R5R2uWwbP2T55vh"},
                'output': {"sessionid": f"p1xq{mask}55vh"}
            },
            {
                'input': {"password": "HlphkcKgQKvofQHP"},
                'output': {"password": mask}
            },
            {
                'input': {"result": "p1xqXSf2HhYWa2ml6R5R2uWwbP2T55vh"},
                'output': {"result": f"p1xq{mask}55vh"}
            },
            {
                'input': {"result": "6.0.0"},
                'output': {"result": "6.0.0"}
            },
            {
                'input': {"result": ["10"]},
                'output': {"result": ["10"]}
            },
            {
                'input': {"result": [{"token": "jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"}]},
                'output': {"result": [{"token": f"jZAC{mask}R2uW"}]}
            },
            {
                'input': {"result": [["10"],["15"]]},
                'output': {"result": [["10"],["15"]]}
            },
            {
                'input': {"result": [[{"token": "jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"}]]},
                'output': {"result": [[{"token": f"jZAC{mask}R2uW"}]]}
            },
            {
                'input': {"result": ["jZAC51wHuWdwvQnxwbP2T55vh6R5R2uW"]},
                'output': {"result": [f"jZAC{mask}R2uW"]}
            }
        ]

        for case in test_cases:
            result = ModuleUtils.hide_private(case['input'])
            self.assertEqual(result, case['output'],
                             f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()
