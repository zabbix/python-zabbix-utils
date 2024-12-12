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
import urllib.request as ul
from unittest.mock import patch

from tests import common
from zabbix_utils.api import ZabbixAPI
from zabbix_utils.types import APIVersion
from zabbix_utils.exceptions import APINotSupported, ProcessingError


DEFAULT_VALUES = common.API_DEFAULTS


class TestZabbixAPI(unittest.TestCase):
    """Test cases for ZabbixAPI object"""
    
    def test_init(self):
        """Tests creating of AsyncZabbixAPI object"""
        
        test_resp = common.MockAPIResponse()
        
        def mock_urlopen(*args, **kwargs):
            return test_resp
        
        with unittest.mock.patch.multiple(
            ul,
            urlopen=mock_urlopen):
            
            with self.assertRaises(APINotSupported,
                                   msg="expected APINotSupported exception hasn't been raised"):
                ZabbixAPI(
                    http_user=DEFAULT_VALUES['user'],
                    http_password=DEFAULT_VALUES['password']
                )
            zapi = ZabbixAPI()
            with self.assertRaises(ProcessingError,
                                   msg="expected ProcessingError exception hasn't been raised"):
                zapi.hosts.get()

            zapi.login(
                user=DEFAULT_VALUES['user'],
                password=DEFAULT_VALUES['password']
            )
            zapi.hosts.get()
            
            test_resp.set_exception(ValueError)
            
            with self.assertRaises(ProcessingError,
                                   msg="expected ProcessingError exception hasn't been raised"):
                ZabbixAPI()
            test_resp.del_exception()

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
                'output': DEFAULT_VALUES['session'],
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
                    send_api_request=common.mock_send_sync_request):

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

                        self.assertEqual(zapi._ZabbixAPI__use_token, bool(case['input'].get('token')),
                                        f"unexpected output with input data: {case['input']}")
                        self.assertEqual(zapi._ZabbixAPI__session_id, case['output'],
                                        f"unexpected output with input data: {case['input']}")

            with patch.multiple(
                    ZabbixAPI,
                    send_api_request=common.mock_send_sync_request):
                
                with self.assertRaises(APINotSupported, msg="expected APINotSupported exception hasn't been raised"):
                    ZabbixAPI(http_user=DEFAULT_VALUES['user'], http_password=DEFAULT_VALUES['password'])
                zapi = ZabbixAPI()
                
                with self.assertRaises(TypeError, msg="expected TypeError exception hasn't been raised"):
                    zapi = ZabbixAPI()
                    zapi.user.login(DEFAULT_VALUES['user'], password=DEFAULT_VALUES['password'])

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
                send_api_request=common.mock_send_sync_request):

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
                send_api_request=common.mock_send_sync_request):

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
                    send_api_request=common.mock_send_sync_request,
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


if __name__ == '__main__':
    unittest.main()
