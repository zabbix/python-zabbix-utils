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

import aiohttp
import unittest
import urllib.request as ul
from unittest.mock import patch
from urllib.error import URLError 

from tests import common
from zabbix_utils.aioapi import AsyncZabbixAPI
from zabbix_utils.types import APIVersion
from zabbix_utils.exceptions import APIRequestError, APINotSupported, ProcessingError


DEFAULT_VALUES = common.API_DEFAULTS


class TestAsyncZabbixAPI(unittest.IsolatedAsyncioTestCase):
    """Test cases for AsyncZabbixAPI object"""
    
    def setUp(self):
        with patch.multiple(
            AsyncZabbixAPI,
            send_sync_request=common.mock_send_sync_request):
            self.zapi = AsyncZabbixAPI(client_session=common.MockSession())

    async def test_init(self):
        """Tests creating of AsyncZabbixAPI object"""

        test_resp = common.MockAPIResponse()

        def mock_ClientSession(*args, **kwargs):
            return common.MockSession()

        def mock_TCPConnector(*args, **kwargs):
            return ''

        def mock_BasicAuth(*args, **kwargs):
            return ''

        def mock_urlopen(*args, **kwargs):
            return test_resp

        with self.assertRaises(AttributeError,
                               msg="expected AttributeError exception hasn't been raised"):
            zapi = AsyncZabbixAPI(
                http_user=DEFAULT_VALUES['user'],
                http_password=DEFAULT_VALUES['password'],
                client_session=common.MockSession()
            )

        with unittest.mock.patch.multiple(
            aiohttp,
            ClientSession=mock_ClientSession,
            TCPConnector=mock_TCPConnector,
            BasicAuth=mock_BasicAuth):

            with unittest.mock.patch.multiple(
                ul,
                urlopen=mock_urlopen):
                zapi = AsyncZabbixAPI()
                await zapi.login(
                    user=DEFAULT_VALUES['user'],
                    password=DEFAULT_VALUES['password']
                )
                
                test_resp.set_exception(ValueError)
            
                with self.assertRaises(ProcessingError,
                                       msg="expected ProcessingError exception hasn't been raised"):
                    AsyncZabbixAPI()
                test_resp.del_exception()

    async def test_login(self):
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
                    AsyncZabbixAPI,
                    send_sync_request=common.mock_send_sync_request,
                    send_async_request=common.mock_send_async_request):

                try:
                    await self.zapi.login(**case['input'])
                except case['exception']:
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                else:
                    self.assertEqual(self.zapi._AsyncZabbixAPI__use_token, bool(case['input'].get('token')),
                                     f"unexpected output with input data: {case['input']}")
                    self.assertEqual(self.zapi._AsyncZabbixAPI__session_id, case['output'],
                                     f"unexpected output with input data: {case['input']}")
                    await self.zapi.logout()
                    
                async with AsyncZabbixAPI(client_session=common.MockSession()) as zapi:
                    try:
                        await zapi.login(**case['input'])
                    except case['exception']:
                        if not case['raised']:
                            self.fail(f"raised unexpected Exception with input data: {case['input']}")
                    else:
                        if case['raised']:
                            self.fail(f"not raised expected Exception with input data: {case['input']}")

                        self.assertEqual(zapi._AsyncZabbixAPI__use_token, bool(case['input'].get('token')),
                                        f"unexpected output with input data: {case['input']}")
                        self.assertEqual(zapi._AsyncZabbixAPI__session_id, case['output'],
                                        f"unexpected output with input data: {case['input']}")

    async def test_logout(self):
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
                    AsyncZabbixAPI,
                    send_async_request=common.mock_send_async_request):

                try:
                    await self.zapi.login(**case['input'])
                except case['exception']:
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                await self.zapi.logout()
                self.assertEqual(self.zapi._AsyncZabbixAPI__session_id, case['output'],
                                 f"unexpected output with input data: {case['input']}")

    async def test_check_auth(self):
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
                    AsyncZabbixAPI,
                    send_async_request=common.mock_send_async_request):

                try:
                    await self.zapi.login(**case['input'])
                except case['exception']:
                    if not case['raised']:
                        self.fail(f"raised unexpected Exception with input data: {case['input']}")
                auth = await self.zapi.check_auth()
                self.assertEqual(auth, case['output']['login'],
                                 f"unexpected output with input data: {case['input']}")
                await self.zapi.logout()
                auth = await self.zapi.check_auth()
                self.assertEqual(auth, case['output']['logout'],
                                 f"unexpected output with input data: {case['input']}")

    async def test__prepare_request(self):
        """Tests __prepare_request method in different cases"""
        
        with patch.multiple(
            AsyncZabbixAPI,
            send_async_request=common.mock_send_async_request):
            await self.zapi.login(token=DEFAULT_VALUES['token'])
            req, headers = self.zapi._AsyncZabbixAPI__prepare_request(
                method='user.login',
                params={'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                need_auth=False
            )
            self.assertEqual(headers.get('Authorization'), None,
                             "unexpected Authorization header, must be: None")
            self.assertEqual(req.get('auth'), None,
                             "unexpected auth request parameter, must be: None")
            req, headers = self.zapi._AsyncZabbixAPI__prepare_request(
                method='user.logout',
                params={'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                need_auth=True
            )
            self.assertEqual(headers.get('Authorization'), 'Bearer ' + DEFAULT_VALUES['token'],
                             "unexpected Authorization header, must be: Bearer " + DEFAULT_VALUES['token'])
            self.zapi.client_session.set_auth()
            req, headers = self.zapi._AsyncZabbixAPI__prepare_request(
                method='user.logout',
                params={'user': DEFAULT_VALUES['user'], 'password': DEFAULT_VALUES['password']},
                need_auth=True
            )
            self.assertEqual(req.get('auth'), DEFAULT_VALUES['token'],
                             "unexpected auth request parameter, must be: " + DEFAULT_VALUES['token'])
            self.zapi.client_session.del_auth()
            await self.zapi.logout()
            
            with self.assertRaises(ProcessingError,
                                   msg="expected ProcessingError exception hasn't been raised"):
                req, headers = self.zapi._AsyncZabbixAPI__prepare_request(
                    method='user.logout',
                    params={},
                    need_auth=True
                )

    def test__check_response(self):
        """Tests __check_response method in different cases"""

        test_cases = [
            {
                'input': {'method': 'user.login', 'response': {'result': DEFAULT_VALUES['session']}},
                'output': {'result': DEFAULT_VALUES['session']},
                'exception': APIRequestError,
                'raised': False
            },
            {
                'input': {'method': 'configuration.export', 'response': {'result': '...'}},
                'output': {'result': '...'},
                'exception': APIRequestError,
                'raised': False
            },
            {
                'input': {'method': 'user.login', 'response': {'error': {'message':'Test API error', 'data':'...'}}},
                'output': None,
                'exception': APIRequestError,
                'raised': True
            }
        ]
        
        for case in test_cases:
            response = None
            try:
                response = self.zapi._AsyncZabbixAPI__check_response(**case['input'])
            except case['exception']:
                if not case['raised']:
                    self.fail(f"raised unexpected Exception with input data: {case['input']}")
            else:
                self.assertEqual(response, case['output'],
                                f"unexpected output with input data: {case['input']}")
        

    def test_check_version(self):
        """Tests __check_version method with different versions"""

        with patch.multiple(
                AsyncZabbixAPI,
                api_version=lambda s: APIVersion(DEFAULT_VALUES['max_version'])):

            with self.assertRaises(APINotSupported,
                                   msg=f"version={DEFAULT_VALUES['max_version']}"):
                AsyncZabbixAPI(client_session=common.MockSession())

            try: 
                AsyncZabbixAPI(client_session=common.MockSession(), skip_version_check=True)
            except Exception:
                self.fail(f"raised unexpected Exception for version: {DEFAULT_VALUES['max_version']}")

        with patch.multiple(
                AsyncZabbixAPI,
                api_version=lambda s: APIVersion(DEFAULT_VALUES['min_version'])):

            with self.assertRaises(APINotSupported,
                                   msg=f"version={DEFAULT_VALUES['min_version']}"):
                AsyncZabbixAPI(client_session=common.MockSession())

            try: 
                AsyncZabbixAPI(client_session=common.MockSession(), skip_version_check=True)
            except Exception:
                self.fail(f"raised unexpected Exception for version: {DEFAULT_VALUES['min_version']}")

    async def test_version_conditions(self):
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
                    AsyncZabbixAPI,
                    send_async_request=common.mock_send_async_request,
                    api_version=lambda s: APIVersion(case['version'])):

                try:
                    await self.zapi.login(**case['input'])
                except ProcessingError:
                    if not case['raised']['ProcessingError']:
                        self.fail(f"raised unexpected Exception for version: {case['input']}")
                except APINotSupported:
                    if not case['raised']['APINotSupported']:
                        self.fail(f"raised unexpected Exception for version: {case['input']}")
                else:
                    if case['raised']['ProcessingError'] or case['raised']['APINotSupported']:
                        self.fail(f"not raised expected Exception for version: {case['version']}")

                    self.assertEqual(self.zapi._AsyncZabbixAPI__session_id, case['output'],
                                         f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()
