#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import base64
import unittest

sys.path.append('.')
from zabbix_utils.api import ZabbixAPI
from zabbix_utils.types import APIVersion
from zabbix_utils.aioapi import AsyncZabbixAPI

ZABBIX_URL = 'https://127.0.0.1:443'
ZABBIX_USER = 'Admin'
ZABBIX_PASSWORD = 'zabbix'
HTTP_USER = 'http_user'
HTTP_PASSWORD = 'http_pass'


class BasicAuthAPITest(unittest.TestCase):
    """Test working with a real Zabbix API instance using Basic auth synchronously

    Should be removed after: `June 30, 2029`
    """

    def setUp(self):
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.url = ZABBIX_URL + '/http_auth/'
        self.api = ZabbixAPI(
            url=self.url,
            user=self.user,
            password=self.password,
            validate_certs=False,
            http_user=HTTP_USER,
            http_password=HTTP_PASSWORD
        )

    def tearDown(self):
        if self.api:
            self.api.logout()

    def test_login(self):
        """Tests login function works properly"""

        self.assertEqual(
            type(self.api), ZabbixAPI, "Login was going wrong")
        self.assertEqual(
            type(self.api.api_version()), APIVersion, "Version getting was going wrong")

    def test_basic_auth(self):
        """Tests __basic_auth function works properly"""

        self.assertEqual(
            self.api._ZabbixAPI__basic_cred, base64.b64encode(
                "http_user:http_pass".encode()
                ).decode(), "Basic auth credentials generation was going wrong")

    def test_version_get(self):
        """Tests getting version info works properly"""

        version = None
        if self.api:
            version = self.api.apiinfo.version()
        self.assertEqual(
            version, str(self.api.api_version()), "Request apiinfo.version was going wrong")

    def test_check_auth(self):
        """Tests checking authentication state works properly"""

        resp = None
        if self.api:
            if self.api._ZabbixAPI__session_id == self.api._ZabbixAPI__token:
                resp = self.api.user.checkAuthentication(token=self.api._ZabbixAPI__session_id)
            else:
                resp = self.api.user.checkAuthentication(sessionid=self.api._ZabbixAPI__session_id)
        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

    def test_user_get(self):
        """Tests getting users info works properly"""

        users = None
        if self.api:
            users = self.api.user.get(
                output=['userid', 'name']
            )
        self.assertEqual(type(users), list, "Request user.get was going wrong")


class BasicAuthAsyncAPITest(unittest.IsolatedAsyncioTestCase):
    """Test working with a real Zabbix API instance using Basic auth asynchronously
    
    Should be removed after: `June 30, 2029`
    """

    async def asyncSetUp(self):
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.url = ZABBIX_URL + '/http_auth/'
        self.api = AsyncZabbixAPI(
            url=self.url,
            validate_certs=False,
            http_user=HTTP_USER,
            http_password=HTTP_PASSWORD
        )
        await self.api.login(
            user=self.user,
            password=self.password
        )

    async def asyncTearDown(self):
        if self.api:
            await self.api.logout()

    async def test_login(self):
        """Tests login function works properly"""

        self.assertEqual(
            type(self.api), AsyncZabbixAPI, "Login was going wrong")
        self.assertEqual(
            type(self.api.api_version()), APIVersion, "Version getting was going wrong")

    async def test_basic_auth(self):
        """Tests __basic_auth function works properly"""

        basic_auth = self.api.client_session._default_auth

        self.assertEqual(
            base64.b64encode(f"{basic_auth.login}:{basic_auth.password}".encode()).decode(),
            base64.b64encode(f"{HTTP_USER}:{HTTP_PASSWORD}".encode()).decode(),
            "Basic auth credentials generation was going wrong"
        )

    async def test_version_get(self):
        """Tests getting version info works properly"""

        version = None
        if self.api:
            version = await self.api.apiinfo.version()
        self.assertEqual(
            version, str(self.api.api_version()), "Request apiinfo.version was going wrong")

    async def test_check_auth(self):
        """Tests checking authentication state works properly"""

        resp = None
        if self.api:
            if self.api._AsyncZabbixAPI__session_id == self.api._AsyncZabbixAPI__token:
                resp = await self.api.user.checkAuthentication(token=(self.api._AsyncZabbixAPI__session_id or ''))
            else:
                resp = await self.api.user.checkAuthentication(sessionid=(self.api._AsyncZabbixAPI__session_id or ''))
        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

    async def test_user_get(self):
        """Tests getting users info works properly"""

        users = None
        if self.api:
            users = await self.api.user.get(
                output=['userid', 'name']
            )
        self.assertEqual(type(users), list, "Request user.get was going wrong")


if __name__ == '__main__':
    unittest.main()
