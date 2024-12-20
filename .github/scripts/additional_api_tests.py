#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import ssl
import unittest
from aiohttp import ClientSession, TCPConnector

sys.path.append('.')
from zabbix_utils.api import ZabbixAPI
from zabbix_utils.types import APIVersion
from zabbix_utils.aioapi import AsyncZabbixAPI

ZABBIX_URL = 'https://127.0.0.1:443'
ZABBIX_USER = 'Admin'
ZABBIX_PASSWORD = 'zabbix'


class CustomCertAPITest(unittest.TestCase):
    """Test working with a real Zabbix API instance synchronously"""

    def setUp(self):
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.url = ZABBIX_URL + '/ssl_context/'

        context = ssl.create_default_context()
        context.load_verify_locations('/etc/nginx/ssl/nginx.crt')

        self.api = ZabbixAPI(
            url=self.url,
            user=self.user,
            password=self.password,
            skip_version_check=True,
            ssl_context=context
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


class CustomCertAsyncAPITest(unittest.IsolatedAsyncioTestCase):
    """Test working with a real Zabbix API instance asynchronously"""

    async def asyncSetUp(self):
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.url = ZABBIX_URL + '/ssl_context/'

        context = ssl.create_default_context()
        context.load_verify_locations('/etc/nginx/ssl/nginx.crt')
        self.session = ClientSession(
            connector=TCPConnector(ssl=context)
        )

        self.api = AsyncZabbixAPI(
            url=self.url,
            skip_version_check=True,
            client_session=self.session
        )
        await self.api.login(
            user=self.user,
            password=self.password
        )

    async def asyncTearDown(self):
        if self.api:
            await self.api.logout()
        if not self.session.closed:
            await self.session.close()

    async def test_login(self):
        """Tests login function works properly"""

        self.assertEqual(
            type(self.api), AsyncZabbixAPI, "Login was going wrong")
        self.assertEqual(
            type(self.api.api_version()), APIVersion, "Version getting was going wrong")

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
