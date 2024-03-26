#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import unittest

sys.path.append('.')
from zabbix_utils.aioapi import AsyncZabbixAPI
from zabbix_utils.types import APIVersion


class IntegrationAPITest(unittest.IsolatedAsyncioTestCase):
    """Test working with a real Zabbix API instance"""

    async def asyncSetUp(self):
        self.url = 'localhost'
        self.user = 'Admin'
        self.password = 'zabbix'
        self.zapi = AsyncZabbixAPI(
            url=self.url,
            skip_version_check=True
        )
        await self.zapi.login(
            user=self.user,
            password=self.password
        )

    async def asyncTearDown(self):
        if self.zapi:
            await self.zapi.logout()

    async def test_login(self):
        """Tests login function works properly"""

        self.assertEqual(
            type(self.zapi), AsyncZabbixAPI, "Login was going wrong")
        self.assertEqual(
            type(self.zapi.api_version()), APIVersion, "Version getting was going wrong")

        await self.zapi.logout()

    async def test_version_get(self):
        """Tests getting version info works properly"""

        version = None
        if self.zapi:
            version = await self.zapi.apiinfo.version()
        self.assertEqual(
            version, str(self.zapi.api_version()), "Request apiinfo.version was going wrong")

    async def test_check_auth(self):
        """Tests checking authentication state works properly"""

        resp = None
        if self.zapi:
            if self.zapi._AsyncZabbixAPI__session_id == self.zapi._AsyncZabbixAPI__token:
                resp = await self.zapi.user.checkAuthentication(token=self.zapi._AsyncZabbixAPI__session_id)
            else:
                resp = await self.zapi.user.checkAuthentication(sessionid=self.zapi._AsyncZabbixAPI__session_id)
        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

    async def test_user_get(self):
        """Tests getting users info works properly"""

        users = None
        if self.zapi:
            users = await self.zapi.user.get(
                output=['userid', 'name']
            )
        self.assertEqual(type(users), list, "Request user.get was going wrong")

    async def test_host_get(self):
        """Tests getting hosts info works properly using suffix"""

        hosts = None
        if self.zapi:
            hosts = await self.zapi.host_.get_(
                output=['hostid', 'host']
            )
        self.assertEqual(type(hosts), list, "Request host.get was going wrong")


if __name__ == '__main__':
    unittest.main()
