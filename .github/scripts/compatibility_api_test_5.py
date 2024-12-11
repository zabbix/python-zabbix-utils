#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import time
import unittest

sys.path.append('.')
from zabbix_utils.api import ZabbixAPI
from zabbix_utils.sender import Sender
from zabbix_utils.getter import Getter
from zabbix_utils.aioapi import AsyncZabbixAPI
from zabbix_utils.aiosender import AsyncSender
from zabbix_utils.aiogetter import AsyncGetter
from zabbix_utils.exceptions import APIRequestError, APINotSupported
from zabbix_utils.types import AgentResponse, ItemValue, TrapperResponse, APIVersion

ZABBIX_URL = '127.0.0.1'
ZABBIX_USER = 'Admin'
ZABBIX_PASSWORD = 'zabbix'


class CompatibilityAPITest(unittest.TestCase):
    """Compatibility synchronous test with Zabbix API version 5.0"""

    def setUp(self):
        self.url = ZABBIX_URL
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.token = 'token'
        self.zapi = ZabbixAPI(
            url=self.url
        )

    def test_classic_auth(self):
        """Tests classic auth using username and password"""

        self.assertEqual(
            type(self.zapi), ZabbixAPI, "Creating ZabbixAPI object was going wrong")

        self.assertEqual(
            type(self.zapi.api_version()), APIVersion, "Version getting was going wrong")

        self.zapi.login(
            user=self.user,
            password=self.password
        )

        self.assertIsNotNone(self.zapi._ZabbixAPI__session_id, "Login by user and password was going wrong")

        resp = self.zapi.user.checkAuthentication(sessionid=self.zapi._ZabbixAPI__session_id)

        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

        users = self.zapi.user.get(
            output=['userid', 'name']
        )
        self.assertEqual(type(users), list, "Request user.get was going wrong")

        self.zapi.logout()

        self.assertIsNone(self.zapi._ZabbixAPI__session_id, "Logout was going wrong")

        with self.assertRaises(APIRequestError,
                               msg="Request user.checkAuthentication after logout was going wrong"):
            resp = self.zapi.user.checkAuthentication(sessionid=(self.zapi._ZabbixAPI__session_id or ''))

    def test_token_auth(self):
        """Tests auth using token"""

        with self.assertRaises(APINotSupported,
                               msg="Login by token should be not supported"):
            self.zapi.login(token=self.token)


class CompatibilitySenderTest(unittest.TestCase):
    """Compatibility synchronous test with Zabbix sender version 5.0"""

    def setUp(self):
        self.ip = ZABBIX_URL
        self.port = 10051
        self.chunk_size = 10
        self.sender = Sender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )
        self.hostname = f"{self.__class__.__name__}_host"
        self.itemname = f"{self.__class__.__name__}_item"
        self.itemkey = f"{self.__class__.__name__}"
        self.prepare_items()

    def prepare_items(self):
        """Creates host and items for sending values later"""

        zapi = ZabbixAPI(
            url=ZABBIX_URL,
            user=ZABBIX_USER,
            password=ZABBIX_PASSWORD,
            skip_version_check=True
        )

        hosts = zapi.host.get(
            filter={'host': self.hostname},
            output=['hostid']
        )

        hostid = None
        if len(hosts) > 0:
            hostid = hosts[0].get('hostid')

        if not hostid:
            hostid = zapi.host.create(
                host=self.hostname,
                interfaces=[{
                    "type": 1,
                    "main": 1,
                    "useip": 1,
                    "ip": "127.0.0.1",
                    "dns": "",
                    "port": "10050"
                }],
                groups=[{"groupid": "2"}]
            )['hostids'][0]

        self.assertIsNotNone(hostid, "Creating test host was going wrong")

        items = zapi.item.get(
            filter={'key_': self.itemkey},
            output=['itemid']
        )

        itemid = None
        if len(items) > 0:
            itemid = items[0].get('itemid')

        if not itemid:
            itemid = zapi.item.create(
                name=self.itemname,
                key_=self.itemkey,
                hostid=hostid,
                type=2,
                value_type=3
            )['itemids'][0]

        self.assertIsNotNone(hostid, "Creating test item was going wrong")

        zapi.logout()

    def test_send_values(self):
        """Tests sending item values"""

        time.sleep(10)

        items = [
            ItemValue(self.hostname, self.itemkey, 10),
            ItemValue(self.hostname, self.itemkey, 'test message'),
            ItemValue(self.hostname, 'item_key1', -1, 1695713666),
            ItemValue(self.hostname, 'item_key2', '{"msg":"test message"}'),
            ItemValue(self.hostname, self.itemkey, 0, 1695713666, 100),
            ItemValue(self.hostname, self.itemkey, 5.5, 1695713666)
        ]
        resp = self.sender.send(items)
        self.assertEqual(type(resp), TrapperResponse, "Sending item values was going wrong")
        self.assertEqual(resp.total, len(items), "Total number of the sent values is unexpected")
        self.assertEqual(resp.processed, 4, "Number of the processed values is unexpected")
        self.assertEqual(resp.failed, (resp.total - resp.processed), "Number of the failed values is unexpected")

        first_chunk = list(resp.details.values())[0][0]
        self.assertEqual(type(first_chunk), TrapperResponse, "Sending item values was going wrong")
        self.assertEqual(first_chunk.total, len(items), "Total number of the sent values is unexpected")
        self.assertEqual(first_chunk.processed, 4, "Number of the processed values is unexpected")
        self.assertEqual(first_chunk.failed, (first_chunk.total - first_chunk.processed), "Number of the failed values is unexpected")


class CompatibilityGetTest(unittest.TestCase):
    """Compatibility synchronous test with Zabbix get version 5.0"""

    def setUp(self):
        self.host = ZABBIX_URL
        self.port = 10050
        self.agent = Getter(
            host=self.host,
            port=self.port
        )

    def test_get_values(self):
        """Tests getting item values"""

        resp = self.agent.get('system.uname')

        self.assertIsNotNone(resp, "Getting item values was going wrong")
        self.assertEqual(type(resp), AgentResponse, "Got value is unexpected")
        self.assertEqual(type(resp.value), str, "Got value is unexpected")


class CompatibilityAsyncAPITest(unittest.IsolatedAsyncioTestCase):
    """Compatibility asynchronous test with Zabbix API version 5.0"""

    async def asyncSetUp(self):
        self.url = ZABBIX_URL
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.token = 'token'
        self.zapi = AsyncZabbixAPI(
            url=self.url
        )

    async def asyncTearDown(self):
        if self.zapi:
            await self.zapi.logout()

    async def test_classic_auth(self):
        """Tests auth using username and password"""

        self.assertEqual(
            type(self.zapi), AsyncZabbixAPI, "Creating AsyncZabbixAPI object was going wrong")

        self.assertEqual(
            type(self.zapi.api_version()), APIVersion, "Version getting was going wrong")

        await self.zapi.login(
            user=self.user,
            password=self.password
        )

        self.assertIsNotNone(self.zapi._AsyncZabbixAPI__session_id, "Login by user and password was going wrong")

        resp = await self.zapi.user.checkAuthentication(sessionid=self.zapi._AsyncZabbixAPI__session_id)

        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

        users = await self.zapi.user.get(
            output=['userid', 'name']
        )
        self.assertEqual(type(users), list, "Request user.get was going wrong")

        await self.zapi.logout()

        self.assertIsNone(self.zapi._AsyncZabbixAPI__session_id, "Logout was going wrong")

        with self.assertRaises(RuntimeError,
                               msg="Request user.checkAuthentication after logout was going wrong"):
            resp = await self.zapi.user.checkAuthentication(sessionid=(self.zapi._AsyncZabbixAPI__session_id or ''))

    async def test_token_auth(self):
        """Tests auth using token"""

        with self.assertRaises(APINotSupported,
                               msg="Login by token should be not supported"):
            await self.zapi.login(token=self.token)


class CompatibilityAsyncSenderTest(unittest.IsolatedAsyncioTestCase):
    """Compatibility asynchronous test with Zabbix sender version 5.0"""

    async def asyncSetUp(self):
        self.ip = ZABBIX_URL
        self.port = 10051
        self.chunk_size = 10
        self.sender = AsyncSender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )
        self.hostname = f"{self.__class__.__name__}_host"
        self.itemname = f"{self.__class__.__name__}_item"
        self.itemkey = f"{self.__class__.__name__}"
        await self.prepare_items()

    async def prepare_items(self):
        """Creates host and items for sending values later"""

        zapi = AsyncZabbixAPI(
            url=ZABBIX_URL,
            skip_version_check=True
        )
        await zapi.login(
            user=ZABBIX_USER,
            password=ZABBIX_PASSWORD
        )

        hosts = await zapi.host.get(
            filter={'host': self.hostname},
            output=['hostid']
        )

        hostid = None
        if len(hosts) > 0:
            hostid = hosts[0].get('hostid')

        if not hostid:
            created_host = await zapi.host.create(
                host=self.hostname,
                interfaces=[{
                    "type": 1,
                    "main": 1,
                    "useip": 1,
                    "ip": "127.0.0.1",
                    "dns": "",
                    "port": "10050"
                }],
                groups=[{"groupid": "2"}]
            )
            hostid = created_host['hostids'][0]

        self.assertIsNotNone(hostid, "Creating test host was going wrong")

        items = await zapi.item.get(
            filter={'key_': self.itemkey},
            output=['itemid']
        )

        itemid = None
        if len(items) > 0:
            itemid = items[0].get('itemid')

        if not itemid:
            created_item = await zapi.item.create(
                name=self.itemname,
                key_=self.itemkey,
                hostid=hostid,
                type=2,
                value_type=3
            )
            itemid = created_item['itemids'][0]

        self.assertIsNotNone(hostid, "Creating test item was going wrong")

        await zapi.logout()

    async def test_send_values(self):
        """Tests sending item values"""

        time.sleep(10)

        items = [
            ItemValue(self.hostname, self.itemkey, 10),
            ItemValue(self.hostname, self.itemkey, 'test message'),
            ItemValue(self.hostname, 'item_key1', -1, 1695713666),
            ItemValue(self.hostname, 'item_key2', '{"msg":"test message"}'),
            ItemValue(self.hostname, self.itemkey, 0, 1695713666, 100),
            ItemValue(self.hostname, self.itemkey, 5.5, 1695713666)
        ]
        resp = await self.sender.send(items)
        self.assertEqual(type(resp), TrapperResponse, "Sending item values was going wrong")
        self.assertEqual(resp.total, len(items), "Total number of the sent values is unexpected")
        self.assertEqual(resp.processed, 4, "Number of the processed values is unexpected")
        self.assertEqual(resp.failed, (resp.total - resp.processed), "Number of the failed values is unexpected")

        first_chunk = list(resp.details.values())[0][0]
        self.assertEqual(type(first_chunk), TrapperResponse, "Sending item values was going wrong")
        self.assertEqual(first_chunk.total, len(items), "Total number of the sent values is unexpected")
        self.assertEqual(first_chunk.processed, 4, "Number of the processed values is unexpected")
        self.assertEqual(first_chunk.failed, (first_chunk.total - first_chunk.processed), "Number of the failed values is unexpected")


class CompatibilityAsyncGetTest(unittest.IsolatedAsyncioTestCase):
    """Compatibility asynchronous test with Zabbix get version 5.0"""

    async def asyncSetUp(self):
        self.host = ZABBIX_URL
        self.port = 10050
        self.agent = AsyncGetter(
            host=self.host,
            port=self.port
        )

    async def test_get_values(self):
        """Tests getting item values"""

        resp = await self.agent.get('system.uname')

        self.assertIsNotNone(resp, "Getting item values was going wrong")
        self.assertEqual(type(resp), AgentResponse, "Got value is unexpected")
        self.assertEqual(type(resp.value), str, "Got value is unexpected")


if __name__ == '__main__':
    unittest.main()
