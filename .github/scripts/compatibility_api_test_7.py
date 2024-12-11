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
from zabbix_utils.exceptions import APIRequestError
from zabbix_utils.types import AgentResponse, ItemValue, TrapperResponse, APIVersion

ZABBIX_URL = '127.0.0.1'
ZABBIX_USER = 'Admin'
ZABBIX_PASSWORD = 'zabbix'
ZABBIX_PROXY_ADDR = '127.0.0.1'


class CompatibilityAPITest(unittest.TestCase):
    """Compatibility synchronous test with Zabbix API version 7.0, 7.2"""

    def setUp(self):
        self.url = ZABBIX_URL
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.token_id = None
        self.token = None
        self.zapi = ZabbixAPI(
            url=self.url
        )
        self._create_token()

    def _create_token(self):
        """Tests auth using username and password"""

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

        tokens = self.zapi.token.get(
            filter={'name': f"{self.user} [{self.__class__.__name__}]"},
            output=['tokenid']
        )

        if tokens:
            self.token_id = int(tokens[0]['tokenid'])
            self.assertEqual(
                type(self.token_id), int, "Request token.get was going wrong")
        else:
            self.token_id = int(self.zapi.token.create(
                name=f"{self.user} [{self.__class__.__name__}]"
            )['tokenids'][0])
            self.assertEqual(
                type(self.token_id), int, "Request token.create was going wrong")

        self.token = self.zapi.token.generate(*[self.token_id])[0]['token']
        self.assertEqual(type(self.token), str, "Request token.generate was going wrong")

        self.zapi.logout()

        self.assertIsNone(self.zapi._ZabbixAPI__session_id, "Logout was going wrong")

        with self.assertRaises(APIRequestError,
                               msg="Request user.checkAuthentication after logout was going wrong"):
            resp = self.zapi.user.checkAuthentication(sessionid=(self.zapi._ZabbixAPI__session_id or ''))

    def test_classic_auth(self):
        """Tests auth using username and password"""

        self._create_token()

    def test_token_auth(self):
        """Tests auth using token"""

        self.assertEqual(
            type(self.zapi), ZabbixAPI, "Creating ZabbixAPI object was going wrong")

        self.assertEqual(
            type(self.zapi.api_version()), APIVersion, "Version getting was going wrong")

        self.zapi.login(token=self.token)

        self.assertIsNotNone(self.zapi._ZabbixAPI__session_id, "Login by token was going wrong")

        resp = self.zapi.user.checkAuthentication(token=self.token)

        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")


class CompatibilitySenderTest(unittest.TestCase):
    """Compatibility synchronous test with Zabbix sender version 7.0, 7.2"""

    def setUp(self):
        self.ip = ZABBIX_URL
        self.port = 10051
        self.chunk_size = 10
        self.sender = Sender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )
        self.zapi = None
        self.hostid = None
        self.proxy_groupid = None
        self.proxy_ip = ZABBIX_PROXY_ADDR
        self.hostname = f"{self.__class__.__name__}_host"
        self.itemname = f"{self.__class__.__name__}_item"
        self.itemkey = f"{self.__class__.__name__}"
        self.pgroupname = "CompatibilitySenderTest_group"
        self.proxy = "CompatibilitySenderTest_proxy"
        self.proxyids = []
        self.prepare_instance()

    def tearDown(self):
        if self.zapi:
            self.zapi.logout()

    def prepare_instance(self):
        """Creates required entities for sending values later"""

        self.zapi = ZabbixAPI(
            url=ZABBIX_URL,
            user=ZABBIX_USER,
            password=ZABBIX_PASSWORD,
            skip_version_check=True
        )

        hosts = self.zapi.host.get(
            filter={'host': self.hostname},
            output=['hostid']
        )

        if len(hosts) > 0:
            self.hostid = hosts[0].get('hostid')

        if not self.hostid:
            self.hostid = self.zapi.host.create(
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

        self.assertIsNotNone(self.hostid, "Creating test host was going wrong")

        items = self.zapi.item.get(
            filter={'key_': self.itemkey},
            output=['itemid']
        )

        itemid = None
        if len(items) > 0:
            itemid = items[0].get('itemid')

        if not itemid:
            itemid = self.zapi.item.create(
                name=self.itemname,
                key_=self.itemkey,
                hostid=self.hostid,
                type=2,
                value_type=3
            )['itemids'][0]

        time.sleep(2)

        self.assertIsNotNone(itemid, "Creating test item was going wrong")

        groups = self.zapi.proxygroup.get(
            filter={'name': self.pgroupname},
            output=['proxy_groupid']
        )

        if len(groups) > 0:
            self.proxy_groupid = groups[0].get('proxy_groupid')

        if not self.proxy_groupid:
            self.proxy_groupid = self.zapi.proxygroup.create(
                name=self.pgroupname,
                failover_delay="10s",
                min_online="1"
            )['proxy_groupids'][0]

            self.assertIsNotNone(self.proxy_groupid, "Creating test proxy group was going wrong")

            time.sleep(10)

        proxies = self.zapi.proxy.get(
            search={'name': self.proxy},
            output=['proxyid']
        )
        if len(proxies) > 0:
            self.zapi.proxy.delete(*[p['proxyid'] for p in proxies])

        self.proxyids += self.zapi.proxy.create(
            name=self.proxy + "1",
            operating_mode="0",
            local_address=self.proxy_ip,
            local_port=10061,
            proxy_groupid=self.proxy_groupid
        )['proxyids']
        self.proxyids += self.zapi.proxy.create(
            name=self.proxy + "2",
            operating_mode="0",
            local_address=self.proxy_ip,
            local_port=10062,
            proxy_groupid=self.proxy_groupid
        )['proxyids']

        self.assertTrue(bool(self.proxyids), "Creating test proxy group was going wrong")

    def test_send_values(self):
        """Tests sending item values"""

        self.zapi.host.update(
            hostid=self.hostid,
            monitored_by="0"
        )
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

        for port in [10061, 10062]:
            self.sender = Sender(
                server=self.proxy_ip,
                port=port,
                chunk_size=self.chunk_size
            )
            self.zapi.host.update(
                hostid=self.hostid,
                monitored_by="2",
                proxy_groupid=self.proxy_groupid
            )
            resp = self.sender.send_value(self.hostname, self.itemkey, 10)

            self.assertEqual(type(resp), TrapperResponse, "Sending item values was going wrong")
            self.assertEqual(resp.total, 1, "Total number of the sent values is unexpected")

            first_chunk = list(resp.details.values())[0][0]
            self.assertEqual(type(first_chunk), TrapperResponse, "Sending item values was going wrong")
            self.assertEqual(first_chunk.total, 1, "Total number of the sent values is unexpected")


class CompatibilityGetTest(unittest.TestCase):
    """Compatibility synchronous test with Zabbix get version 7.0, 7.2"""

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
    """Compatibility asynchronous test with Zabbix API version 7.0, 7.2"""

    async def asyncSetUp(self):
        self.url = ZABBIX_URL
        self.user = ZABBIX_USER
        self.password = ZABBIX_PASSWORD
        self.token_id = None
        self.token = None
        self.zapi = AsyncZabbixAPI(
            url=self.url
        )
        await self._create_token()

    async def asyncTearDown(self):
        if self.zapi:
            await self.zapi.logout()

    async def _create_token(self):
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

        tokens = await self.zapi.token.get(
            filter={'name': f"{self.user} [{self.__class__.__name__}]"},
            output=['tokenid']
        )

        if tokens:
            self.token_id = int(tokens[0]['tokenid'])
            self.assertEqual(
                type(self.token_id), int, "Request token.get was going wrong")
        else:
            created_token = await self.zapi.token.create(
                name=f"{self.user} [{self.__class__.__name__}]"
            )
            self.token_id = int(created_token['tokenids'][0])
            self.assertEqual(
                type(self.token_id), int, "Request token.create was going wrong")

        generated_token = await self.zapi.token.generate(*[self.token_id])
        self.token = generated_token[0]['token']
        self.assertEqual(type(self.token), str, "Request token.generate was going wrong")

    async def test_classic_auth(self):
        """Tests auth using username and password"""

        await self._create_token()

    async def test_token_auth(self):
        """Tests auth using token"""

        self.assertEqual(
            type(self.zapi), AsyncZabbixAPI, "Creating AsyncZabbixAPI object was going wrong")

        self.assertEqual(
            type(self.zapi.api_version()), APIVersion, "Version getting was going wrong")

        await self.zapi.login(token=self.token)

        self.assertIsNotNone(self.zapi._AsyncZabbixAPI__session_id, "Login by token was going wrong")

        resp = await self.zapi.user.checkAuthentication(token=self.token)

        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

        await self.zapi.logout()

        self.assertIsNone(self.zapi._AsyncZabbixAPI__session_id, "Logout was going wrong")

        with self.assertRaises(RuntimeError,
                               msg="Request user.checkAuthentication after logout was going wrong"):
            resp = await self.zapi.user.checkAuthentication(sessionid=(self.zapi._AsyncZabbixAPI__session_id or ''))


class CompatibilityAsyncSenderTest(unittest.IsolatedAsyncioTestCase):
    """Compatibility asynchronous test with Zabbix sender version 7.0, 7.2"""

    async def asyncSetUp(self):
        self.ip = ZABBIX_URL
        self.port = 10051
        self.chunk_size = 10
        self.sender = AsyncSender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )
        self.zapi = None
        self.hostid = None
        self.proxy_groupid = None
        self.proxy_ip = ZABBIX_PROXY_ADDR
        self.hostname = f"{self.__class__.__name__}_host"
        self.itemname = f"{self.__class__.__name__}_item"
        self.itemkey = f"{self.__class__.__name__}"
        self.pgroupname = "CompatibilitySenderTest_group"
        self.proxy = "CompatibilitySenderTest_proxy"
        self.proxyids = []
        await self.prepare_items()

    async def asyncTearDown(self):
        if self.zapi:
            self.zapi.logout()

    async def prepare_items(self):
        """Creates required entities for sending values later"""

        self.zapi = ZabbixAPI(
            url=ZABBIX_URL,
            user=ZABBIX_USER,
            password=ZABBIX_PASSWORD,
            skip_version_check=True
        )

        hosts = self.zapi.host.get(
            filter={'host': self.hostname},
            output=['hostid']
        )

        if len(hosts) > 0:
            self.hostid = hosts[0].get('hostid')

        if not self.hostid:
            created_host = self.zapi.host.create(
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
            self.hostid = created_host['hostids'][0]

        self.assertIsNotNone(self.hostid, "Creating test host was going wrong")

        items = self.zapi.item.get(
            filter={'key_': self.itemkey},
            output=['itemid']
        )

        itemid = None
        if len(items) > 0:
            itemid = items[0].get('itemid')

        if not itemid:
            created_item = self.zapi.item.create(
                name=self.itemname,
                key_=self.itemkey,
                hostid=self.hostid,
                type=2,
                value_type=3
            )
            itemid = created_item['itemids'][0]

        self.assertIsNotNone(itemid, "Creating test item was going wrong")

        groups = self.zapi.proxygroup.get(
            filter={'name': self.pgroupname},
            output=['proxy_groupid']
        )

        if len(groups) > 0:
            self.proxy_groupid = groups[0].get('proxy_groupid')

        if not self.proxy_groupid:
            created_proxy_group = self.zapi.proxygroup.create(
                name=self.pgroupname,
                failover_delay="10s",
                min_online="1"
            )
            self.proxy_groupid = created_proxy_group['proxy_groupids'][0]

            self.assertIsNotNone(self.proxy_groupid, "Creating test proxy group was going wrong")

            time.sleep(10)

        proxies = self.zapi.proxy.get(
            search={'name': self.proxy},
            output=['proxyid']
        )
        if len(proxies) > 0:
            self.zapi.proxy.delete(*[p['proxyid'] for p in proxies])

        created_proxy = self.zapi.proxy.create(
            name=self.proxy + "1",
            operating_mode="0",
            local_address=self.proxy_ip,
            local_port=10061,
            proxy_groupid=self.proxy_groupid
        )
        self.proxyids += created_proxy['proxyids']
        created_proxy = self.zapi.proxy.create(
            name=self.proxy + "2",
            operating_mode="0",
            local_address=self.proxy_ip,
            local_port=10062,
            proxy_groupid=self.proxy_groupid
        )
        self.proxyids += created_proxy['proxyids']

        self.assertTrue(bool(self.proxyids), "Creating test proxy group was going wrong")

    async def test_send_values(self):
        """Tests sending item values"""

        self.zapi.host.update(
            hostid=self.hostid,
            monitored_by="0"
        )

        time.sleep(5)

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

        for port in [10061, 10062]:
            self.sender = AsyncSender(
                server=self.proxy_ip,
                port=port,
                chunk_size=self.chunk_size
            )
            self.zapi.host.update(
                hostid=self.hostid,
                monitored_by="2",
                proxy_groupid=self.proxy_groupid
            )
            resp = await self.sender.send_value(self.hostname, self.itemkey, 10)

            self.assertEqual(type(resp), TrapperResponse, "Sending item values was going wrong")
            self.assertEqual(resp.total, 1, "Total number of the sent values is unexpected")

            first_chunk = list(resp.details.values())[0][0]
            self.assertEqual(type(first_chunk), TrapperResponse, "Sending item values was going wrong")
            self.assertEqual(first_chunk.total, 1, "Total number of the sent values is unexpected")


class CompatibilityAsyncGetTest(unittest.IsolatedAsyncioTestCase):
    """Compatibility asynchronous test with Zabbix get version 7.0, 7.2"""

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
