#!/usr/bin/env python
import sys
import time
import unittest

sys.path.append('.')
from zabbix_utils.get import ZabbixGet
from zabbix_utils.exceptions import ZabbixAPIException
from zabbix_utils.api import ZabbixAPI, ZabbixAPIVersion
from zabbix_utils.sender import ZabbixItem, ZabbixSender, ZabbixResponse

ZABBIX_URL = 'localhost'
ZABBIX_USER = 'Admin'
ZABBIX_PASSWORD = 'zabbix'


class CompatibilityAPITest(unittest.TestCase):
    """Compatibility test with the latest Zabbix API version"""

    def setUp(self):
        self.url = 'localhost'
        self.user = 'Admin'
        self.password = 'zabbix'
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
            type(self.zapi.api_version()), ZabbixAPIVersion, "Version getting was going wrong")

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

        with self.assertRaises(ZabbixAPIException,
                               msg="Request user.checkAuthentication after logout was going wrong"):
            resp = self.zapi.user.checkAuthentication(sessionid=self.zapi._ZabbixAPI__session_id)

    def test_classic_auth(self):
        """Tests auth using username and password"""

        self._create_token()

    def test_token_auth(self):
        """Tests auth using token"""

        self.assertEqual(
            type(self.zapi), ZabbixAPI, "Creating ZabbixAPI object was going wrong")

        self.assertEqual(
            type(self.zapi.api_version()), ZabbixAPIVersion, "Version getting was going wrong")

        self.zapi.login(token=self.token)

        self.assertIsNotNone(self.zapi._ZabbixAPI__session_id, "Login by token was going wrong")

        resp = self.zapi.user.checkAuthentication(token=self.token)

        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

        users = self.zapi.user.get(
            output=['userid', 'alias']
        )
        self.assertEqual(type(users), list, "Request user.get was going wrong")

        self.zapi.logout()

        self.assertIsNone(self.zapi._ZabbixAPI__session_id, "Logout was going wrong")

        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")


class CompatibilitySenderTest(unittest.TestCase):
    """Compatibility test with the latest Zabbix sender version"""

    def setUp(self):
        self.ip = '127.0.0.1'
        self.port = 10051
        self.chunk_size = 10
        self.sender = ZabbixSender(
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

            time.sleep(2)

        self.assertIsNotNone(hostid, "Creating test item was going wrong")

        zapi.logout()

    def test_send_values(self):
        """Tests sending item values"""

        items = [
            ZabbixItem(self.hostname, self.itemkey, 10),
            ZabbixItem(self.hostname, self.itemkey, 'test message'),
            ZabbixItem(self.hostname, 'item_key1', -1, 1695713666),
            ZabbixItem(self.hostname, 'item_key2', '{"msg":"test message"}'),
            ZabbixItem(self.hostname, self.itemkey, 0, 1695713666, 100),
            ZabbixItem(self.hostname, self.itemkey, 5.5, 1695713666)
        ]
        resp = self.sender.send(items)[0]

        self.assertEqual(type(resp), ZabbixResponse, "Sending item values was going wrong")
        self.assertEqual(resp.total, len(items), "Total number of the sent values is unexpected")
        self.assertEqual(resp.processed, 4, "Number of the processed values is unexpected")
        self.assertEqual(resp.failed, (resp.total - resp.processed), "Number of the failed values is unexpected")


class CompatibilityGetTest(unittest.TestCase):
    """Compatibility test with the latest Zabbix get version"""

    def setUp(self):
        self.host = 'localhost'
        self.port = 10050
        self.agent = ZabbixGet(
            host=self.host,
            port=self.port
        )

    def test_get_values(self):
        """Tests getting item values"""

        resp = self.agent.get('system.uname')

        self.assertIsNotNone(resp, "Getting item values was going wrong")
        self.assertEqual(type(resp), str, "Got value is unexpected")


if __name__ == '__main__':
    unittest.main()
