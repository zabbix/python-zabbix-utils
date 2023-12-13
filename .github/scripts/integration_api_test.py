#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import unittest

sys.path.append('.')
from zabbix_utils.api import ZabbixAPI, APIVersion


class IntegrationAPITest(unittest.TestCase):
    """Test working with a real Zabbix API instance"""

    def setUp(self):
        self.url = 'localhost'
        self.user = 'Admin'
        self.password = 'zabbix'
        self.zapi = ZabbixAPI(
            url=self.url,
            user=self.user,
            password=self.password,
            skip_version_check=True
        )

    def tearDown(self):
        if self.zapi:
            self.zapi.logout()

    def test_login(self):
        """Tests login function works properly"""

        self.assertEqual(
            type(self.zapi), ZabbixAPI, "Login was going wrong")
        self.assertEqual(
            type(self.zapi.api_version()), APIVersion, "Version getting was going wrong")

    def test_version_get(self):
        """Tests getting version info works properly"""

        version = None
        if self.zapi:
            version = self.zapi.apiinfo.version()
        self.assertEqual(
            version, str(self.zapi.api_version()), "Request apiinfo.version was going wrong")

    def test_check_auth(self):
        """Tests checking authentication state works properly"""

        resp = None
        if self.zapi:
            if self.zapi._ZabbixAPI__session_id == self.zapi._ZabbixAPI__token:
                resp = self.zapi.user.checkAuthentication(token=self.zapi._ZabbixAPI__session_id)
            else:
                resp = self.zapi.user.checkAuthentication(sessionid=self.zapi._ZabbixAPI__session_id)
        self.assertEqual(
            type(resp), dict, "Request user.checkAuthentication was going wrong")

    def test_user_get(self):
        """Tests getting users info works properly"""

        users = None
        if self.zapi:
            users = self.zapi.user.get(
                output=['userid', 'name']
            )
        self.assertEqual(type(users), list, "Request user.get was going wrong")

    def test_host_get(self):
        """Tests getting hosts info works properly using suffix"""

        hosts = None
        if self.zapi:
            hosts = self.zapi.host_.get_(
                output=['hostid', 'host']
            )
        self.assertEqual(type(hosts), list, "Request host.get was going wrong")


if __name__ == '__main__':
    unittest.main()
