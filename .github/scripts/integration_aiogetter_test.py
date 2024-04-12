#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import json
import unittest

sys.path.append('.')
from zabbix_utils.aiogetter import AsyncGetter


class IntegrationGetTest(unittest.IsolatedAsyncioTestCase):
    """Test working with a real Zabbix agent instance"""

    async def asyncSetUp(self):
        self.host = '127.0.0.1'
        self.port = 10050
        self.agent = AsyncGetter(
            host=self.host,
            port=self.port
        )

    async def test_get(self):
        """Tests getting item values from Zabbix agent works properly"""

        resp = await self.agent.get('net.if.discovery')

        self.assertIsNotNone(resp, "Getting item values was going wrong")
        try:
            resp_list = json.loads(resp.value)
        except json.decoder.JSONDecodeError:
            self.fail(f"raised unexpected Exception while parsing response: {resp}")

        self.assertEqual(type(resp_list), list, "Getting item values was going wrong")
        for resp in resp_list:
            self.assertEqual(type(resp), dict, "Getting item values was going wrong")


if __name__ == '__main__':
    unittest.main()
