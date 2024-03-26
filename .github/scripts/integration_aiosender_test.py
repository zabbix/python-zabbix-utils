#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import unittest

sys.path.append('.')
from zabbix_utils.aiosender import AsyncSender
from zabbix_utils.types import ItemValue, TrapperResponse, Node


class IntegrationSenderTest(unittest.IsolatedAsyncioTestCase):
    """Test working with a real Zabbix server/proxy instance"""

    async def asyncSetUp(self):
        self.ip = '127.0.0.1'
        self.port = 10051
        self.chunk_size = 10
        self.sender = AsyncSender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )

    async def test_send(self):
        """Tests sending item values works properly"""

        items = [
            ItemValue('host1', 'item.key1', 10),
            ItemValue('host1', 'item.key2', 'test message'),
            ItemValue('host2', 'item.key1', -1, 1695713666),
            ItemValue('host3', 'item.key1', '{"msg":"test message"}'),
            ItemValue('host2', 'item.key1', 0, 1695713666, 100)
        ]
        response = await self.sender.send(items)

        self.assertEqual(type(response.details), dict, "Sending item values was going wrong")
        for node, resp in response.details.items():
            self.assertEqual(type(node), Node, "Sending item values was going wrong")
            for item in resp:
                self.assertEqual(type(item), TrapperResponse, "Sending item values was going wrong")
                for key in ('processed', 'failed', 'total', 'time', 'chunk'):
                    try:
                        self.assertIsNotNone(getattr(item, key), f"There aren't expected '{key}' value")
                    except AttributeError:
                        self.fail(f"raised unexpected Exception for attribute: {key}")


if __name__ == '__main__':
    unittest.main()
