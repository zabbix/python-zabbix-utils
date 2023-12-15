#!/usr/bin/env python
# Copyright (C) 2001-2023 Zabbix SIA
#
# Zabbix SIA licenses this file under the MIT License.
# See the LICENSE file in the project root for more information.

import sys
import unittest

sys.path.append('.')
from zabbix_utils.sender import ItemValue, Sender, TrapperResponse, Node


class IntegrationSenderTest(unittest.TestCase):
    """Test working with a real Zabbix server/proxy instance"""

    def setUp(self):
        self.ip = '127.0.0.1'
        self.port = 10051
        self.chunk_size = 10
        self.sender = Sender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )

    def test_send(self):
        """Tests sending item values works properly"""

        items = [
            ItemValue('host1', 'item.key1', 10),
            ItemValue('host1', 'item.key2', 'test message'),
            ItemValue('host2', 'item.key1', -1, 1695713666),
            ItemValue('host3', 'item.key1', '{"msg":"test message"}'),
            ItemValue('host2', 'item.key1', 0, 1695713666, 100)
        ]
        responses = self.sender.send(items)

        self.assertEqual(type(responses), dict, "Sending item values was going wrong")
        for node, resp in responses.items():
            self.assertEqual(type(node), Node, "Sending item values was going wrong")
            self.assertEqual(type(resp), TrapperResponse, "Sending item values was going wrong")
            for key in ('processed', 'failed', 'total', 'time', 'chunk'):
                try:
                    self.assertIsNotNone(getattr(resp, key), f"There aren't expected '{key}' value")
                except AttributeError:
                    self.fail(f"raised unexpected Exception for attribute: {key}")


if __name__ == '__main__':
    unittest.main()
