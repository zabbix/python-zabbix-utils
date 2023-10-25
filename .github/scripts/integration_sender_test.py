#!/usr/bin/env python
import sys
import unittest

sys.path.append('.')
from zabbix_utils.sender import ZabbixItem, ZabbixSender, ZabbixResponse


class IntegrationSenderTest(unittest.TestCase):
    """Test working with a real Zabbix server/proxy instance"""

    def setUp(self):
        self.ip = '127.0.0.1'
        self.port = 10051
        self.chunk_size = 10
        self.sender = ZabbixSender(
            server=self.ip,
            port=self.port,
            chunk_size=self.chunk_size
        )

    def test_send(self):
        """Tests sending item values works properly"""

        items = [
            ZabbixItem('host1', 'item.key1', 10),
            ZabbixItem('host1', 'item.key2', 'test message'),
            ZabbixItem('host2', 'item.key1', -1, 1695713666),
            ZabbixItem('host3', 'item.key1', '{"msg":"test message"}'),
            ZabbixItem('host2', 'item.key1', 0, 1695713666, 100)
        ]
        chunks_resp = self.sender.send(items)

        self.assertEqual(type(chunks_resp), list, "Sending item values was going wrong")
        for resp in chunks_resp:
            self.assertEqual(type(resp), ZabbixResponse, "Sending item values was going wrong")
            for key in ('processed', 'failed', 'total', 'time', 'chunk'):
                try:
                    self.assertIsNotNone(getattr(resp, key), f"There aren't expected '{key}' value")
                except AttributeError:
                    self.fail(f"raised unexpected Exception for attribute: {key}")


if __name__ == '__main__':
    unittest.main()
