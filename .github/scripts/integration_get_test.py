#!/usr/bin/env python
import sys
import json
import unittest

sys.path.append('.')
from zabbix_utils.getter import Getter


class IntegrationGetTest(unittest.TestCase):
    """Test working with a real Zabbix agent instance"""

    def setUp(self):
        self.host = '127.0.0.1'
        self.port = 10050
        self.agent = Getter(
            host=self.host,
            port=self.port
        )

    def test_get(self):
        """Tests getting item values from Zabbix agent works properly"""

        resp = self.agent.get('net.if.discovery')

        self.assertIsNotNone(resp, "Getting item values was going wrong")
        try:
            resp_list = json.loads(resp)
        except json.decoder.JSONDecodeError:
            self.fail(f"raised unexpected Exception while parsing response: {resp}")

        self.assertEqual(type(resp_list), list, "Getting item values was going wrong")
        for resp in resp_list:
            self.assertEqual(type(resp), dict, "Getting item values was going wrong")


if __name__ == '__main__':
    unittest.main()
