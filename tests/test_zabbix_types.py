# zabbix_utils
#
# Copyright (C) 2001-2023 Zabbix SIA
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import json
import unittest

from zabbix_utils.types import APIVersion, Cluster, ItemValue


class TestAPIVersion(unittest.TestCase):
    """Test cases for APIVersion object"""

    def test_init(self):
        """Tests creating of APIVersion object"""

        test_cases = [
            {'input': '7.0.0alpha', 'output': '7.0.0alpha', 'exception': TypeError, 'raised': True},
            {'input': '6.0.0', 'output': '6.0.0', 'exception': TypeError, 'raised': False},
            {'input': '6.0', 'output': None, 'exception': TypeError, 'raised': True},
            {'input': '7', 'output': None, 'exception': TypeError, 'raised': True}
        ]

        for case in test_cases:
            try:
                ver = APIVersion(case['input'])
            except ValueError:
                if not case['raised']:
                    self.fail(f"raised unexpected Exception with input data: {case['input']}")
            else:
                if case['raised']:
                    self.fail(f"not raised expected Exception with input data: {case['input']}")
                self.assertEqual(str(ver), case['output'],
                                 f"unexpected output with input data: {case['input']}")

    def test_major(self):
        """Tests getting the major version part of APIVersion"""

        test_cases = [
            {'input': '6.0.10', 'output': 6.0},
            {'input': '6.2.0', 'output': 6.2}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'])
            self.assertEqual(ver.major, case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_minor(self):
        """Tests getting the minor version part of APIVersion"""

        test_cases = [
            {'input': '6.0.10', 'output': 10},
            {'input': '6.2.0', 'output': 0}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'])
            self.assertEqual(ver.minor, case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_is_lts(self):
        """Tests is_lts method for different versions"""

        test_cases = [
            {'input': '6.0.10', 'output': True},
            {'input': '6.2.0', 'output': False},
            {'input': '6.4.5', 'output': False},
            {'input': '7.0.0', 'output': True},
            {'input': '7.0.30', 'output': True}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'])
            self.assertEqual(ver.is_lts(), case['output'],
                             f"unexpected output with input data: {case['input']}")

    def test_compare(self):
        """Tests version comparison for different version formats"""

        test_cases = [
            {'input': ['6.0.0','6.0.0'], 'operation': 'eq', 'output': True},
            {'input': ['6.0.0',6.0], 'operation': 'ne', 'output': False},
            {'input': ['6.0.0',6.0], 'operation': 'ge', 'output': True},
            {'input': ['6.0.0',7.0], 'operation': 'lt', 'output': True},
            {'input': ['6.4.1',6.4], 'operation': 'gt', 'output': False}
        ]

        for case in test_cases:
            ver = APIVersion(case['input'][0])
            result = (getattr(ver, f"__{case['operation']}__")(case['input'][1]))
            self.assertEqual(result, case['output'],
                             f"unexpected output with input data: {case['input']}")

        ver = APIVersion('6.0.0')
        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver > {}

        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver < []

        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver < 6

        with self.assertRaises(TypeError,
                               msg=f"input data={case['input']}"):
            ver != 7

        with self.assertRaises(ValueError,
                               msg=f"input data={case['input']}"):
            ver <= '7.0'


class TestCluster(unittest.TestCase):
    """Test cases for Zabbix Cluster object"""

    def test_parsing(self):
        """Tests creating of Zabbix Cluster object"""

        test_cases = [
            {
                'input': ['127.0.0.1'],
                'clusters': json.dumps([["127.0.0.1", 10051]])
            },
            {
                'input': ['localhost:10151'],
                'clusters': json.dumps([["localhost", 10151]])
            },
            {
                'input': ['zabbix.cluster.node1','zabbix.cluster.node2:20051','zabbix.cluster.node3:30051'],
                'clusters': json.dumps([
                    ["zabbix.cluster.node1", 10051], ["zabbix.cluster.node2", 20051], ["zabbix.cluster.node3", 30051]
                ])
            }
        ]

        for case in test_cases:
            cluster = Cluster(case['input'])

            self.assertEqual(str(cluster), case['clusters'],
                             f"unexpected output with input data: {case['input']}")


class TestItemValue(unittest.TestCase):
    """Test cases for Zabbix Item object"""

    def test_parsing(self):
        """Tests creating of Zabbix Item object"""

        test_cases = [
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0},
                'output': json.dumps({"host": "test_host", "key": "test_key", "value": "0"}),
                'exception': ValueError,
                'raised': False
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': 1695713666},
                'output':  json.dumps({"host": "test_host", "key": "test_key", "value": "0", "clock": 1695713666}),
                'exception': ValueError,
                'raised': False
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': '123abc'},
                'output':  json.dumps({"host": "test_host", "key": "test_key", "value": "0", "clock": '123abc'}),
                'exception': ValueError,
                'raised': True
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'clock': 1695713666, 'ns': 100},
                'output': json.dumps({"host": "test_host", "key": "test_key", "value": "0", "clock": 1695713666, "ns": 100}),
                'exception': ValueError,
                'raised': False
            },
            {
                'input': {'host':'test_host', 'key':'test_key', 'value': 0, 'ns': '123abc'},
                'output': json.dumps({"host": "test_host", "key": "test_key", "value": "0", "ns": '123abc'}),
                'exception': ValueError,
                'raised': True
            }
        ]

        for case in test_cases:
            try:
                item = ItemValue(**case['input'])
            except ValueError:
                if not case['raised']:
                    self.fail(f"raised unexpected ValueError for input data: {case['input']}")
            else:
                if case['raised']:
                    self.fail(f"not raised expected ValueError for input data: {case['input']}")

                self.assertEqual(str(item), case['output'],
                                 f"unexpected output with input data: {case['input']}")
                
                self.assertEqual(str(item), repr(item),
                                 f"unexpected output with input data: {case['input']}")


if __name__ == '__main__':
    unittest.main()