import unittest
from typing import Union, get_type_hints

from zabbix_utils.getter import Getter
from zabbix_utils.types import AgentResponse


class TestGetterAnnotations(unittest.TestCase):
    def test_get_annotations_match_supported_payloads_and_response(self):
        hints = get_type_hints(Getter.get)

        self.assertEqual(hints["key"], Union[bytes, str, list, dict])
        self.assertIs(hints["return"], AgentResponse)


if __name__ == "__main__":
    unittest.main()
