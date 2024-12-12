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

import re
import json
from typing import Union, Any, List
from decimal import Decimal

from .exceptions import ProcessingError

from .version import __max_supported__


class APIVersion():
    """Zabbix API version object.

    Args:
        apiver (str): Raw version in string format.
    """

    def __init__(self, apiver: str):
        self.__raw = apiver
        self.__first, self.__second, self.__third = self.__parse_version(self.__raw)

    def __getitem__(self, index: int) -> Any:
        # Get a symbol from the raw version string by index
        # For compatibility with using Zabbix version as a string
        return self.__raw[index]

    def is_lts(self) -> bool:
        """Check if the current version is LTS.

        Returns:
            bool: `True` if the current version is LTS.
        """

        return self.__second == 0

    @property
    def major(self) -> float:
        """Get major version number.

        Returns:
            float: A major version number.
        """

        return float(f"{self.__first}.{self.__second}")

    @property
    def minor(self) -> int:
        """Get minor version number.

        Returns:
            int: A minor version number.
        """

        return self.__third

    def __parse_version(self, ver: str) -> List[Any]:
        # Parse the version string into a list of integers.
        match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', ver)
        if match is None:
            raise ValueError(
                f"Unable to parse version of Zabbix API: {ver}. " +
                f"Default '{__max_supported__}.0' format is expected."
            ) from None
        return list(map(int, match.groups()))

    def __str__(self) -> str:
        return self.__raw

    def __repr__(self) -> str:
        return self.__raw

    def __eq__(self, other: Union[float, str]) -> bool:
        if isinstance(other, float):
            return self.major == other
        if isinstance(other, str):
            return [self.__first, self.__second, self.__third] == self.__parse_version(other)
        raise TypeError(
            f"'==' not supported between instances of '{type(self).__name__}' and \
'{type(other).__name__}', only 'float' or 'str' is expected"
        )

    def __gt__(self, other: Union[float, str]) -> bool:
        if isinstance(other, float):
            return self.major > other
        if isinstance(other, str):
            return [self.__first, self.__second, self.__third] > self.__parse_version(other)
        raise TypeError(
            f"'>' not supported between instances of '{type(self).__name__}' and \
'{type(other).__name__}', only 'float' or 'str' is expected"
        )

    def __lt__(self, other: Union[float, str]) -> bool:
        if isinstance(other, float):
            return self.major < other
        if isinstance(other, str):
            return [self.__first, self.__second, self.__third] < self.__parse_version(other)
        raise TypeError(
            f"'<' not supported between instances of '{type(self).__name__}' and \
'{type(other).__name__}', only 'float' or 'str' is expected"
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __ge__(self, other: Any) -> bool:
        return not self.__lt__(other)

    def __le__(self, other: Any) -> bool:
        return not self.__gt__(other)


class TrapperResponse():
    """Contains response from Zabbix server/proxy.

    Args:
        chunk (int, optional): Current chunk number. Defaults to `1`.
    """

    def __init__(self, chunk: int = 1):
        self.__processed = 0
        self.__failed = 0
        self.__total = 0
        self.__time = 0
        self.__chunk = chunk
        self.details = None

    def __repr__(self) -> str:
        result = {}
        for key, value in self.__dict__.items():
            if key == 'details':
                continue
            result[
                key[len(f"_{self.__class__.__name__}__"):]
            ] = str(value) if isinstance(value, Decimal) else value

        return json.dumps(result)

    def parse(self, response: dict) -> dict:
        """Parse response from Zabbix.

        Args:
            response (dict): Raw response from Zabbix.

        Raises:
            ProcessingError: Raises if unexpected response received
        """

        fields = {
            "processed": ('[Pp]rocessed', r'\d+'),
            "failed": ('[Ff]ailed', r'\d+'),
            "total": ('[Tt]otal', r'\d+'),
            "time": ('[Ss]econds spent', r'\d+\.\d+')
        }

        pattern = re.compile(
            r";\s+?".join([rf"{r[0]}:\s+?(?P<{k}>{r[1]})" for k, r in fields.items()])
        )

        info = response.get('info')
        if not info:
            raise ProcessingError(f"Received unexpected response: {response}")

        res = pattern.search(info).groupdict()

        return res

    def add(self, response: dict, chunk: Union[int, None] = None):
        """Add and merge response data from Zabbix.

        Args:
            response (dict): Raw response from Zabbix.
            chunk (int, optional): Chunk number. Defaults to `None`.
        """

        resp = self.parse(response)

        def add_value(cls, key, value):
            setattr(
                cls,
                key,
                getattr(cls, key) + value
            )

        for k, v in resp.items():
            add_value(
                self,
                f"_{self.__class__.__name__}__{k}",
                Decimal(v) if '.' in v else int(v)
            )
        if chunk is not None:
            self.__chunk = chunk

        return self

    @property
    def processed(self) -> int:
        """Returns number of processed packets.

        Returns:
            int: Number of processed packets.
        """

        return self.__processed

    @property
    def failed(self) -> int:
        """Returns number of failed packets.

        Returns:
            int: Number of failed packets.
        """

        return self.__failed

    @property
    def total(self) -> int:
        """Returns total number of packets.

        Returns:
            int: Total number of packets.
        """

        return self.__total

    @property
    def time(self) -> int:
        """Returns value of spent time.

        Returns:
            int: Spent time for the packets sending.
        """

        return self.__time

    @property
    def chunk(self) -> int:
        """Returns current chunk number.

        Returns:
            int: Number of the current chunk.
        """

        return self.__chunk


class ItemValue():
    """Contains data of a single item value.

    Args:
        host (str): Specify host name the item belongs to (as registered in Zabbix frontend).
        key (str): Specify item key to send value to.
        value (str): Specify item value.
        clock (int, optional): Specify time in Unix timestamp format. Defaults to `None`.
        ns (int, optional): Specify time expressed in nanoseconds. Defaults to `None`.
    """

    def __init__(self, host: str, key: str, value: str,
                 clock: Union[int, None] = None, ns: Union[int, None] = None):
        self.host = str(host)
        self.key = str(key)
        self.value = str(value)
        self.clock = None
        self.ns = None

        if clock is not None:
            try:
                self.clock = int(clock)
            except ValueError:
                raise ValueError(
                    'The clock value must be expressed in the Unix Timestamp format') from None

        if ns is not None:
            try:
                self.ns = int(ns)
            except ValueError:
                raise ValueError(
                    'The ns value must be expressed in the integer value of nanoseconds') from None

    def __str__(self) -> str:
        return json.dumps(self.to_json(), ensure_ascii=False)

    def __repr__(self) -> str:
        return self.__str__()

    def to_json(self) -> dict:
        """Represents ItemValue object in dictionary for json.

        Returns:
            dict: Object attributes in dictionary.
        """

        return {k: v for k, v in self.__dict__.items() if v is not None}


class Node():
    """Contains one Zabbix node object.

    Args:
        addr (str): Listen address of Zabbix server.
        port (int, str): Listen port of Zabbix server.

    Raises:
        TypeError: Raises if not integer value was received.
    """

    def __init__(self, addr: str, port: Union[int, str]):
        self.address = addr if addr != '0.0.0.0/0' else '127.0.0.1'
        try:
            self.port = int(port)
        except ValueError:
            raise TypeError('Port must be an integer value') from None

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"

    def __repr__(self) -> str:
        return self.__str__()


class Cluster():
    """Contains Zabbix node objects in a cluster object.

    Args:
        addr (list): Raw list of node addresses.
    """

    def __init__(self, addr: list):
        self.nodes = self.__parse_ha_node(addr)

    def __parse_ha_node(self, node_list: list) -> list:
        nodes = []
        for node_item in node_list:
            node_item = node_item.strip()
            if ':' in node_item:
                nodes.append(Node(*node_item.split(':')))
            else:
                nodes.append(Node(node_item, '10051'))

        return nodes

    def __str__(self) -> str:
        return json.dumps([(node.address, node.port) for node in self.nodes])

    def __repr__(self) -> str:
        return self.__str__()


class AgentResponse:
    """Contains response from Zabbix agent/agent2.

    Args:
        response (string): Raw response from Zabbix.
    """

    def __init__(self, response: str):
        error_code = 'ZBX_NOTSUPPORTED'
        self.raw = response
        if response == error_code:
            self.value = None
            self.error = 'Not supported by Zabbix Agent'
        elif response.startswith(error_code + '\0'):
            self.value = None
            self.error = response[len(error_code)+1:]
        else:
            idx = response.find('\0')
            if idx == -1:
                self.value = response
            else:
                self.value = response[:idx]
            self.error = None

    def __repr__(self) -> str:
        return json.dumps({
            'error': self.error,
            'raw': self.raw,
            'value': self.value,
        })
