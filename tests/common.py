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

import ssl
import json

from zabbix_utils.types import ItemValue
from zabbix_utils.version import __min_supported__, __max_supported__


API_DEFAULTS = {
    'user': 'Admin',
    'password': 'zabbix',
    'token': 'oTmtWu',
    'session': 'cc364fb50199c5e305aa91785b7e49a0',
    'max_version': "{}.0".format(__max_supported__ + .2),
    'min_version': "{}.0".format(__min_supported__ - .2)
}


GETTER_DEFAULTS = {
    'host': 'localhost',
    'port': 10050,
    'source_ip': '192.168.1.1'
}

SENDER_DEFAULTS = {
    'server': 'localhost',
    'port': 10051,
    'source_ip': '192.168.1.1',
    'clusters': [
        ['zabbix.cluster.node1','zabbix.cluster.node2:20051'],
        ['zabbix.cluster2.node1','zabbix.cluster2.node2'],
        ['zabbix.domain']
    ]
}

ZABBIX_CONFIG = [
    f"""[root]
ServerActive=zabbix.cluster.node1;zabbix.cluster.node2:20051,zabbix.cluster2.node1;zabbix.cluster2.node2,zabbix.domain
Server={SENDER_DEFAULTS['server']}
SourceIP={SENDER_DEFAULTS['source_ip']}
TLSConnect=unencrypted
TLSAccept=unencrypted
""",
    f"""[root]
Server={SENDER_DEFAULTS['server']}
SourceIP={SENDER_DEFAULTS['source_ip']}
""",
    f"""[root]
SourceIP={SENDER_DEFAULTS['source_ip']}
"""
]


class MockBasicAuth():
    login = API_DEFAULTS['user']
    password = API_DEFAULTS['password']

class MockSessionConn():
    def __init__(self):
        self._ssl = None
        self.closed = False
    def close(self):
        self.closed = True

class MockSession():
    def __init__(self, exception=None):
        self._default_auth = None
        self._connector = MockSessionConn()
        self.EXC = exception
    def set_auth(self):
        self._default_auth = MockBasicAuth()
    def del_auth(self):
        self._default_auth = None
    def set_ssl(self, ssl):
        self._connector._ssl = ssl
    def del_ssl(self):
        self._connector._ssl = None
    def set_exception(self, exception):
        self.EXC = exception
    def del_exception(self):
        self.EXC = None
    async def close(self):
        pass
    async def post(self, *args, **kwargs):
        if self.EXC:
            raise self.EXC()
        return MockAPIResponse()


class MockAPIResponse():
    def __init__(self, exception=None):
        self.EXC = exception
    def set_exception(self, exception):
        self.EXC = exception
    def del_exception(self):
        self.EXC = None
    def raise_for_status(self):
        pass
    async def json(self, *args, **kwargs):
        if self.EXC:
            raise self.EXC()
        return {
            "jsonrpc": "2.0",
            "result": "{}.0".format(__max_supported__),
            "id": "0"
        }
    def read(self, *args, **kwargs):
        if self.EXC:
            raise self.EXC()
        return json.dumps({
            "jsonrpc": "2.0",
            "result": "{}.0".format(__max_supported__),
            "id": "0"
        }).encode('utf-8')


class MockConnector():
    def __init__(self, input_stream, exception=None):
        self.STREAM = input_stream
        self.EXC = exception
    def __raiser(self, *args, **kwargs):
        if self.EXC:
            raise self.EXC()
    def connect(self, *args, **kwargs):
        self.__raiser(*args, **kwargs)
    def recv(self, bufsize, *args, **kwargs):
        self.__raiser(*args, **kwargs)
        resp = self.STREAM[0:bufsize]
        self.STREAM = self.STREAM[bufsize:]
        return resp
    def sendall(self, *args, **kwargs):
        self.__raiser(*args, **kwargs)


class MockReader():
    STREAM = ''
    EXC = None
    @classmethod
    def set_stream(cls, stream):
        cls.STREAM = stream
    @classmethod
    def set_exception(cls, exception):
        cls.EXC = exception
    @classmethod
    async def readexactly(cls, length=0):
        if cls.EXC:
            raise cls.EXC()
        resp = cls.STREAM[0:length]
        cls.STREAM = cls.STREAM[length:]
        return resp
    @classmethod
    def close(cls):
        cls.EXC = None


class MockWriter():
    EXC = None
    @classmethod
    def set_exception(cls, exception):
        cls.EXC = exception
    @classmethod
    def write(cls, *args, **kwargs):
        if cls.EXC:
            raise cls.EXC()
    @classmethod
    async def drain(cls, *args, **kwargs):
        pass
    @classmethod
    def close(cls):
        cls.EXC = None
    @classmethod
    async def wait_closed(cls):
        cls.EXC = None

class MockLogger():
    def debug(self, *args, **kwargs):
        pass
    def error(self, *args, **kwargs):
        pass
    def warning(self, *args, **kwargs):
        pass

def mock_send_sync_request(self, method, *args, **kwargs):
    result = {}
    if method == 'apiinfo.version':
        result = f"{__max_supported__}.0"
    elif method == 'user.login':
        result = API_DEFAULTS['session']
    elif method == 'user.logout':
        result = True
    elif method == 'user.checkAuthentication':
        result = {'userid': 42}
    return {'jsonrpc': '2.0', 'result': result, 'id': 1}

async def mock_send_async_request(self, method, *args, **kwargs):
    result = {}
    if method == 'user.login':
        result = API_DEFAULTS['session']
    elif method == 'user.logout':
        result = True
    elif method == 'user.checkAuthentication':
        result = {'userid': 42}
    return {'jsonrpc': '2.0', 'result': result, 'id': 1}

def socket_wrapper(connection, *args, **kwargs):
    return connection

def ssl_context(*args, **kwargs):
    return ssl.create_default_context()

def response_gen(items):
    def items_check(items):
        for i, item in enumerate(items):
            if isinstance(item, ItemValue):
                items[i] = item.to_json()
        return items
    info = {
        'processed': len([i for i in items_check(items) if json.loads(i['value'])]),
        'failed': len([i for i in items_check(items) if not json.loads(i['value'])]),
        'total': len(items),
        'seconds spent': '0.000100'
    }
    result = {
        'response': 'success',
        'info': '; '.join([f"{k}: {v}" for k,v in info.items()])
    }

    return result
