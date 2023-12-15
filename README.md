# Zabbix utils library

[![Tests](https://github.com/zabbix/python-zabbix-utils/actions/workflows/tests.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/tests.yaml)
[![Zabbix API](https://github.com/zabbix/python-zabbix-utils/actions/workflows/integration_api.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/integration_api.yaml)
[![Zabbix sender](https://github.com/zabbix/python-zabbix-utils/actions/workflows/integration_sender.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/integration_sender.yaml)
[![Zabbix get](https://github.com/zabbix/python-zabbix-utils/actions/workflows/integration_get.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/integration_get.yaml)
[![Zabbix 5.0](https://github.com/zabbix/python-zabbix-utils/actions/workflows/compatibility_50.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/compatibility_50.yaml)
[![Zabbix 6.0](https://github.com/zabbix/python-zabbix-utils/actions/workflows/compatibility_60.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/compatibility_60.yaml)
[![Zabbix 6.4](https://github.com/zabbix/python-zabbix-utils/actions/workflows/compatibility_64.yaml/badge.svg)](https://github.com/zabbix/python-zabbix-utils/actions/workflows/compatibility_64.yaml)

**zabbix_utils** is a Python library for working with [Zabbix API](https://www.zabbix.com/documentation/current/manual/api/reference) as well as with [Zabbix sender](https://www.zabbix.com/documentation/current/manpages/zabbix_sender) and [Zabbix get](https://www.zabbix.com/documentation/current/manpages/zabbix_get) protocols.

## Get started
* [Requirements](#requirements)
* [Installation](#installation)
* [Zabbix API](#to-work-with-zabbix-api)
* [Zabbix Sender](#to-work-via-zabbix-sender-protocol)
* [Zabbix Get](#to-work-via-zabbix-get-protocol)
* [Debug log](#enabling-debug-log)

## Requirements

Supported versions:

* Zabbix 5.0+
* Python 3.8+

Tested on:

* Zabbix 5.0, 6.0, 6.4 and 7.0.0 alpha 7
* Python 3.8, 3.9, 3.10 and 3.11

## Documentation

### Installation

Install **zabbix_utils** library using pip:

```bash
$ pip install zabbix_utils
```

### Use cases

##### To work with Zabbix API

To work with Zabbix API you can import and use **zabbix_utils** library as follows:

```python
from zabbix_utils import ZabbixAPI

api = ZabbixAPI(url="127.0.0.1")
api.login(user="User", password="zabbix")

users = api.user.get(
    output=['userid','name']
)

for user in users:
    print(user['name'])

api.logout()
```

You can also authenticate using an API token (supported since Zabbix 5.4):

```python
from zabbix_utils import ZabbixAPI

api = ZabbixAPI(url="127.0.0.1")
api.login(token="xxxxxxxx")

users = api.user.get(
    output=['userid','name']
)

for user in users:
    print(user['name'])
```

When token is used, calling `api.logout()` is not necessary.

It is possible to specify authentication fields by the following environment variables:
`ZABBIX_URL`, `ZABBIX_TOKEN`, `ZABBIX_USER`, `ZABBIX_PASSWORD`

You can compare Zabbix API version with strings and numbers, for example:

```python
from zabbix_utils import ZabbixAPI

url = "127.0.0.1"
user = "User"
password = "zabbix"

api = ZabbixAPI(url=url, user=user, password=password)

# Method to get version
ver = api.api_version()
print(type(ver).__name__, ver) # APIVersion 7.0.0

# ZabbixAPI prototype with version
ver = api.version
print(type(ver).__name__, ver) # APIVersion 7.0.0

# Comparing versions
print(ver > 6.0)      # True
print(ver != 7.0)     # False
print(ver != "7.0.0") # False

# Version additional methods
print(ver.major)    # 7.0
print(ver.minor)    # 0
print(ver.is_lts()) # True

api.logout()
```

In case the API object or method name matches one of Python keywords, you can use the suffix `_` in their name to execute correctly:
```python
from zabbix_utils import ZabbixAPI

api = ZabbixAPI(url="127.0.0.1")
api.login(token="xxxxxxxx")

template_source = ''
with open('template_example.xml', mode='r', encoding='utf-8') as f:
    template_source = f.read()

response = api.configuration.import_(
    source=template_source,
    format="xml",
    rules={...}
)

if response:
    print("Template imported successfully")
```

> Please, refer to the [Zabbix API Documentation](https://www.zabbix.com/documentation/current/manual/api/reference) and the [using examples](https://github.com/zabbix/python-zabbix-utils/tree/main/examples/api) for more information.

##### To work via Zabbix sender protocol

To send item values to a Zabbix server or a Zabbix proxy you can import and use the library as follows:

```python
from zabbix_utils import Sender

sender = Sender(server='127.0.0.1', port=10051)
resp = sender.send_value('host', 'item.key', 'value', 1695713666)

print(resp)
# {"127.0.0.1:10051": {"processed": 1, "failed": 0, "total": 1, "time": "0.000338", "chunk": 1}}
```

Or you can prepare a list of item values and send all at once:

```python
from zabbix_utils import ItemValue, Sender

items = [
    ItemValue('host1', 'item.key1', 10),
    ItemValue('host1', 'item.key2', 'test message'),
    ItemValue('host2', 'item.key1', -1, 1695713666),
    ItemValue('host3', 'item.key1', '{"msg":"test message"}'),
    ItemValue('host2', 'item.key1', 0, 1695713666, 100)
]

sender = Sender(server='127.0.0.1', port=10051)
response = sender.send(items)

print(response)
# {"127.0.0.1:10051": {"processed": 5, "failed": 0, "total": 5, "time": "0.001661", "chunk": 1}}
```

> Please, refer to the [Zabbix sender protocol](https://www.zabbix.com/documentation/current/manual/appendix/protocols/zabbix_sender) and the [using examples](https://github.com/zabbix/python-zabbix-utils/tree/main/examples/sender) for more information.

##### To work via Zabbix get protocol

To get a value by item key from a Zabbix agent or agent 2 you can import and use the library as follows:

```python
from zabbix_utils import Getter

agent = Getter(host='127.0.0.1', port=10050)
resp = agent.get('system.uname')

print(resp)
# Linux test_server 5.15.0-3.60.5.1.el9uek.x86_64
```

> Please, refer to the [Zabbix agent protocol](https://www.zabbix.com/documentation/current/manual/appendix/protocols/zabbix_agent) and the [using examples](https://github.com/zabbix/python-zabbix-utils/tree/main/examples/get) for more information.

### Enabling debug log

If it needed to debug some issue with Zabbix API, sender or get you can enable the output of logging. The **zabbix_utils** library uses the default python logging module, but it doesn't log by default. You can define logging handler to see records from the library, for example:

```python
import logging
from zabbix_utils import Getter

logging.basicConfig(
    format=u'[%(asctime)s] %(levelname)s %(message)s',
    level=logging.DEBUG
)

agent = Getter(host='127.0.0.1', port=10050)
resp = agent.get('system.uname')

print(resp)
```

And then you can see records like the following:

```
[2023-10-01 12:00:01,587] DEBUG Content of the packet: b'ZBXD\x01\x0c\x00\x00\x00\x00\x00\x00\x00system.uname'
[2023-10-01 12:00:01,722] DEBUG Zabbix response header: b'ZBXD\x01C\x00\x00\x00C\x00\x00\x00'
[2023-10-01 12:00:01,723] DEBUG Zabbix response body: Linux test_server 5.15.0-3.60.5.1.el9uek.x86_64
[2023-10-01 12:00:01,724] DEBUG Response from [127.0.0.1:10050]: Linux test_server 5.15.0-3.60.5.1.el9uek.x86_64
Linux test_server 5.15.0-3.60.5.1.el9uek.x86_64

```

## License
**zabbix_utils** is distributed under MIT License.
