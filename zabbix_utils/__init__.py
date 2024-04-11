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

from .api import ZabbixAPI
from .sender import Sender
from .getter import Getter
from .types import ItemValue, APIVersion
from .exceptions import ModuleBaseException, APIRequestError, APINotSupported, ProcessingError

from .aiosender import AsyncSender
from .aiogetter import AsyncGetter
try:
    __import__('aiohttp')
except ModuleNotFoundError:
    class AsyncZabbixAPI():
        def __init__(self, *args, **kwargs):
            raise ModuleNotFoundError("No module named 'aiohttp'")
else:
    from .aioapi import AsyncZabbixAPI

__all__ = (
    'ZabbixAPI',
    'AsyncZabbixAPI',
    'APIVersion',
    'Sender',
    'AsyncSender',
    'ItemValue',
    'Getter',
    'AsyncGetter',
    'ModuleBaseException',
    'APIRequestError',
    'APINotSupported',
    'ProcessingError'
)
