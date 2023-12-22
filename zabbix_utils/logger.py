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
import logging
from .common import ModuleUtils


class EmptyHandler(logging.Handler):
    """Empty logging handler."""

    def emit(self, *args, **kwargs):
        pass


class SensitiveFilter(logging.Filter):
    """Filter to hide sensitive Zabbix info (password, auth) in logs"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __hide_data(self, raw_data):
        return json.dumps(ModuleUtils.hide_private(raw_data), indent=4, separators=(',', ': '))

    def filter(self, record):
        if isinstance(record.args, tuple):
            record.args = tuple(self.__hide_data(arg)
                                if isinstance(arg, dict) else arg for arg in record.args)
        if isinstance(record.args, dict):
            record.args = self.__hide_data(record.args)

        return 1
