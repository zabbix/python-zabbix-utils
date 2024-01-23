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

from typing import Union

from .common import ModuleUtils


class ModuleBaseException(Exception):
    pass


class APIRequestError(ModuleBaseException):
    """Exception class when Zabbix API returns error by request.

    Args:
        api_error (str|dict): Raw error message from Zabbix API.
    """
    def __init__(self, api_error: Union[str, dict]):
        if isinstance(api_error, dict):
            api_error['body'] = ModuleUtils.hide_private(api_error['body'])
            super().__init__("{message} {data}".format(**api_error))
            for key, value in api_error.items():
                setattr(self, key, value)
        else:
            super().__init__(api_error)


class APINotSupported(ModuleBaseException):
    """Exception class when object/action is not supported by Zabbix API.

    Args:
        message (str): Not supported object/action message.

        version (str): Current version of Zabbix API.
    """

    def __init__(self, message: str, version: str = None):
        if version:
            message = f"{message} is unsupported for Zabbix {version} version"
        super().__init__(message)


class ProcessingError(ModuleBaseException):
    def __init__(self, *args):
        super().__init__(" ".join(map(str, args)))
        return
