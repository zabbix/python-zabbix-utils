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
from typing import Match


class ZabbixAPIUtils():

    # Hidding mask for sensitive data
    HIDINGMASK = "*"*8

    # The main php-file of Zabbix API
    JSONRPC_FILE = 'api_jsonrpc.php'

    # Methods working without auth token
    UNAUTH_METHODS = ('apiinfo.version', 'user.login', 'user.checkAuthentication')

    # Methods returning files contents
    FILES_METHODS = ('configuration.export')

    # List of private fields
    PRIVATE_FIELDS = {
        "token": "[A-Za-z0-9]+",
        "auth": "[A-Za-z0-9]+",
        "sessionid": "[A-Za-z0-9]+",
        "password": "[^'\"]+",
        "result": "[A-Za-z0-9]+"
    }

    @classmethod
    def check_url(cls, url: str) -> str:
        """Check url completeness

        Args:
            url (str): Unchecked URL of Zabbix API

        Returns:
            str: Checked URL of Zabbix API
        """

        if '/' + cls.JSONRPC_FILE not in url:
            url += cls.JSONRPC_FILE if url[-1] == '/' else '/' + cls.JSONRPC_FILE
        if 'http' != url[:4]:
            url = 'http://' + url

        return url

    @classmethod
    def secreter(cls, string: str, show_len: int = 4) -> str:
        """Replace the most part of string to hiding mask.

        Args:
            string (str): Raw string with without hiding.

            show_len (int, optional): Number of signs shown on each side of the string. \
Defaults to 4.

        Returns:
            str: String with hiding part.
        """

        if len(string) <= 16 or (show_len + 4) >= 16:
            return cls.HIDINGMASK
        if show_len == 0:
            return string

        return f"{string[:show_len]}{cls.HIDINGMASK}{string[0-show_len:]}"

    @classmethod
    def cutter(cls, string: str, max_len: int = 255, dots: bool = True) -> str:
        """Cut a part of received text with 'max_len' length.

        Args:
            string (str): Raw string with without cutting.

            max_len (int, optional): Maximal length of result. Defaults to 255.

            dots (bool, optional): Specifying adding three dots at the end. Defaults to True.

        Returns:
            str: [description]
        """

        if len(string) <= max_len:
            return string

        return string[0:max_len] + ('...' if dots else '')

    @classmethod
    def hide_private(cls, message: str, fields: dict = None) -> str:
        """Hide private data Zabbix info (e.g. token, password)

        Args:
            message (str): Message text with private data.

            fields (dict): Dictionary of private fields and their seeking regexps.

        Returns:
            str: Message text without private data.
        """

        private_fields = fields if fields else cls.PRIVATE_FIELDS

        def gen_repl(match: Match):
            return cls.secreter(match.group(0))

        pattern = re.compile(
            r"|".join([rf"((?<=[\"']{f}[\"']:\s[\"']){r})" for f, r in private_fields.items()])
        )

        return re.sub(pattern, gen_repl, message)
