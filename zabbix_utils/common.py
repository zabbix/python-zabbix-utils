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


class ModuleUtils():

    # Hidding mask for sensitive data
    HIDING_MASK = "*" * 8

    # The main php-file of Zabbix API
    JSONRPC_FILE = 'api_jsonrpc.php'

    # Methods working without auth token
    UNAUTH_METHODS = ('apiinfo.version', 'user.login', 'user.checkAuthentication')

    # Methods returning files contents
    FILES_METHODS = ('configuration.export',)

    # List of private fields
    PRIVATE_FIELDS = {
        "token": "[A-Za-z0-9]+",
        "auth": "[A-Za-z0-9]+",
        "sessionid": "[A-Za-z0-9]+",
        "password": "[^'\"]+",
        "result": "(?!(zabbix_export|[0-9.]{5}))[A-Za-z0-9]+",
    }

    @classmethod
    def check_url(cls, url: str) -> str:
        """Check url completeness

        Args:
            url (str): Unchecked URL of Zabbix API

        Returns:
            str: Checked URL of Zabbix API
        """

        if not url.endswith(cls.JSONRPC_FILE):
            url += cls.JSONRPC_FILE if url[-1] == '/' else '/' + cls.JSONRPC_FILE
        if not url.startswith('http'):
            url = 'http://' + url

        return url

    @classmethod
    def mask_secret(cls, string: str, show_len: int = 4) -> str:
        """Replace the most part of string to hiding mask.

        Args:
            string (str): Raw string with without hiding.
            show_len (int, optional): Number of signs shown on each side of the string. \
Defaults to 4.

        Returns:
            str: String with hiding part.
        """

        # If show_len is 0 or the length of the string is smaller than the hiding mask length
        # and show_len from both sides of the string, return only hiding mask.
        if show_len == 0 or len(string) <= (len(cls.HIDING_MASK) + show_len*2):
            return cls.HIDING_MASK

        # Return the string with the the hiding mask, surrounded by specified number of characters
        # shown on each side of the string.
        return f"{string[:show_len]}{cls.HIDING_MASK}{string[-show_len:]}"

    @classmethod
    def hide_private(cls, message: str, fields: dict = None) -> str:
        """Hide private data Zabbix info (e.g. token, password)

        Args:
            message (str): Message text with private data.
            fields (dict): Dictionary of private fields and their seeking regexps.

        Returns:
            str: Message text without private data.
        """

        # Use provided fields or default to class-level private fields.
        private_fields = fields if fields else cls.PRIVATE_FIELDS

        def gen_repl(match: Match):
            return cls.mask_secret(match.group(0))

        # Create a regular expression pattern by joining seeking regexps for private fields.
        pattern = re.compile(
            r"|".join([rf"((?<=[\"']{f}[\"']:\s[\"']){r})" for f, r in private_fields.items()])
        )

        # Use the regular expression pattern to replace occurrences of private data in the message.
        return re.sub(pattern, gen_repl, message)
