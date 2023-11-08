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
import ssl
import json
import base64
import logging
import urllib.request as ul

from uuid import uuid4
from os import environ as env
from urllib.error import URLError

from typing import Callable, Union, Any, List
# For Python less 3.11 compatibility
try:
    from typing import Self  # type: ignore
except ImportError:
    from typing_extensions import Self

from .utils import ZabbixAPIUtils
from .logger import EmptyHandler, SensitiveFilter
from .exceptions import ZabbixAPIException, ZabbixAPINotSupported, ZabbixProcessingException
from .version import __version__, __min_supported__, __max_supported__


log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())
log.addFilter(SensitiveFilter())


class ZabbixAPIObject():
    """Zabbix API object.

    Args:
        name (str): Zabbix API object name.
        parent (class): Zabbix API parent of the object.
    """

    def __init__(self, name: str, parent: Callable):
        self.object = name
        self.parent = parent

    def __getattr__(self, name: str) -> Callable:
        """Dynamic creation of an API method.

        Args:
            name (str): Zabbix API object method name.

        Raises:
            TypeError: Raises if gets unexpected arguments.

        Returns:
            Self: Zabbix API method.
        """

        def func(*args: Any, **kwargs: Any) -> Any:
            if args and kwargs:
                raise TypeError("Only args or kwargs should be used.")

            method = f'{self.object}.{name}'

            log.debug("Executing %s method", method)

            need_auth = not (method in ZabbixAPIUtils.UNAUTH_METHODS)

            return self.parent.send_api_request(
                method,
                args or kwargs,
                need_auth
            ).get('result')

        return func


class ZabbixAPIVersion():
    """Zabbix API version object.

    Args:
        apiver (str): Raw version in string format.
    """

    def __init__(self, apiver: str):
        self.__raw = apiver
        self.first, self.second, self.third = self.__parse_version(self.__raw)

    def __getitem__(self, index: int) -> Any:
        return self.__raw[index]

    def is_lts(self) -> bool:
        """Check if the current version is LTS.

        Returns:
            bool: `True` if the current version is LTS.
        """

        return self.second == 0

    @property
    def major(self) -> float:
        """Get major version number.

        Returns:
            float: A major version number.
        """

        return float(f"{self.first}.{self.second}")

    @property
    def minor(self) -> int:
        """Get minor version number.

        Returns:
            int: A minor version number.
        """

        return self.third

    def __parse_version(self, ver: str) -> List[Any]:
        regexp = r"(\d+)\.(\d+)\.(\d+).*"
        try:
            result = list(map(int, re.search(regexp, ver).groups()))
            return result
        except AttributeError:
            raise TypeError(
                f"Unable to parse version of Zabbix API: {ver}. " +
                f"Default '{__max_supported__}.0' format is expected."
            ) from None

    def __str__(self) -> str:
        return self.__raw

    def __repr__(self) -> str:
        return self.__raw

    def __eq__(self, other: Union[float, str]) -> bool:
        if isinstance(other, float):
            return self.major == other

        return str(self.__parse_version(self.__raw)) == str(self.__parse_version(other))

    def __gt__(self, other: Union[float, str]) -> bool:
        if isinstance(other, float):
            return self.major > other
        if isinstance(other, str):
            return [self.first, self.second, self.third] > self.__parse_version(other)
        raise TypeError(
            f"'>' not supported between instances of '{type(self).__name__}' and \
'{type(other).__name__}', only 'float' or 'str' is expected"
        )

    def __lt__(self, other: Union[float, str]) -> bool:
        if isinstance(other, float):
            return self.major < other
        if isinstance(other, str):
            return [self.first, self.second, self.third] < self.__parse_version(other)
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


class ZabbixAPI():
    """Provide interface for working with Zabbix API.

    Args:
        url (str, optional): Zabbix API URL. Defaults to `http://localhost/zabbix/api_jsonrpc.php`.

        token (str, optional): Zabbix API token. Defaults to `None`.

        user (str, optional): Zabbix API username. Defaults to `None`.

        password (str, optional): Zabbix API user's password. Defaults to `None`.

        http_user (str, optional): Basic Authentication username. Defaults to `None`.

        http_password (str, optional): Basic Authentication password. Defaults to `None`.

        skip_version_check (bool, optional): Skip version compatibility check. Defaults to `False`.

        validate_certs (bool, optional): Specifying certificate validation. Defaults to `True`.

        timeout (int, optional): Connection timeout to Zabbix API. Defaults to `30`.
    """

    def __init__(self, url: Union[str, None] = None, token: Union[str, None] = None,
                 user: Union[str, None] = None, password: Union[str, None] = None,
                 http_user: Union[str, None] = None, http_password: Union[str, None] = None,
                 skip_version_check: bool = False, validate_certs: bool = True, timeout: int = 30):

        url = url or env.get('ZABBIX_URL') or 'http://localhost/zabbix/api_jsonrpc.php'
        user = user or env.get('ZABBIX_USER') or None
        password = password or env.get('ZABBIX_PASSWORD') or None

        self._token = token or env.get('ZABBIX_TOKEN') or None
        self.url = ZabbixAPIUtils.check_url(url)
        self.validate_certs = validate_certs
        self.timeout = timeout
        self.session_id = None
        self.use_basic = False
        self.basic_cred = None

        if http_user and http_password:
            self.basic_auth(http_user, http_password)

        self._version = self.api_version()

        # Check version compatibility
        self.__check_version(skip_version_check)

        if self._version < 5.4 and self._token and not (user and password):
            raise ZabbixAPINotSupported(
                message="Token usage",
                version=self._version
            )
        if self._token or (user and password):
            self.__login(user, password)
            log.debug("Connected to Zabbix API version %s: %s", self._version, self.url)

    def __getattr__(self, name: str) -> Callable:
        """Dynamic creation of an API object.

        Args:
            name (str): Zabbix API method name.

        Returns:
            ZabbixAPIObject: Zabbix API object instance.
        """

        return ZabbixAPIObject(name, self)

    def __login(self, user: str, password: str) -> None:
        user_cred = {
            "username": user,
            "password": password
        }

        if self._version < 6.4:
            user_cred = {
                "user": user,
                "password": password
            }

        if self._token and self._version >= 5.4:
            log.debug("Login to Zabbix API using token:%s", ZabbixAPIUtils.secreter(self._token))
            self.session_id = self._token
            return

        log.debug(
            "Login to Zabbix API using username:%s password:%s", user, ZabbixAPIUtils.HIDINGMASK
        )
        self.session_id = self.user.login(**user_cred)

    def __logout(self) -> None:
        if self.session_id:
            if self.session_id == self._token:
                self.session_id = None
                self._token = None
                return

            log.debug("Logout from Zabbix API")

            if self.user.logout():
                self.session_id = None
                self._token = None
        else:
            log.debug("You're not logged in Zabbix API")

    def __refresh_auth(self, session_id: str) -> dict:
        if session_id:
            if session_id == self._token:
                log.debug("Refresh auth session using token in Zabbix API")
                return self.user.checkAuthentication(token=session_id)

            log.debug("Refresh auth session using sessionid in Zabbix API")
            return self.user.checkAuthentication(sessionid=session_id)
        else:
            log.debug("You're not logged in Zabbix API")

        return {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.__logout()

    @property
    def version(self) -> ZabbixAPIVersion:
        """Return object of Zabbix API version.

        Returns:
            ZabbixAPIVersion: Object of Zabbix API version.
        """

        return self._version

    def api_version(self) -> ZabbixAPIVersion:
        """Get raw version of Zabbix API.

        Returns:
            ZabbixAPIVersion: Object of Zabbix API version
        """

        return ZabbixAPIVersion(self.apiinfo.version())

    def login(self, token: Union[str, None] = None, user: Union[str, None] = None,
              password: Union[str, None] = None) -> Self:
        """Login to Zabbix API.

        Args:
            token (str, optional): Zabbix API token. Defaults to `None`.

            user (str, optional): Zabbix API username. Defaults to `None`.

            password (str, optional): Zabbix API user's password. Defaults to `None`.

        Returns:
            ZabbixAPI: Zabbix API instance.
        """

        if self._version < 5.4 and token:
            raise ZabbixAPINotSupported(
                message="Token usage",
                version=self._version
            )
        if (not (token or (user and password))) or (token and user and password):
            raise ZabbixProcessingException(
                "Either a token or a user and a password must be specified")

        self._token = token
        self.__login(user, password)
        log.debug("Connected to Zabbix API version %s: %s", self._version, self.url)

        return self

    def logout(self) -> None:
        """Logout from Zabbix API."""

        self.__logout()

    def basic_auth(self, user: str, password: str) -> Self:
        """Enable Basic Authentication using.

        Args:
            user (str): Basic Authentication username.

            password (str): Basic Authentication password.

        Returns:
            ZabbixAPI: Zabbix API instance.
        """

        log.debug(
            "Enable Basic Authentication with username:%s password:%s",
            user,
            ZabbixAPIUtils.HIDINGMASK
        )

        self.use_basic = True
        self.basic_cred = base64.b64encode(
            f"{user}:{password}".encode()
        ).decode()

        return self

    def check_auth(self) -> bool:
        """Check authentication status in Zabbix API.

        Returns:
            bool: User authentication status (`True`, `False`)
        """

        refresh_resp = self.__refresh_auth(self.session_id).get('userid')

        return bool(refresh_resp)

    def send_api_request(self, method: str, params: Union[dict, None] = None,
                         need_auth=True) -> dict:
        """Function for sending request to Zabbix API.

        Args:
            method (str): Zabbix API method name.

            params (dict, optional): Params for request body. Defaults to `None`.

            need_auth (bool, optional): Authorization using flag. Defaults to `False`.

        Raises:
            ZabbixProcessingException: Wrapping built-in exceptions during request processing.

            ZabbixAPIException: Wrapping errors from Zabbix API.

        Returns:
            dict: Dictionary with Zabbix API response.
        """

        request_json = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {},
            'id': str(uuid4()),
        }

        req = ul.Request(self.url)

        if need_auth and self.session_id:
            if self._version < 6.4 or self.use_basic:
                request_json['auth'] = self.session_id
            else:
                req.add_header("Authorization", f"Bearer {self.session_id}")
        elif need_auth:
            raise ZabbixProcessingException("You're not logged in Zabbix API")

        if self.use_basic:
            req.add_header("Authorization", f"Basic {self.basic_cred}")

        data = json.dumps(request_json)

        log.debug(
            "Sending request to %s with body:%s",
            self.url,
            json.dumps(request_json)
        )

        req.data = data.encode("utf-8")
        req.get_method = lambda: 'POST'
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json-rpc')
        req.add_header('User-Agent', f"{__name__}/{__version__}")
        req.timeout = self.timeout

        if not self.validate_certs:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = None

        try:
            resp = ul.urlopen(req, context=ctx)
            resp_json = json.loads(resp.read().decode('utf-8'))
        except URLError as err:
            raise ZabbixProcessingException(f"Unable to connect to {self.url}:", err) from None
        except ValueError as err:
            raise ZabbixProcessingException("Unable to parse json:", err) from None

        if method not in ZabbixAPIUtils.FILES_METHODS:
            log.debug(
                "Received response body: %s",
                json.dumps(resp_json, indent=4, separators=(',', ': '))
            )
        else:
            debug_json = resp_json.copy()
            if debug_json.get('result'):
                debug_json['result'] = ZabbixAPIUtils.cutter(debug_json['result'], 100)
            log.debug(
                "Received response body (cutted): %s",
                json.dumps(debug_json, indent=4, separators=(',', ': '))
            )

        if 'error' in resp_json:
            err = resp_json['error'].copy()
            err['body'] = json.dumps(request_json)
            raise ZabbixAPIException(err)

        return resp_json

    def __check_version(self, skip_check: bool) -> None:
        if self._version < __min_supported__:
            if skip_check:
                log.debug(
                    "Version of Zabbix API [%s] is less than the library supports. %s",
                    self._version,
                    "Further library use at your own risk!"
                )
            else:
                raise ZabbixAPINotSupported(
                    f"Version of Zabbix API [{self._version}] is not supported by the library. " +
                    f"The oldest supported version is {__min_supported__}.0"
                )

        if self._version > __max_supported__:
            if skip_check:
                log.debug(
                    "Version of Zabbix API [%s] is more than the library was tested on. %s",
                    self._version,
                    "Recommended to update the library. Further library use at your own risk!"
                )
            else:
                raise ZabbixAPINotSupported(
                    f"Version of Zabbix API [{self._version}] was not tested with the library. " +
                    f"The latest tested version is {__max_supported__}.0"
                )
