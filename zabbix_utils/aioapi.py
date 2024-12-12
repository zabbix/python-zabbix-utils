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
import base64
import aiohttp
import logging

from uuid import uuid4
import urllib.request as ul
from textwrap import shorten
from os import environ as env

from urllib.error import URLError
from typing import Callable, Union, Optional, Any
from aiohttp.client_exceptions import ContentTypeError

from .types import APIVersion
from .common import ModuleUtils
from .logger import EmptyHandler, SensitiveFilter
from .exceptions import APIRequestError, APINotSupported, ProcessingError
from .version import __version__, __min_supported__, __max_supported__

log = logging.getLogger(__name__)
log.addHandler(EmptyHandler())
log.addFilter(SensitiveFilter())


class APIObject():
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
            Callable: Zabbix API method.
        """

        # For compatibility with Python less 3.9 versions
        def removesuffix(string: str, suffix: str) -> str:
            return str(string[:-len(suffix)]) if suffix and string.endswith(suffix) else string

        async def func(*args: Any, **kwargs: Any) -> Any:
            if args and kwargs:
                await self.__exception(TypeError("Only args or kwargs should be used."))

            # Support '_' suffix to avoid conflicts with python keywords
            method = removesuffix(self.object, '_') + "." + removesuffix(name, '_')

            # Support passing list of ids and params as a dict
            params = kwargs or (
                (args[0] if type(args[0]) in (list, dict,) else list(args)) if args else None)

            log.debug("Executing %s method", method)

            need_auth = method not in ModuleUtils.UNAUTH_METHODS

            response = await self.parent.send_async_request(
                method,
                params,
                need_auth
            )
            return response.get('result')

        return func


class AsyncZabbixAPI():
    """Provide asynchronous interface for working with Zabbix API.

    Args:
        url (str, optional): Zabbix API URL. Defaults to `http://localhost/zabbix/api_jsonrpc.php`.
        http_user (str, optional): Basic Authentication username. Defaults to `None`.
        http_password (str, optional): Basic Authentication password. Defaults to `None`.
        skip_version_check (bool, optional): Skip version compatibility check. Defaults to `False`.
        validate_certs (bool, optional): Specifying certificate validation. Defaults to `True`.
        client_session (aiohttp.ClientSession, optional): Client's session. Defaults to `None`.
        timeout (int, optional): Connection timeout to Zabbix API. Defaults to `30`.
    """

    __version = None
    __use_token = False
    __session_id = None
    __internal_client = None

    def __init__(self, url: Optional[str] = None,
                 http_user: Optional[str] = None, http_password: Optional[str] = None,
                 skip_version_check: bool = False, validate_certs: bool = True,
                 client_session: Optional[aiohttp.ClientSession] = None, timeout: int = 30):

        url = url or env.get('ZABBIX_URL') or 'http://localhost/zabbix/api_jsonrpc.php'

        self.url = ModuleUtils.check_url(url)
        self.validate_certs = validate_certs
        self.timeout = timeout

        client_params: dict = {}

        if client_session is None:
            client_params["connector"] = aiohttp.TCPConnector(
                ssl=self.validate_certs
            )
            # HTTP Auth unsupported since Zabbix 7.2
            if http_user and http_password:
                client_params["auth"] = aiohttp.BasicAuth(
                    login=http_user,
                    password=http_password
                )
            self.__internal_client = aiohttp.ClientSession(**client_params)
            self.client_session = self.__internal_client
        else:
            if http_user and http_password:
                raise AttributeError(
                    "Parameters http_user/http_password shouldn't be used with client_session"
                )
            self.client_session = client_session

        self.__check_version(skip_version_check)

        if self.version > 7.0 and http_user and http_password:
            self.__close_session()
            raise APINotSupported("HTTP authentication unsupported since Zabbix 7.2.")

    def __getattr__(self, name: str) -> Callable:
        """Dynamic creation of an API object.

        Args:
            name (str): Zabbix API method name.

        Returns:
            APIObject: Zabbix API object instance.
        """

        return APIObject(name, self)

    async def __aenter__(self) -> Callable:
        return self

    async def __aexit__(self, *args) -> None:
        await self.logout()

    async def __aclose_session(self) -> None:
        if self.__internal_client:
            await self.__internal_client.close()

    async def __exception(self, exc) -> None:
        await self.__aclose_session()
        raise exc from exc

    def __close_session(self) -> None:
        if self.__internal_client:
            self.__internal_client._connector.close()

    def api_version(self) -> APIVersion:
        """Return object of Zabbix API version.

        Returns:
            APIVersion: Object of Zabbix API version
        """

        if self.__version is None:
            self.__version = APIVersion(
                self.send_sync_request('apiinfo.version', {}, False).get('result')
            )
        return self.__version

    @property
    def version(self) -> APIVersion:
        """Return object of Zabbix API version.

        Returns:
            APIVersion: Object of Zabbix API version.
        """

        return self.api_version()

    async def login(self, token: Optional[str] = None, user: Optional[str] = None,
                    password: Optional[str] = None) -> None:
        """Login to Zabbix API.

        Args:
            token (str, optional): Zabbix API token. Defaults to `None`.
            user (str, optional): Zabbix API username. Defaults to `None`.
            password (str, optional): Zabbix API user's password. Defaults to `None`.
        """

        user = user or env.get('ZABBIX_USER') or None
        password = password or env.get('ZABBIX_PASSWORD') or None
        token = token or env.get('ZABBIX_TOKEN') or None

        if token:
            if self.version < 5.4:
                await self.__exception(APINotSupported(
                    message="Token usage",
                    version=self.version
                ))
            if user or password:
                await self.__exception(
                    ProcessingError("Token cannot be used with username and password")
                )
            self.__use_token = True
            self.__session_id = token
            return

        if not user:
            await self.__exception(ProcessingError("Username is missing"))
        if not password:
            await self.__exception(ProcessingError("User password is missing"))

        if self.version < 5.4:
            user_cred = {
                "user": user,
                "password": password
            }
        else:
            user_cred = {
                "username": user,
                "password": password
            }

        log.debug(
            "Login to Zabbix API using username:%s password:%s", user, ModuleUtils.HIDING_MASK
        )
        self.__use_token = False
        self.__session_id = await self.user.login(**user_cred)

        log.debug("Connected to Zabbix API version %s: %s", self.version, self.url)

    async def logout(self) -> None:
        """Logout from Zabbix API."""

        if self.__session_id:
            if self.__use_token:
                self.__session_id = None
                self.__use_token = False
                await self.__aclose_session()
                return

            log.debug("Logout from Zabbix API")
            await self.user.logout()
            self.__session_id = None
            await self.__aclose_session()
        else:
            log.debug("You're not logged in Zabbix API")

    async def check_auth(self) -> bool:
        """Check authentication status in Zabbix API.

        Returns:
            bool: User authentication status (`True`, `False`)
        """

        if not self.__session_id:
            log.debug("You're not logged in Zabbix API")
            return False

        if self.__use_token:
            log.debug("Check auth session using token in Zabbix API")
            refresh_resp = await self.user.checkAuthentication(token=self.__session_id)
        else:
            log.debug("Check auth session using sessionid in Zabbix API")
            refresh_resp = await self.user.checkAuthentication(sessionid=self.__session_id)

        return bool(refresh_resp.get('userid'))

    def __prepare_request(self, method: str, params: Optional[dict] = None,
                          need_auth=True) -> Union[dict, dict]:
        request = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {},
            'id': str(uuid4()),
        }

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json-rpc',
            'User-Agent': f"{__name__}/{__version__}"
        }

        if need_auth:
            if not self.__session_id:
                raise ProcessingError("You're not logged in Zabbix API")
            if self.version < 6.4:
                request['auth'] = self.__session_id
            elif self.version <= 7.0 and self.client_session._default_auth is not None:
                request['auth'] = self.__session_id
            else:
                headers["Authorization"] = f"Bearer {self.__session_id}"

        log.debug(
            "Sending request to %s with body: %s",
            self.url,
            request
        )

        return (request, headers)

    def __check_response(self, method: str, response: dict) -> dict:
        if method not in ModuleUtils.FILES_METHODS:
            log.debug(
                "Received response body: %s",
                response
            )
        else:
            debug_json = response.copy()
            if debug_json.get('result'):
                debug_json['result'] = shorten(debug_json['result'], 200, placeholder='...')
            log.debug(
                "Received response body (clipped): %s",
                json.dumps(debug_json, indent=4, separators=(',', ': '))
            )

        if 'error' in response:
            err = response['error'].copy()
            err['body'] = response.copy()
            raise APIRequestError(err)

        return response

    async def send_async_request(self, method: str, params: Optional[dict] = None,
                                 need_auth=True) -> dict:
        """Function for sending asynchronous request to Zabbix API.

        Args:
            method (str): Zabbix API method name.
            params (dict, optional): Params for request body. Defaults to `None`.
            need_auth (bool, optional): Authorization using flag. Defaults to `False`.

        Raises:
            ProcessingError: Wrapping built-in exceptions during request processing.
            APIRequestError: Wrapping errors from Zabbix API.

        Returns:
            dict: Dictionary with Zabbix API response.
        """

        try:
            request_json, headers = self.__prepare_request(method, params, need_auth)
        except ProcessingError as err:
            await self.__exception(err)

        resp = await self.client_session.post(
            self.url,
            json=request_json,
            headers=headers,
            timeout=self.timeout
        )
        resp.raise_for_status()

        try:
            resp_json = await resp.json()
        except ContentTypeError as err:
            await self.__exception(ProcessingError(f"Unable to connect to {self.url}:", err))
        except ValueError as err:
            await self.__exception(ProcessingError("Unable to parse json:", err))

        try:
            return self.__check_response(method, resp_json)
        except APIRequestError as err:
            await self.__exception(err)

    def send_sync_request(self, method: str, params: Optional[dict] = None,
                          need_auth=True) -> dict:
        """Function for sending synchronous request to Zabbix API.

        Args:
            method (str): Zabbix API method name.
            params (dict, optional): Params for request body. Defaults to `None`.
            need_auth (bool, optional): Authorization using flag. Defaults to `False`.

        Raises:
            ProcessingError: Wrapping built-in exceptions during request processing.
            APIRequestError: Wrapping errors from Zabbix API.

        Returns:
            dict: Dictionary with Zabbix API response.
        """

        request_json, headers = self.__prepare_request(method, params, need_auth)

        # HTTP Auth unsupported since Zabbix 7.2
        basic_auth = self.client_session._default_auth
        if basic_auth is not None:
            headers["Authorization"] = "Basic " + base64.b64encode(
                f"{basic_auth.login}:{basic_auth.password}".encode()
            ).decode()

        req = ul.Request(
            self.url,
            data=json.dumps(request_json).encode("utf-8"),
            headers=headers,
            method='POST'
        )
        req.timeout = self.timeout

        # Disable SSL certificate validation if needed.
        if not self.validate_certs:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif not isinstance(self.client_session._connector._ssl, bool):
            ctx = self.client_session._connector._ssl
        else:
            ctx = None

        try:
            resp = ul.urlopen(req, context=ctx)
            resp_json = json.loads(resp.read().decode('utf-8'))
        except URLError as err:
            self.__close_session()
            raise ProcessingError(f"Unable to connect to {self.url}:", err) from None
        except ValueError as err:
            self.__close_session()
            raise ProcessingError("Unable to parse json:", err) from None
        except Exception as err:
            self.__close_session()
            raise ProcessingError(err) from None

        return self.__check_response(method, resp_json)

    def __check_version(self, skip_check: bool) -> None:

        skip_check_help = "If you're sure zabbix_utils will work properly with your current \
Zabbix version you can skip this check by \
specifying skip_version_check=True when create ZabbixAPI object."

        if self.version < __min_supported__:
            if skip_check:
                log.debug(
                    "Version of Zabbix API [%s] is less than the library supports. %s",
                    self.version,
                    "Further library use at your own risk!"
                )
            else:
                raise APINotSupported(
                    f"Version of Zabbix API [{self.version}] is not supported by the library. " +
                    f"The oldest supported version is {__min_supported__}.0. " + skip_check_help
                )

        if self.version > __max_supported__:
            if skip_check:
                log.debug(
                    "Version of Zabbix API [%s] is more than the library was tested on. %s",
                    self.version,
                    "Recommended to update the library. Further library use at your own risk!"
                )
            else:
                raise APINotSupported(
                    f"Version of Zabbix API [{self.version}] was not tested with the library. " +
                    f"The latest tested version is {__max_supported__}.0. " + skip_check_help
                )
