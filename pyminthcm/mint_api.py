import atexit
import json
import logging
from enum import Enum
from json.decoder import JSONDecodeError
from urllib.parse import quote

from oauthlib.oauth2 import (
    BackendApplicationClient,
    InvalidClientError,
    TokenExpiredError,
)
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error
from requests_oauthlib import OAuth2Session


class HTTPMethod(str, Enum):
    GET = "get"
    POST = "post"
    PATCH = "patch"
    DELETE = "delete"


class MintHCMError(Exception):
    """Custom exception for MintHCM API errors."""

    def __init__(self, message: str, code: int | None = None, details: str = ""):
        self.message = message
        self.code = code
        self.details = details
        super().__init__(self.message)

    def __str__(self):
        if self.code:
            return f"MintHCM API Error ({self.code}): {self.message} {f'- {self.details}' if self.details else ''}"
        else:
            return f"MintHCM API Error {self.message} {f'- {self.details}' if self.details else ''}"


class AuthenticationError(MintHCMError):
    """Raised when authentication fails (invalid credentials, token issues)."""

    pass


class RequestError(MintHCMError):
    """Raised when there is an issue with the API request (invalid URL, method, etc.)."""

    pass


class MintHCM:
    """
    MintHCM API client for handling OAuth2 authentication and API requests.
    This class provides methods to interact with the MintHCM API, including authentication,
    making requests, and handling tokens.

    :param client_id: (str) The client ID for OAuth2 authentication.
    :param client_secret: (str) The client secret for OAuth2 authentication.
    :param url: (str) The base URL for the MintHCM API.
    :param token_path: (str) The path to the file where the access token will be stored.
    :param logout_on_exit: (bool) If True, logs out the user when the instance is deleted.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        url: str,
        token_path: str = "AccessToken.json",
        logout_on_exit: bool = False,
    ):
        self.baseurl = url
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_path = token_path
        self._logout_on_exit = logout_on_exit
        self._user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
        )
        self._login()

    def _load_token(self) -> bool:
        """
        Loads the token from the specified token path.
        If the token path is not set, this method does nothing.

        :return: (bool) True if the token was loaded successfully, False otherwise.
        """

        if not self._token_path:
            return False

        try:
            with open(self._token_path, "r") as file:
                if token_data := file.read().strip():
                    self.session.token = json.loads(token_data)
                    return True
        except (FileNotFoundError, json.JSONDecodeError):
            return False

    def _save_token(self) -> None:
        """
        Saves the current token to the specified token path.
        If the token path is not set, this method does nothing.

        :return: None
        """
        if not self._token_path:
            return

        with open(self._token_path, "w") as file:
            file.write(json.dumps(self.session.token))

    def _refresh_token(self) -> None:
        """
        Fetch a new token from from token access url, specified in config file.

        :return: None
        """
        try:
            self.session.fetch_token(
                token_url=f"{self.baseurl[:-2]}access_token",
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
            self._save_token()
        except InvalidClientError:
            raise AuthenticationError("invalid API client ID or secret")
        except CustomOAuth2Error:
            raise RequestError("error accessing MintHCM API")
        except Exception as e:
            raise RequestError(f"failed to refresh token: {str(e)}")

    def _login(self) -> None:
        """
        Checks to see if a Oauth2 Session exists, if not builds a session and retrieves the token from the config file,
        if no token in config file, fetch a new one.

        :return: None
        """
        if not hasattr(self, "OAuth2Session"):
            client = BackendApplicationClient(client_id=self._client_id)
            self.session = OAuth2Session(client=client, client_id=self._client_id)
            self.session.headers.update(
                {"User-Agent": self._user_agent, "Content-Type": "application/json"}
            )
            if self._token_path and self._load_token():
                pass
            else:
                self._refresh_token()
        else:
            self._refresh_token()

        if self._logout_on_exit:
            atexit.register(self._logout)

    def _logout(self) -> None:
        """
        Logs out current Oauth2 Session

        :return: None
        """
        self._request(f"{self.baseurl}/logout", "post")

        if self._token_path:
            try:
                with open(self._token_path, "w+") as file:
                    file.write("")
            except Exception:
                pass

    def _request(
        self, url: str, method: HTTPMethod, payload: dict | None = None
    ) -> dict:
        """
        Makes a request to the given url using the specified method.
        :param url: (string) The url to make the request to.
        :param method: (string) The HTTP method to use (get, post, patch, delete).
        :param payload: (dictionary) The payload to send with the request.

        :return: (dictionary) The response data.
        """
        url = url.rstrip("/")
        url = quote(url, safe="/:?=&")

        try:
            request_method = getattr(self.session, method)
        except AttributeError:
            raise RequestError(f"invalid HTTP method: {method}")

        data = json.dumps({"data": payload})

        for attempt in range(2):
            try:
                if method in [HTTPMethod.GET, HTTPMethod.DELETE]:
                    response = request_method(url)
                else:
                    response = request_method(url, data=data)

                status_code = response.status_code

                if status_code == 401:
                    if attempt == 0:
                        self._refresh_token()
                        continue
                    else:
                        raise AuthenticationError(
                            "authentication failed - token rejected",
                            code=401,
                        )

                if status_code >= 400:
                    content = json.loads(response.content)
                    error_details = content.get("errors", {}).get("detail", "")
                    raise RequestError(
                        "request failed",
                        code=response.status_code,
                        details=error_details,
                    )

                return json.loads(response.content)
            except TokenExpiredError:
                if attempt == 0:
                    self._refresh_token()
                else:
                    raise AuthenticationError("API token refresh failed")
            except JSONDecodeError:
                logging.error(f"Failed to decode JSON response: {response.content}")
                raise RequestError(
                    "request failed",
                    code=status_code,
                    details="Invalid JSON response: " + response.content.decode(),
                )
            except Exception as e:
                if attempt == 1 or not isinstance(e, TokenExpiredError):
                    raise e

        raise RequestError("request failed after retrying")

    def get(self, url: str) -> dict:
        """
        Makes a GET request to the given url.

        :param url: (string) The url to make the request to.

        :return: (dictionary) The response data.
        """
        return self._request(url, HTTPMethod.GET)

    def post(self, url: str, payload: dict) -> dict:
        """
        Makes a POST request to the given url.

        :param url: (string) The url to make the request to.
        :param payload: (dictionary) The payload to send with the request.

        :return: (dictionary) The response data.
        """
        return self._request(url, HTTPMethod.POST, payload)

    def patch(self, url: str, payload: dict) -> dict:
        """
        Makes a PATCH request to the given url.

        :param url: (string) The url to make the request to.
        :param payload: (dictionary) The payload to send with the request.

        :return: (dictionary) The response data.
        """
        return self._request(url, HTTPMethod.PATCH, payload)

    def delete(self, url: str) -> dict:
        """
        Makes a DELETE request to the given url.

        :param url: (string) The url to make the request to.

        :return: (dictionary) The response data.
        """
        return self._request(url, HTTPMethod.DELETE)

    def get_modules_metadata(self) -> dict:
        """
        Retrieves the metadata of all modules in the MintHCM instance.

        :return: (dictionary) The metadata of all modules.
        """
        return self.get(f"{self.baseurl}/meta/modules")

    def get_user_preferences(self, user_id: str) -> dict:
        """
        Gets the preferences of a user.

        :param user_id: (string) id of the user you want to get preferences for.

        :return: (dictionary) The preferences of the user.
        """
        return self.get(f"{self.baseurl}/user-preferences/{user_id}")


class Module:
    def __init__(self, minthcm: MintHCM, module_name: str):
        self.module_name = module_name
        self.minthcm = minthcm

    def create(self, attributes: dict) -> dict:
        """
        Creates a record with given attributes
        :param attributes: (dict) fields with data you want to populate the record with.

        :return: (dictionary) The record that was created with the attributes.
        """
        data = {
            "type": self.module_name,
            "attributes": {**attributes},
        }
        return self.minthcm.post(f"{self.minthcm.baseurl}/module", payload=data)

    def update(self, record_id: str, attributes: dict) -> dict:
        """
        updates a record.

        :param record_id: (string) id of the current module record.
        :param attributes: (dict) fields inside of the record to be updated.

        :return: (dictionary) The updated record
        """
        data = {"type": self.module_name, "id": record_id, "attributes": {**attributes}}
        return self.minthcm.patch(f"{self.minthcm.baseurl}/module", payload=data)

    def delete(self, record_id: str) -> dict:
        """
        Delete a specific record by id.
        :param record_id: (string) The record id within the module you want to delete.

        :return: (dictionary) Confirmation of deletion of record.
        """
        url = f"/module/{self.module_name}/{record_id}"
        return self.minthcm.delete(f"{self.minthcm.baseurl}{url}")

    def fields(self) -> list:
        """
        Gets all the attributes that can be set in a record.
        :return: (list) All the names of attributes in a record.
        """
        # Get total record count
        url = f"/meta/fields/{self.module_name}"
        return self.minthcm.get(f"{self.minthcm.baseurl}{url}")

    def get(
        self, fields: list = None, sort: str = None, operator: str = "and", **filters
    ) -> list:
        """
        Gets records given a specific id or filters, can be sorted only once, and the fields returned for each record
        can be specified.

        :param fields: (list) A list of fields you want to be returned from each record.
        :param sort: (string) The field you want the records to be sorted by.
        :param filters: (**kwargs) fields that the record has that you want to filter on.
                        ie... date_start= {'operator': '>', 'value':'2020-05-08T09:59:00+00:00'}

        Important notice: we don’t support multiple level sorting right now!

        :return: (list) A list of dictionaries, where each dictionary is a record.
        """
        if fields:
            fields_str = f"?fields[{self.module_name}]=" + ",".join(fields)
        else:
            fields_str = "?"

        if operator not in ["and", "or"]:
            operator = "and"

        filter_str = f"filter[operator]={operator}"

        operators = {
            "=": "EQ",
            "<>": "NEQ",
            ">": "GT",
            ">=": "GTE",
            "<": "LT",
            "<=": "LTE",
            "LIKE": "LIKE",
            "NOT LIKE": "NOT_LIKE",
            "IN": "IN",
            "NOT IN": "NOT_IN",
        }

        for field, value in filters.items():
            if isinstance(value, dict):
                if value["operator"] == "BETWEEN":
                    values = value["value"].split(",")
                    filter_str += f"&filter[{field}][GT]={values[0]}&filter[{field}][LT]={values[1]}"
                else:
                    filter_str += f"&filter[{field}][{operators[value['operator']]}]={value['value']}"
            else:
                filter_str += f"&filter[{field}][EQ]={value}"

        url = (
            f"{self.minthcm.baseurl}/module/{self.module_name}{fields_str}&{filter_str}"
        )

        if sort:
            url += f"&sort=-{sort}"

        return self.minthcm.get(url)

    def get_all_records(self) -> dict:
        """
        Gets all the records in a module.

        :return: (dictionary) A list of all the records in the module.
        """
        url = f"/module/{self.module_name}"
        return self.minthcm.get(f"{self.minthcm.baseurl}{url}")

    def get_relationship(self, record_id: str, related_module_name: str) -> dict:
        """
        returns the relationship between this record and another module.

        :param record_id: (string) id of the current module record.
        :param related_module_name: (string) the module name you want to search relationships for, ie. Contacts.

        :return: (dictionary) A list of relationships that this module's record contains with the related module.
        """
        url = f"/module/{self.module_name}/{record_id}/relationships/{related_module_name.lower()}"
        return self.minthcm.get(f"{self.minthcm.baseurl}{url}")

    def create_relationship(
        self, record_id: str, related_module_name: str, related_bean_id: str
    ) -> dict:
        """
        Creates a relationship between 2 records.

        :param record_id: (string) id of the current module record.
        :param related_module_name: (string) the module name of the record you want to create a relationship,
               ie. Contacts.
        :param related_bean_id: (string) id of the record inside of the other module.

        :return: (dictionary) A record that the relationship was created.
        """
        url = f"/module/{self.module_name}/{record_id}/relationships/{related_module_name.lower()}"
        data = {"type": related_module_name.capitalize(), "id": related_bean_id}
        return self.minthcm.post(f"{self.minthcm.baseurl}{url}", payload=data)

    def delete_relationship(
        self, record_id: str, related_module_name: str, related_bean_id: str
    ) -> dict:
        """
        Deletes a relationship between 2 records.

        :param record_id: (string) id of the current module record.
        :param related_module_name: (string) the module name of the record you want to delete a relationship,
               ie. Contacts.
        :param related_bean_id: (string) id of the record inside of the other module.

        :return: (dictionary) A record that the relationship was deleted.
        """
        url = f"/module/{self.module_name}/{record_id}/relationships/{related_module_name.lower()}/{related_bean_id}"
        return self.minthcm.delete(f"{self.minthcm.baseurl}{url}")
