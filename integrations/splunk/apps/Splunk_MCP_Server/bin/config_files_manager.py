from typing import Any, Dict, Optional

from logging_config import get_logger
from requests import Response
from settings import MCPSettings
from splunk_api import call_splunk_api

logger = get_logger(__name__)


class ConfigFileManager:
    """
    ConfigFileManager is a helper class for interacting with Splunk configuration (conf) files via Splunk's REST API.

    This class abstracts common operations—reading, updating, and managing stanzas and fields—against Splunk's configuration endpoints.
    It communicates with Splunk's REST configuration endpoints (see API docs:
    https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.2/configuration-endpoints/configuration-endpoint-descriptions)
    to facilitate programmatic management of app/local/global conf file data.

    Use this class to get or set configuration values (stanza keys/fields) for a given Splunk app context.

    Typical usage:
        mgr = ConfigFileManager(session_key, "search")
        contents = mgr.get_stanza("inputs", "my_stanza")
        mgr.update_stanza("inputs", "my_stanza", {"disabled": "0"})

    All methods assume the caller has a valid Splunk session token and appropriate permissions for the target app and conf file.
    """

    def __init__(
        self,
        session_key: str,
        app_name: Optional[str] = None,
        owner: str = "nobody",
    ) -> None:
        settings = MCPSettings.get()
        self.app_name = app_name or settings.app_name
        self.session_key = session_key
        self.owner = owner

    def get_stanza(
        self, config_file_name: str, stanza: str
    ) -> Optional[Dict[str, str]]:
        """
        Get a stanza from a config file.

        Assuming you have a [general stanza] in mcp.conf, you can get the value of the stanza by calling:
        get_stanza("mcp", "general")
        """
        response = self._request(
            "GET", config_file_name=config_file_name, stanza=stanza
        )
        if response.status_code != 200:
            logger.error(
                f"Error getting stanza {stanza} from {config_file_name}: {response.status_code}"
            )
            return None

        json_data = response.json()
        return {e["name"]: e["content"] for e in json_data.get("entry", [])}

    def update_stanza(
        self, config_file_name: str, stanza: str, data: Dict[str, Any]
    ) -> bool:
        """
        Update a stanza in a config file.

        Assuming you have a [general stanza] in mcp.conf, you can update the value of the stanza by calling:
        update_stanza("mcp", "general", {"value": "new value"})
        """
        response = self._request(
            "POST",
            config_file_name=config_file_name,
            stanza=stanza,
            data=data,
        )
        if response.status_code != 200:
            logger.error(f"Error updating stanza {stanza} from {config_file_name}")
            return False

        logger.info(
            f"Stanza {stanza} updated successfully in {config_file_name}, data={data}, response: {response.json()}"
        )
        return True

    def _build_api_path(self, config_file: str, stanza: str) -> str:
        return (
            f"servicesNS/{self.owner}/{self.app_name}/properties/{config_file}/{stanza}"
        )

    def _request(
        self,
        method: str,
        config_file_name: str,
        stanza: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Response:
        api_endpoint = self._build_api_path(config_file_name, stanza)
        logger.debug(
            f"Config file request: {method} {api_endpoint} (collection={self.app_name}, owner={self.owner})"
        )
        return call_splunk_api(
            session_key=self.session_key,
            method=method,
            api=api_endpoint,
            headers=headers,
            params={"output_mode": "json"},
            data=data,
        )


__all__ = ["ConfigFileManager"]
