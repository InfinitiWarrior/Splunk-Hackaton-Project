"""
Tool Manager Module.

This module provides comprehensive management of MCP tools, including tool discovery,
validation, execution, and argument processing. It handles both built-in tools and
custom tool definitions loaded from configuration files.
"""

import http
import json
import re
import threading
import time
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from constants import (
    EVENT_SPL_SAFETY_ERROR,
    EVENT_SPL_SAFETY_REJECTION,
    TELEMETRY_SUPPRESS_KEY,
)
from kvstore_manager import KVStoreManager
from logging_config import get_logger, log_telemetry
from settings import MCPSettings
from tool_collision import (
    ComparableTool,
    JaccardToolCollisionDetector,
    ToolCollisionDetector,
    ToolCollisionResult,
)
from tool_enabled_collection import EnabledTool, ToolEnabledCollection


def _coerce_bool(value: Any) -> bool:
    """Coerce various representations into a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return False


from splunk_api import (
    call_splunk_api,
    check_spl_safe,
    is_saved_search_disabled,
    normalize_search_command,
    run_splunk_query_internal,
)

# Module logger
logger = get_logger(__name__)

# Thread-safe singleton lock
_manager_lock = threading.Lock()
_default_manager: Optional["ToolManager"] = None


class ArgumentType(Enum):
    """
    Enumeration of supported argument types for tool parameters.

    This enum defines the types that can be used for tool arguments,
    ensuring type safety and proper validation.
    """

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"

    @classmethod
    def from_string(cls, value: str) -> "ArgumentType":
        """
        Convert string representation to ArgumentType enum.

        Args:
            value: String value to convert.

        Returns:
            ArgumentType enum value, defaults to STRING if not recognized.
        """
        if not value:
            return cls.STRING

        normalized_value = value.lower().strip()

        type_mapping = {
            "string": cls.STRING,
            "integer": cls.INTEGER,
            "number": cls.NUMBER,
            "boolean": cls.BOOLEAN,
        }

        result = type_mapping.get(normalized_value, cls.STRING)
        if result == cls.STRING and normalized_value not in type_mapping:
            logger.warning("Unknown argument type '%s', defaulting to STRING", value)

        return result


@dataclass
class ToolArgumentValidation:
    """
    Validation rules for tool arguments.

    This class encapsulates regex patterns and error messages
    for validating tool argument values.

    Attributes:
        pattern: Optional regex pattern for validation.
        message: Optional custom error message for validation failures.
    """

    pattern: Optional[str] = None
    message: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolArgumentValidation":
        """
        Create validation instance from dictionary data.

        Args:
            data: Dictionary containing validation configuration.

        Returns:
            ToolArgumentValidation instance.
        """
        if not data:
            return cls()

        return cls(
            pattern=data.get("pattern"),
            message=data.get("message"),
        )


@dataclass
class ToolArgument:
    """
    Definition of a single tool argument.

    This class represents a complete argument specification including
    type information, validation rules, and metadata for UI generation.

    Attributes:
        name: Argument name.
        type: Argument type from ArgumentType enum.
        description: Human-readable description.
        required: Whether the argument is mandatory.
        placeholder: Example value for UI hints.
        default: Default value if not provided.
        group: Logical grouping for UI organization.
        display_order: Ordering hint for UI display.
        min: Minimum value for numeric types.
        max: Maximum value for numeric types.
        enum: List or dict of allowed values.
        quoted: Whether string values should be quoted in SPL.
        validation: Validation rules for the argument.
    """

    name: str
    type: ArgumentType = ArgumentType.STRING
    description: str = ""
    required: bool = False
    placeholder: Optional[str] = None
    default: Optional[Any] = None
    group: Optional[str] = None
    display_order: Optional[int] = None
    min: Optional[float] = None
    max: Optional[float] = None
    enum: Optional[Union[List[Any], Dict[str, Any]]] = None
    quoted: bool = True
    validation: ToolArgumentValidation = field(default_factory=ToolArgumentValidation)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolArgument":
        """
        Create ToolArgument from dictionary configuration.

        Args:
            data: Dictionary containing argument configuration.

        Returns:
            ToolArgument instance.

        Raises:
            KeyError: If required 'name' field is missing.
        """
        if "name" not in data:
            raise KeyError("Tool argument must have 'name' field")

        # Extract needs_quoting from _meta.formatting.needs_quoting if present
        arg_type = ArgumentType.from_string(data.get("type", "string"))
        quoted = arg_type == ArgumentType.STRING
        meta = data.get("_meta", {})
        formatting = meta.get("formatting", {}) if isinstance(meta, dict) else {}
        if "needs_quoting" in formatting:
            quoted = formatting["needs_quoting"]

        return cls(
            name=data["name"],
            type=ArgumentType.from_string(data.get("type", "string")),
            description=data.get("description", ""),
            required=data.get("required", False),
            placeholder=data.get("placeholder"),
            default=data.get("default"),
            group=data.get("group"),
            display_order=data.get("display_order"),
            min=data.get("min"),
            max=data.get("max"),
            enum=data.get("enum"),
            quoted=quoted,
            validation=ToolArgumentValidation.from_dict(data.get("validation", {})),
        )


@dataclass
class ToolExample:
    """
    Example usage for a tool.

    This class provides example invocations and expected outcomes
    for tools, useful for documentation and testing.

    Attributes:
        name: Example name/title.
        description: Description of what the example demonstrates.
        arguments: Example argument values.
        expected_use: Description of expected use case.
    """

    name: str
    description: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    expected_use: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolExample":
        """
        Create ToolExample from dictionary configuration.

        Args:
            data: Dictionary containing example configuration.

        Returns:
            ToolExample instance.
        """
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            arguments=data.get("arguments", {}),
            expected_use=data.get("expected_use"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the example back to a dictionary."""
        result: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments or {},
        }
        if self.expected_use is not None:
            result["expected_use"] = self.expected_use
        return result


@dataclass
class Tool:
    """
    Complete tool definition with execution capabilities.

    This class represents a complete MCP tool including metadata,
    argument specifications, SPL query template, and execution logic.

    Attributes:
        name: Unique tool identifier.
        description: Human-readable description.
        tags: List of descriptive tags.
        spl: SPL query template for execution.
        arguments: List of tool arguments.
        examples: List of usage examples.
        raw: Original configuration data.
        row_limiter: Whether tool adds row limiting in the argument.
        time_range: Whether tool supports time range arguments.
        required_app: Name of Splunk app required for this tool to function (optional).
    """

    name: str
    description: Optional[str]
    tags: List[str]
    _key: str
    spl: str = ""
    arguments: List[ToolArgument] = field(default_factory=list)
    examples: List[ToolExample] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    row_limiter: bool = True
    time_range: bool = True
    required_app: Optional[str] = None
    external_app: Optional[str] = None
    built_in: bool = False
    title: Optional[str] = None
    guardrails: bool = False
    schema_format: str = "legacy"
    execution_type: str = "spl"
    api_method: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_headers: Dict[str, Any] = field(default_factory=dict)
    api_params: Dict[str, Any] = field(default_factory=dict)
    api_body: Optional[Any] = None
    saved_search: Optional[Dict[str, Any]] = None

    @property
    def tool_id(self) -> str:
        return self._key

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Tool":
        """
        Create Tool instance from dictionary configuration.

        Args:
            data: Dictionary containing tool configuration.

        Returns:
            Tool instance with injected standard arguments.

        Raises:
            ValueError: If required fields are missing.
        """
        schema_format = "legacy"
        raw_source = data
        if "inputSchema" in data and "_meta" in data:
            raw_source = data
            data = cls._convert_from_new_schema(data)
            schema_format = "new"

        # Validate required fields for internal representation
        execution_type = (data.get("execution_type") or "spl").lower()
        required_fields = ["name"]
        if execution_type == "spl":
            required_fields.append("spl")
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            raise ValueError(
                f"Tool definition missing required fields {missing_fields}"
            )

        logger.info("Creating tool from configuration: %s", data.get("name"))
        key = data.get("_key")
        if not isinstance(key, str) or not key.strip():
            raise ValueError(
                f"Tool definition '{data.get('name', 'unknown')}' is missing a valid '_key'."
            )
        key = key.strip()

        tool = cls(
            name=data["name"],
            title=data.get("title"),
            description=data.get("description"),
            tags=data.get("tags", []),
            spl=data["spl"],
            arguments=[
                ToolArgument.from_dict(arg) for arg in data.get("arguments", [])
            ],
            examples=[ToolExample.from_dict(ex) for ex in data.get("examples", [])],
            raw=raw_source,
            row_limiter=data.get("row_limiter", True),
            time_range=data.get("time_range", True),
            required_app=data.get("required_app"),
            external_app=data.get("external_app"),
            built_in=_coerce_bool(data.get("built_in", False)),
            _key=key,
            guardrails=_coerce_bool(data.get("guardrails", False)),
            schema_format=schema_format,
            execution_type=execution_type,
            api_method=data.get("api_method"),
            api_endpoint=data.get("api_endpoint"),
            api_headers=data.get("api_headers") or {},
            api_params=data.get("api_params") or {},
            api_body=data.get("api_body"),
            saved_search=data.get("saved_search"),
        )

        tool._inject_standard_arguments()
        logger.info(
            "Created tool '%s' with %d arguments", tool.name, len(tool.arguments)
        )
        return tool

    @classmethod
    def _convert_from_new_schema(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert new external schema payload into internal representation."""
        meta = data.get("_meta") or {}
        execution = meta.get("execution") or {}
        external_app_id = meta.get("external_app_id")
        if not external_app_id:
            raise ValueError("Tool definition missing '_meta.external_app_id'.")

        exec_type = (execution.get("type") or "spl").lower()

        properties = (data.get("inputSchema") or {}).get("properties", {})
        required_args = set((data.get("inputSchema") or {}).get("required", []) or [])
        arguments: List[Dict[str, Any]] = []
        for arg_name, prop in properties.items():
            if not isinstance(prop, dict):
                continue
            arg: Dict[str, Any] = {
                "name": arg_name,
                "type": prop.get("type", "string"),
                "description": prop.get("description", ""),
                "required": arg_name in required_args,
                "_meta": prop.get("_meta", {}),
            }
            if "default" in prop:
                arg["default"] = prop.get("default")
            if "enum" in prop:
                arg["enum"] = prop.get("enum")
            if "minimum" in prop:
                arg["min"] = prop.get("minimum")
            if "maximum" in prop:
                arg["max"] = prop.get("maximum")

            pattern = prop.get("pattern")
            validation_message = prop.get("validation_message")
            validation: Dict[str, Any] = {}
            if pattern:
                validation["pattern"] = pattern
            if validation_message:
                validation["message"] = validation_message
            if validation:
                arg["validation"] = validation
            arguments.append(arg)

        # Prefix the tool name with the configured name prefix for uniqueness.
        name_prefix = meta.get("name_prefix")
        if not isinstance(name_prefix, str) or not name_prefix.strip():
            name_prefix = external_app_id
        else:
            name_prefix = name_prefix.strip()

        orig_name = data.get("name")
        if (
            orig_name
            and isinstance(orig_name, str)
            and name_prefix
            and orig_name.startswith(f"{name_prefix}_")
        ):
            unique_name = orig_name
        else:
            unique_name = f"{name_prefix}_{orig_name}" if name_prefix else orig_name

        converted: Dict[str, Any] = {
            "name": unique_name,
            "title": data.get("title"),
            "description": data.get("description"),
            "tags": meta.get("tags", []),
            "required_app": meta.get("required_app"),
            "external_app": external_app_id,
            "arguments": arguments,
            "examples": meta.get("examples", []),
            "built_in": _coerce_bool(meta.get("built_in", False)),
            "execution_type": exec_type,
        }

        # Preserve saved_search metadata if present
        saved_search = meta.get("saved_search")
        if isinstance(saved_search, dict):
            converted["saved_search"] = deepcopy(saved_search)

        if exec_type == "spl":
            template = execution.get("template")
            if not isinstance(template, str) or not template.strip():
                raise ValueError("Execution template is required for SPL tools.")
            if any(
                execution.get(field)
                for field in ("method", "endpoint", "headers", "params", "body")
            ):
                raise ValueError("SPL tools cannot define API execution fields.")
            converted["spl"] = template.strip()
            converted["row_limiter"] = _coerce_bool(execution.get("row_limiter", True))
            converted["time_range"] = _coerce_bool(execution.get("time_range", True))
            converted["guardrails"] = _coerce_bool(execution.get("guardrails", False))
        elif exec_type == "api":
            method = execution.get("method")
            endpoint = execution.get("endpoint")
            if not isinstance(method, str) or not method.strip():
                raise ValueError("API tools require a HTTP 'method'.")
            if not isinstance(endpoint, str) or not endpoint.strip():
                raise ValueError("API tools require an 'endpoint'.")
            if execution.get("template"):
                raise ValueError("API tools cannot define SPL templates.")
            converted["spl"] = ""
            converted["row_limiter"] = False
            converted["time_range"] = False
            converted["guardrails"] = False
            converted["api_method"] = method.strip().upper()
            converted["api_endpoint"] = endpoint.strip()
            headers = execution.get("headers") or {}
            params = execution.get("params") or {}
            if headers and not isinstance(headers, dict):
                raise ValueError("API headers must be an object.")
            if params and not isinstance(params, dict):
                raise ValueError("API params must be an object.")
            converted["api_headers"] = (
                deepcopy(headers) if isinstance(headers, dict) else {}
            )
            converted["api_params"] = (
                deepcopy(params) if isinstance(params, dict) else {}
            )
            if "body" in execution:
                converted["api_body"] = deepcopy(execution.get("body"))
            else:
                converted["api_body"] = None
        else:
            raise ValueError("Unsupported execution type. Allowed: spl, api.")

        if "_key" in data:
            converted["_key"] = data["_key"]
        return converted

    def _inject_standard_arguments(self) -> None:
        """
        This method adds common arguments like earliest_time, latest_time,
        and row_limit to tools that don't already define them.
        """
        if self.execution_type != "spl":
            return

        existing_args = {arg.name for arg in self.arguments}
        settings = MCPSettings.get()
        standard_args: List[ToolArgument] = []

        # Add time range arguments if enabled
        if self.time_range:
            if "earliest_time" not in existing_args:
                standard_args.append(
                    ToolArgument(
                        name="earliest_time",
                        type=ArgumentType.STRING,
                        description="Start time for search (e.g., -24h, -1d)",
                        required=False,
                        default="-24h",
                        placeholder="-24h",
                        quoted=False,
                    )
                )

            if "latest_time" not in existing_args:
                standard_args.append(
                    ToolArgument(
                        name="latest_time",
                        type=ArgumentType.STRING,
                        description="End time for search (e.g., now, -1h)",
                        required=False,
                        default="now",
                        placeholder="now",
                        quoted=False,
                    )
                )

        # Add row limit argument
        if self.row_limiter and "row_limit" not in existing_args:
            standard_args.append(
                ToolArgument(
                    name="row_limit",
                    type=ArgumentType.INTEGER,
                    description="Maximum number of rows to return",
                    required=False,
                    default=settings.default_row_limit,
                    min=1,
                    max=settings.max_row_limit,
                )
            )

        if standard_args:
            self.arguments.extend(standard_args)
            logger.info(
                "Injected %d standard arguments for tool: %s",
                len(standard_args),
                self.name,
            )

    def execute(self, session_key: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the tool with provided arguments.

        This method validates arguments, builds the SPL query, and executes
        it against Splunk, returning the formatted results.

        Args:
            session_key: Splunk authentication token.
            args: Dictionary of argument values.

        Returns:
            Dictionary containing execution results or error information.

        Raises:
            Exception: For validation errors or execution failures.
        """
        logger.info("Executing tool '%s' with args: %s", self.name, args)

        # Validate arguments
        validation_error = self._validate_arguments(args)
        if validation_error:
            logger.error(
                "Argument validation failed for tool '%s': %s",
                self.name,
                validation_error,
            )
            raise ValueError(validation_error)

        # Reject disabled saved searches before execution
        disabled_error = self._check_saved_search_not_disabled(session_key, args)
        if disabled_error:
            return disabled_error

        # Normalize and prepare arguments
        normalized_args = self._normalize_arguments(args)

        if self.execution_type == "api":
            return self._execute_api(session_key, normalized_args)

        # Build SPL query
        try:
            spl_query = self._build_spl_query(normalized_args)
            logger.info("Built SPL query for tool: %s", self.name)
        except Exception as e:
            logger.error("Failed to build SPL query for tool '%s': %s", self.name, e)
            raise

        settings = MCPSettings.get()

        # Normalize the query to ensure proper format and limits
        normalized_query = normalize_search_command(spl_query, settings.max_row_limit)
        logger.info("Normalized SPL query for tool: %s", self.name)

        # Safety check unless excluded
        try:
            excluded = self.name in settings.safe_spl_exclude_tools
            if not excluded:
                is_safe, message = check_spl_safe(
                    settings, session_key, normalized_query
                )
                if not is_safe:
                    log_telemetry(
                        EVENT_SPL_SAFETY_REJECTION,
                        http.HTTPStatus.BAD_REQUEST,
                        error_message=message,
                    )
                    logger.error("SPL safety validation failed: %s", message)
                    return {
                        "status_code": int(http.HTTPStatus.BAD_REQUEST),
                        "content": message,
                        TELEMETRY_SUPPRESS_KEY: True,
                    }
                logger.info("SPL validation passed: %s", message)
        except Exception as e:
            log_telemetry(
                EVENT_SPL_SAFETY_ERROR,
                http.HTTPStatus.INTERNAL_SERVER_ERROR,
                error_message=str(e),
                error_type=type(e).__name__,
            )
            logger.exception("Error during SPL safety validation: %s", e)
            return {
                "status_code": int(http.HTTPStatus.INTERNAL_SERVER_ERROR),
                "content": f"Safety validation error: {e}",
                TELEMETRY_SUPPRESS_KEY: True,
            }

        # Execute query
        try:
            start_time = time.time()  # Start time for execution duration
            result = run_splunk_query_internal(
                settings=settings,
                session_key=session_key,
                query=normalized_query,
                earliest_time=normalized_args.get("earliest_time"),
                latest_time=normalized_args.get("latest_time"),
                row_limit=normalized_args.get("row_limit", settings.default_row_limit),
                app=normalized_args.get("app"),
                tool_name=self.name,
            )
            end_time = time.time()  # End time for execution duration
            execution_time = end_time - start_time

            logger.info(
                "Tool '%s' executed successfully",
                self.name,
                extra={"execution_time_seconds": round(execution_time, 2)},
            )
            return result

        except Exception as e:
            logger.exception("Tool execution failed for '%s': %s", self.name, e)
            raise

    _SAVEDSEARCH_RE = re.compile(r"^\|\s*savedsearch\s+\$(\w+)\$", re.IGNORECASE)

    def _check_saved_search_not_disabled(
        self, session_key: str, args: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Block execution when the target saved search has disabled=1."""
        match = self._SAVEDSEARCH_RE.match(self.spl.strip())
        if not match:
            logger.info(
                "Tool '%s': SPL does not reference a saved search, skipping disabled check",
                self.name,
            )
            return None

        name = str(args.get(match.group(1), ""))
        if not name:
            logger.warning(
                "Tool '%s': saved search name argument '%s' is empty",
                self.name,
                match.group(1),
            )
            return None

        app = args.get("app")
        is_disabled, message, resolved_app = is_saved_search_disabled(
            session_key, name, app=app
        )
        if is_disabled:
            logger.warning(
                "Tool '%s': saved search '%s' is disabled, blocking execution",
                self.name,
                name,
            )
            return {
                "status_code": int(http.HTTPStatus.BAD_REQUEST),
                "content": message,
            }

        if resolved_app is None:
            logger.warning("Tool '%s': %s", self.name, message)
            return {
                "status_code": int(http.HTTPStatus.BAD_REQUEST),
                "content": message,
            }

        # this checks that if an app is provided, it must match the resolved app
        if app and app != resolved_app:
            logger.warning(
                "Tool '%s': saved search '%s' belongs to app '%s', not '%s'",
                self.name,
                name,
                resolved_app,
                app,
            )
            return {
                "status_code": int(http.HTTPStatus.BAD_REQUEST),
                "content": (
                    f"Saved search '{name}' belongs to app '{resolved_app}', "
                    f"not '{app}'. Use app='{resolved_app}' or omit the app "
                    "parameter to auto-resolve."
                ),
            }

        if not app:
            logger.info(
                "Tool '%s': auto-resolved saved search '%s' to app '%s'",
                self.name,
                name,
                resolved_app,
            )
        args["app"] = resolved_app

        logger.info(
            "Tool '%s': saved search '%s' is enabled, proceeding with execution",
            self.name,
            name,
        )
        return None

    def _validate_arguments(self, args: Dict[str, Any]) -> Optional[str]:
        """
        Validate provided arguments against tool specification.

        Args:
            args: Arguments to validate.

        Returns:
            Error message if validation fails, None if successful.
        """
        # Check required arguments
        error = self._validate_required_arguments(args)
        if error:
            return error

        # Check argument patterns
        error = self._validate_argument_patterns(args)
        if error:
            return error

        return None

    def _validate_required_arguments(self, args: Dict[str, Any]) -> Optional[str]:
        """Validate that all required arguments are present."""
        for arg_spec in self.arguments:
            if arg_spec.required and arg_spec.name not in args:
                return f"Missing required argument: {arg_spec.name}"
        return None

    def _validate_argument_patterns(self, args: Dict[str, Any]) -> Optional[str]:
        """Validate arguments against regex patterns."""
        for arg_spec in self.arguments:
            if not arg_spec.validation or not arg_spec.validation.pattern:
                continue

            if arg_spec.name not in args:
                continue

            try:
                value_str = str(args[arg_spec.name])
                if not re.fullmatch(arg_spec.validation.pattern, value_str):
                    return (
                        arg_spec.validation.message
                        or f"Value for '{arg_spec.name}' failed validation"
                    )
            except re.error as e:
                logger.warning(
                    "Invalid regex pattern for %s.%s: %s", self.name, arg_spec.name, e
                )

        return None

    def _normalize_arguments(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and validate argument values according to their types.

        Args:
            args: Raw argument values.

        Returns:
            Dictionary of normalized argument values.

        Raises:
            ValueError: If argument normalization fails.
        """
        normalized = {}

        for arg_spec in self.arguments:
            if arg_spec.name not in args:
                # Use default value if available
                if arg_spec.default is not None:
                    normalized[arg_spec.name] = arg_spec.default
                continue

            value = args[arg_spec.name]

            try:
                if arg_spec.type == ArgumentType.STRING:
                    normalized[arg_spec.name] = self._normalize_string_arg(
                        arg_spec, value
                    )
                elif arg_spec.type == ArgumentType.INTEGER:
                    normalized[arg_spec.name] = self._normalize_integer_arg(
                        arg_spec, value
                    )
                elif arg_spec.type == ArgumentType.NUMBER:
                    normalized[arg_spec.name] = self._normalize_number_arg(
                        arg_spec, value
                    )
                elif arg_spec.type == ArgumentType.BOOLEAN:
                    normalized[arg_spec.name] = self._normalize_boolean_arg(
                        arg_spec, value
                    )
                else:
                    normalized[arg_spec.name] = value

            except Exception as e:
                raise ValueError(f"Failed to normalize argument '{arg_spec.name}': {e}")

        return normalized

    def _normalize_string_arg(self, spec: ToolArgument, value: Any) -> str:
        """Normalize string argument with enum validation."""
        str_value = str(value)

        if spec.enum:
            if isinstance(spec.enum, dict):
                if str_value not in spec.enum:
                    raise ValueError(
                        f"Value '{str_value}' not in allowed keys {list(spec.enum.keys())}"
                    )
                # For dictionary-style enums, return the value corresponding to the key
                return spec.enum.get(str_value, "")
            if isinstance(spec.enum, list):
                if str_value not in spec.enum:
                    raise ValueError(
                        f"Value '{str_value}' not in allowed values {spec.enum}"
                    )

        if spec.quoted and self.execution_type != "api":
            # Use shlex.quote to properly escape and quote the string for SPL
            return json.dumps(str_value)

        return str_value

    def _normalize_integer_arg(self, spec: ToolArgument, value: Any) -> int:
        """Normalize integer argument with range validation."""
        if isinstance(value, bool):
            raise ValueError("Boolean provided where integer expected")

        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid integer value: {value}")

        if spec.min is not None and int_value < spec.min:
            raise ValueError(f"Value {int_value} below minimum {spec.min}")
        if spec.max is not None and int_value > spec.max:
            raise ValueError(f"Value {int_value} above maximum {spec.max}")

        if spec.enum and int_value not in spec.enum:
            raise ValueError(f"Value {int_value} not in allowed values {spec.enum}")

        return int_value

    def _normalize_number_arg(self, spec: ToolArgument, value: Any) -> float:
        """Normalize number argument with range validation."""
        try:
            float_value = float(value)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid number value: {value}")

        if spec.min is not None and float_value < spec.min:
            raise ValueError(f"Value {float_value} below minimum {spec.min}")
        if spec.max is not None and float_value > spec.max:
            raise ValueError(f"Value {float_value} above maximum {spec.max}")

        return float_value

    def _normalize_boolean_arg(self, spec: ToolArgument, value: Any) -> bool:
        """Normalize boolean argument."""
        if isinstance(value, bool):
            return value

        str_value = str(value).lower().strip()
        if str_value in {"true", "1", "yes", "on"}:
            return True
        if str_value in {"false", "0", "no", "off"}:
            return False

        raise ValueError(f"Invalid boolean value: {value}")

    def _build_spl_query(self, args: Dict[str, Any]) -> str:
        """
        Build SPL query from template and arguments.

        Args:
            args: Normalized argument values.

        Returns:
            Complete SPL query string.
        """
        try:
            query = self.spl

            # Remove optional parameters from the SPL query template
            # if they are not present in the request payload.
            for arg in self.arguments:
                if arg.name not in args:
                    query = query.replace(f" {arg.name}=${arg.name}$", "")

            # Simple template substitution
            for key, value in args.items():
                placeholder = f"${key}$"
                if placeholder in query:
                    query = query.replace(placeholder, str(value))

            logger.info("Built SPL query for tool '%s'", self.name)
            return query

        except Exception as e:
            logger.error("Failed to build SPL query for tool '%s': %s", self.name, e)
            raise

    def _build_api_request(self, args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.api_method or not self.api_endpoint:
            raise ValueError(f"API tool '{self.name}' is missing method or endpoint.")

        endpoint = self._substitute_placeholders(self.api_endpoint, args)
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("API endpoint is required after placeholder substitution.")

        headers = self._substitute_placeholders(
            deepcopy(self.api_headers) if self.api_headers else {}, args
        )
        params = self._substitute_placeholders(
            deepcopy(self.api_params) if self.api_params else {}, args
        )
        body = self._substitute_placeholders(deepcopy(self.api_body), args)

        return {
            "method": self.api_method,
            "endpoint": endpoint,
            "headers": headers if headers else None,
            "params": params if params else None,
            "body": body,
        }

    @staticmethod
    def _normalize_chat_history(body: Any) -> None:
        """Ensure chat_history is a JSON-encoded list of message objects.

        SAIA expects '[{"role": "user", "content": "..."}]'.
        - Pre-formatted JSON list string  → passed through unchanged.
        - Plain string / non-list JSON    → wrapped as a single user message.
        - None or missing                 → left untouched.
        - Non-dict body                   → ignored.
        """
        # chat_history only needs to be normalized for SAIA tools, wherein body is a dict
        if not isinstance(body, dict):
            return
        chat = body.get("chat_history")
        # Only process if chat_history is a string (skip None, missing, etc.)
        if isinstance(chat, str):
            is_json_list = False
            try:
                # Check if already a valid JSON list, and so pass through
                is_json_list = isinstance(json.loads(chat), list)
            except (json.JSONDecodeError, ValueError):
                pass
            # If not a valid JSON list, wrap as a single user message
            if not is_json_list:
                body["chat_history"] = json.dumps([{"role": "user", "content": chat}])

    @staticmethod
    def _normalize_additional_context(body: Any) -> None:
        """Ensure additional_context is a dict.  SAIA expects a JSON object,
        so this is stored as a native Python dict for single serialisation."""
        # additional_context only needs to be normalized for SAIA tools, wherein body is a dict
        if not isinstance(body, dict):
            return
        value = body.get("additional_context")
        if not isinstance(value, str):
            return
        if not value.strip():
            body.pop("additional_context", None)
            return
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                body["additional_context"] = parsed
                return
        except (json.JSONDecodeError, ValueError):
            pass
        body["additional_context"] = {"user_prompt": value}

    def _execute_api(self, session_key: str, args: Dict[str, Any]) -> Dict[str, Any]:
        request_details = self._build_api_request(args)
        body = request_details.get("body") or {}
        self._normalize_chat_history(body)
        self._normalize_additional_context(body)
        data = self._serialize_body(body, request_details.get("headers"))

        response = call_splunk_api(
            session_key=session_key,
            method=request_details["method"],
            api=request_details["endpoint"],
            headers=request_details["headers"],
            params=request_details["params"],
            data=data,
        )

        try:
            content = response.json()
        except ValueError:
            content = response.text

        return self._format_api_response(response.status_code, response.ok, content)

    @staticmethod
    def _format_api_response(
        status_code: int, ok: bool, content: Any
    ) -> Dict[str, Any]:
        """Normalize an API response into the standard tool result format.

        On error  → {"error": "<message>", "status_code": <int>}
        On success → {"results": [<row>, ...], "truncated": False, "total_rows": N}
        """
        if not ok:
            msg = content if isinstance(content, str) else json.dumps(content)
            return {"error": msg, "status_code": status_code}

        # Dict (typical SAIA response) — wrap in a single-element list
        if isinstance(content, dict):
            rows = [content]
        # List — ensure each item is a dict
        elif isinstance(content, list):
            rows = [r if isinstance(r, dict) else {"response": r} for r in content]
        # Plain string or others — wrap under "response" key
        else:
            rows = [{"response": content}]

        return {"results": rows, "truncated": False, "total_rows": len(rows)}

    @staticmethod
    def _serialize_body(body: Any, headers: Optional[Dict[str, str]]) -> Any:
        """Serialize the request body based on Content-Type.

        JSON content type → raw JSON string preserving types.
        Otherwise → form-encode dicts (stringify non-string values).
        """
        if body is None:
            return None
        content_type = (headers or {}).get("Content-Type", "")
        if isinstance(body, dict) and not content_type.startswith("application/json"):
            return {
                k: v if isinstance(v, str) else json.dumps(v) for k, v in body.items()
            }
        if isinstance(body, (dict, list)):
            return json.dumps(body)
        return str(body)

    @staticmethod
    def _substitute_placeholders(value: Any, args: Dict[str, Any]) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            for key, arg_value in args.items():
                placeholder = f"${key}$"
                if value == placeholder:
                    return arg_value
                if placeholder in value:
                    value = value.replace(placeholder, str(arg_value))
            return value
        if isinstance(value, dict):
            resolved = {}
            for k, v in value.items():
                original = v
                v = Tool._substitute_placeholders(v, args)
                if (
                    v == original
                    and isinstance(v, str)
                    and v.startswith("$")
                    and v.endswith("$")
                ):
                    continue
                resolved[k] = v
            return resolved
        if isinstance(value, list):
            return [Tool._substitute_placeholders(item, args) for item in value]
        return value

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert tool to dictionary representation.

        Returns:
            Dictionary containing complete tool configuration.
        """
        return {
            "_key": self.tool_id,
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "tags": self.tags,
            "spl": self.spl,
            "row_limiter": self.row_limiter,
            "time_range": self.time_range,
            "required_app": self.required_app,
            "external_app": self.external_app,
            "built_in": self.built_in,
            "guardrails": self.guardrails,
            "execution_type": self.execution_type,
            "api_method": self.api_method,
            "api_endpoint": self.api_endpoint,
            "api_headers": self.api_headers,
            "api_params": self.api_params,
            "api_body": self.api_body,
            "arguments": [
                {
                    "name": arg.name,
                    "type": arg.type.value,
                    "description": arg.description,
                    "required": arg.required,
                    "placeholder": arg.placeholder,
                    "default": arg.default,
                    "group": arg.group,
                    "display_order": arg.display_order,
                    "min": arg.min,
                    "max": arg.max,
                    "enum": arg.enum,
                    "quoted": arg.quoted,
                    "validation": {
                        "pattern": arg.validation.pattern,
                        "message": arg.validation.message,
                    },
                }
                for arg in self.arguments
            ],
            "examples": [
                {
                    "name": ex.name,
                    "description": ex.description,
                    "arguments": ex.arguments,
                    "expected_use": ex.expected_use,
                }
                for ex in self.examples
            ],
        }

    def to_external_dict(self) -> Dict[str, Any]:
        """Return the tool definition in the new external schema format."""
        properties: Dict[str, Any] = {}
        required: List[str] = []

        for arg in self.arguments:
            properties[arg.name] = self._argument_to_schema_property(arg)
            if arg.required:
                required.append(arg.name)

        input_schema: Dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            input_schema["required"] = required

        if self.execution_type == "api":
            execution: Dict[str, Any] = {
                "type": "api",
                "method": self.api_method,
                "endpoint": self.api_endpoint,
            }
            if self.api_headers:
                execution["headers"] = self.api_headers
            if self.api_params:
                execution["params"] = self.api_params
            if self.api_body is not None:
                execution["body"] = self.api_body
        else:
            execution = {
                "type": "spl",
                "template": self.spl,
                "row_limiter": self.row_limiter,
                "time_range": self.time_range,
            }
            if self.guardrails:
                execution["guardrails"] = self.guardrails

        meta: Dict[str, Any] = {
            "tags": self.tags,
            "examples": [ex.to_dict() for ex in self.examples],
            "execution": execution,
        }
        if self.external_app:
            meta["external_app_id"] = self.external_app
        if self.required_app:
            meta["required_app"] = self.required_app
        if self.built_in:
            meta["built_in"] = True
        if self.saved_search:
            meta["saved_search"] = self.saved_search

        payload = {
            "tool_id": self.tool_id,
            "name": self.name,
            "title": self.title or self.name,
            "description": self.description,
            "inputSchema": input_schema,
            "_meta": meta,
        }
        return payload

    @staticmethod
    def _argument_to_schema_property(arg: ToolArgument) -> Dict[str, Any]:
        """Convert a ToolArgument into a JSON schema property."""
        prop: Dict[str, Any] = {"type": arg.type.value}
        if arg.description:
            prop["description"] = arg.description
        if arg.default is not None:
            prop["default"] = arg.default
        if arg.enum is not None:
            prop["enum"] = arg.enum
        if arg.min is not None:
            prop["minimum"] = arg.min
        if arg.max is not None:
            prop["maximum"] = arg.max
        if arg.validation and arg.validation.pattern:
            prop["pattern"] = arg.validation.pattern

        if arg.validation and arg.validation.message:
            prop["validation_message"] = arg.validation.message

        return prop


class ToolManager:
    """
    Manager for MCP tools with discovery and execution capabilities.

    This class provides centralized management of all available tools,
    including loading from configuration files, validation, and execution.

    Attributes:
        tools: Dictionary mapping tool IDs (_key) to Tool instances.
    """

    def __init__(self) -> None:
        """Initialize the tool manager."""
        self.tools: Dict[str, Tool] = {}
        self._builtin_tools: Dict[str, Tool] = {}
        self.enabled_tool_ids: Dict[str, str] = {}
        self._enabled_tools_loaded: bool = False
        self.tool_collision_detector: ToolCollisionDetector = (
            JaccardToolCollisionDetector(
                threshold=MCPSettings.get().jaccard_similarity_threshold
            )
        )
        logger.info("ToolManager initialized")

    def load_tools_from_file(
        self, file_path: str, mark_as_builtin: bool = False
    ) -> None:
        """
        Load tools from a JSON configuration file.

        Args:
            file_path: Path to the JSON file containing tool definitions.
            mark_as_builtin: If True, loaded tools are marked as built-in tools.

        Raises:
            Exception: If file loading or parsing fails.
        """
        logger.info("Loading tools from file: %s", file_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            tools_data = data.get("tools", [])
            loaded_count = 0

            for tool_data in tools_data:
                try:
                    tool = Tool.from_dict(tool_data)
                    self._register_tool(tool, mark_as_builtin=mark_as_builtin)
                    loaded_count += 1
                    logger.info("Loaded tool: %s", tool.name)
                except Exception as e:
                    logger.error(
                        "Failed to load tool from %s: %s",
                        tool_data.get("name", "unknown"),
                        e,
                    )

            logger.info("Successfully loaded %d tools from %s", loaded_count, file_path)

        except Exception as e:
            logger.error("Failed to load tools from file %s: %s", file_path, e)
            raise

    def _register_tool(self, tool: Tool, mark_as_builtin: bool = False) -> None:
        """
        Register a tool in the manager, optionally tracking it as built-in.
        """
        if not tool.tool_id:
            raise ValueError(f"Tool '{tool.name}' is missing required '_key'.")
        self.tools[tool.tool_id] = tool
        if mark_as_builtin:
            self._builtin_tools[tool.tool_id] = tool

    def _reset_to_builtin_tools(self) -> None:
        """
        Reset the in-memory tool list to only the built-in tools.
        """
        self.tools.clear()
        self.tools.update(self._builtin_tools)

    def _load_tools_from_kvstore(self, session_key: str) -> None:
        """
        Load custom tools from KV Store and add them to the manager.
        """
        kv_manager = KVStoreManager(
            session_key=session_key,
            collection="mcp_tools",
            owner="nobody",
        )

        try:
            response = kv_manager.query(output_mode="json", count="0")
        except Exception as e:
            logger.error("KV Store query for custom tools failed: %s", e)
            return

        if response.status_code != 200:
            logger.error(
                "KV Store returned status %s when loading tools: %s",
                response.status_code,
                getattr(response, "text", ""),
            )
            return

        try:
            records = response.json()
        except json.JSONDecodeError as e:
            logger.error("Failed to decode KV Store response: %s", e)
            return

        if not isinstance(records, list):
            logger.error("Unexpected KV Store response format: %s", records)
            return

        loaded_count = 0
        for tool_data in records:
            if not isinstance(tool_data, dict):
                continue
            try:
                tool = Tool.from_dict(tool_data)
                tool.built_in = bool(tool_data.get("built_in", False))
                self._register_tool(tool, mark_as_builtin=False)
                loaded_count += 1
            except Exception as e:
                logger.error(
                    "Failed to load custom tool '%s' from KV Store: %s",
                    tool_data.get("name", "unknown"),
                    e,
                )

        logger.info("Loaded %d custom tools from KV Store", loaded_count)

    def _prune_stale_collision_refs(
        self,
        enabled_tool: EnabledTool,
        tool_enabled_collection: ToolEnabledCollection,
    ) -> None:
        """
        Remove collision references that point to tools that no longer exist
        in tools or builtin_tools.
        """

        stale_ids = [
            tid
            for tid in enabled_tool.collision_ids
            if tid not in self._builtin_tools and tid not in self.tools
        ]

        for tid in stale_ids:
            logger.warning(f"Pruning stale collision ref: {tid}")
            enabled_tool.discard_collision(tid)

        if stale_ids:
            try:
                tool_enabled_collection.replace(enabled_tool)
            except Exception as e:
                logger.error(f"Failed to prune stale collision refs: {e}")

    def invalidate_enabled_tool_cache(self) -> None:
        """Mark the in-memory enabled tool map as stale.

        The next call to :meth:`_load_enabled_tool_map` will re-read
        from KV Store.  Call this after any operation that mutates the
        enabled-tools collection (enable, disable, delete, seed).
        """
        self._enabled_tools_loaded = False
        logger.info("Enabled tool cache invalidated")

    def _load_enabled_tool_map(self, session_key: str) -> None:
        """
        Load enabled tool mappings from KV Store.

        Results are cached in memory.  Subsequent calls are no-ops
        unless :meth:`invalidate_enabled_tool_cache` has been called.
        """
        if self._enabled_tools_loaded:
            logger.info("Enabled tool map already loaded, using cached data")
            return

        logger.info("Loading enabled tool map from KV Store...")
        tool_enabled_collection = ToolEnabledCollection(session_key)

        try:
            enabled_tools = tool_enabled_collection.get_all_enabled_tools()
            has_marker = tool_enabled_collection.has_seed_marker()
        except Exception as e:
            logger.error(f"Failed to load enabled tools from KV Store: {e}")
            return
        # This check actually ensures that builtin tools are seeded before anything else.
        if not enabled_tools and not has_marker:
            try:
                seeded = self._seed_builtin_tools_enabled(tool_enabled_collection)
                if seeded:
                    logger.info(
                        f"Seeded {seeded} built-in tools as enabled defaults",
                    )
                self._enabled_tools_loaded = True
                return
            except Exception as e:
                logger.error(f"Failed to seed built-in tools: {e}")
                return

        logger.info(f"Found {len(enabled_tools)} enabled tool records in KV Store")

        self.enabled_tool_ids.clear()
        for enabled_tool in enabled_tools:
            self._prune_stale_collision_refs(enabled_tool, tool_enabled_collection)
            self.enabled_tool_ids[enabled_tool.name] = enabled_tool.tool_id

            logger.info(
                "Loaded enabled tool: %s -> %s", enabled_tool.name, enabled_tool.tool_id
            )

        self._enabled_tools_loaded = True
        logger.info("Finished loading enabled tool map: %s", self.enabled_tool_ids)

    def _seed_builtin_tools_enabled(
        self,
        tool_enabled_collection: ToolEnabledCollection,
    ) -> int:
        """
        Seeds builtin tools and check for tool collisions between them.

        Called only when no enabled tools exist in KV Store, so collision
        detection starts from an empty set and only considers builtin tools.
        """
        if not self._builtin_tools:
            logger.info("No built-in tools available to seed enablement")
            return 0

        builtin_comparable: List[ComparableTool] = []
        seen_names: Set[str] = set()
        for tool in self._builtin_tools.values():
            tool_name = tool.name
            if not tool_name or not tool.tool_id:
                continue
            if tool_name in seen_names:
                logger.warning(
                    "Skipping duplicate built-in tool name '%s' while seeding enablement",
                    tool_name,
                )
                continue
            seen_names.add(tool_name)
            builtin_comparable.append(
                ComparableTool(
                    name=tool_name,
                    description=tool.description or "",
                    tool_id=tool.tool_id,
                )
            )

        if not builtin_comparable:
            return 0

        tools_to_seed: List[EnabledTool] = []
        for i, comparable_tool in enumerate(builtin_comparable):
            others = builtin_comparable[:i] + builtin_comparable[i + 1 :]
            collision_result = self._detect_collisions_for_tool(
                comparable_tool.name,
                comparable_tool.description,
                others,
            )
            tools_to_seed.append(
                EnabledTool(
                    name=comparable_tool.name,
                    tool_id=comparable_tool.tool_id,
                    collision_ids=collision_result.colliding_tools_ids,
                )
            )

        tool_enabled_collection.batch_save(
            tools_to_seed,
            push_seed_marker=True,
        )

        for tool in tools_to_seed:
            self.enabled_tool_ids[tool.name] = tool.tool_id

        logger.debug(f"Seeded enabled tool map: {self.enabled_tool_ids}")
        return len(tools_to_seed)

    def get_tool(self, name: str) -> Optional[Tool]:
        """
        Get a tool by name, only if it's enabled.

        Args:
            name: Tool name to retrieve.

        Returns:
            Tool instance if found and enabled, None otherwise.
        """
        # First check if the tool is enabled
        enabled_tool_id = self.enabled_tool_ids.get(name)
        if not enabled_tool_id:
            logger.info("Tool not enabled: %s", name)
            return None

        # Get the tool by its key (much more efficient than searching by name)
        tool = self.tools.get(enabled_tool_id)
        if tool:
            logger.info("Retrieved enabled tool: %s (key=%s)", name, enabled_tool_id)
        else:
            logger.warning(
                "Enabled tool not found in tools dict: %s (key=%s)",
                name,
                enabled_tool_id,
            )
        return tool

    def refresh_custom_tools(self, session_key: Optional[str]) -> None:
        """
        Reload custom tools from KV Store using the provided session key.
        """
        if not session_key:
            logger.warning(
                "Session key not provided; skipping custom tool refresh from KV Store"
            )
            return

        logger.info(
            "Starting refresh_custom_tools - before reset, have %d tools",
            len(self.tools),
        )
        self._reset_to_builtin_tools()
        logger.info("After reset to builtin, have %d tools", len(self.tools))
        self._load_tools_from_kvstore(session_key)
        logger.info("After loading from kvstore, have %d tools", len(self.tools))
        self._load_enabled_tool_map(session_key)
        logger.info(
            "After loading enabled map, have %d enabled tools",
            len(self.enabled_tool_ids),
        )

    def get_enabled_tool(self, tool_name: str, session_key: str) -> Optional[Tool]:
        """
        Retrieve a tool only if it is enabled, verified via a single KV Store lookup.

        This is more efficient than reloading the entire enabled tools map
        and is used in the tools/call path where only one tool needs verification.
        PersistentServer spawns multiple processes that don't share in-memory
        state, so we must check KV Store for authoritative enabled status.

        Returns:
            Tool instance if found and enabled, None otherwise.
        """
        tool_enabled_collection = ToolEnabledCollection(session_key)
        enabled_tool = tool_enabled_collection.get(tool_name)
        if not enabled_tool:
            logger.info("Tool not enabled in KV Store: %s", tool_name)
            return None

        tool = self.tools.get(enabled_tool.tool_id)
        if not tool:
            logger.warning(
                "Enabled tool not found in tools dict: %s (tool_id=%s)",
                tool_name,
                enabled_tool.tool_id,
            )
        return tool

    def refresh_enabled_tools(self, session_key: Optional[str]) -> None:
        """
        Reload the full enabled tools mapping from KV Store.

        Always invalidates the cache before loading to ensure fresh state.
        This is critical because PersistentServer spawns multiple processes
        that don't share in-memory state — a tool disabled in one process
        must be reflected in all others on the next call.
        """
        if not session_key:
            logger.warning(
                "Session key not provided; skipping enabled tools refresh from KV Store"
            )
            return
        self.invalidate_enabled_tool_cache()
        self._load_enabled_tool_map(session_key)

    def refresh_tools_for_listing(self, session_key: Optional[str]) -> None:
        """
        Refresh both custom tools and the enabled tools mapping using a single session key.

        This ensures KV-backed tool definitions and enablement state are loaded together,
        avoiding stale enabled maps when only custom tools are refreshed.
        """
        self.refresh_custom_tools(session_key)
        self.refresh_enabled_tools(session_key)

    @staticmethod
    def _tool_not_found_error(tool_name: str) -> Dict[str, Any]:
        return {
            "error": f"Tool '{tool_name}' is not currently enabled.",
            "code": "tool_not_found",
        }

    def disable_tool(
        self, tool_name: str, tool_id: str, session_key: str
    ) -> Tuple[int, Optional[Dict[str, Any]]]:
        """
        Disable a tool by removing its entry in the KV store and updating in-memory mappings.
        It also removes any collision references from other enabled tools.

        Returns:
            Tuple of (status_code, error_detail_if_any)
        """

        # Always reload tools as PersistentServer spawn many processes, and they don't share in-memory state (two different Tool Managers with different tools cache).
        self.refresh_custom_tools(session_key)

        tool_enabled_collection = ToolEnabledCollection(session_key)
        enabled_tool = tool_enabled_collection.get(tool_name)

        if enabled_tool is None:
            logger.debug("Tool '%s' is not enabled", tool_name)
            return 200, None

        colliding_tool_ids = list(enabled_tool.collision_ids)
        colliding_enabled_tools = tool_enabled_collection.get_by_tool_ids(
            colliding_tool_ids
        )

        # Update collision references
        for colliding_enabled_tool in colliding_enabled_tools:
            colliding_enabled_tool.discard_collision(tool_id)

        # Batch update all collision references in a single request
        tool_enabled_collection.batch_save(colliding_enabled_tools)

        # Delete the enabled tool
        tool_enabled_collection.delete(tool_name)

        self.invalidate_enabled_tool_cache()
        logger.info("Disabled tool '%s'", tool_name)
        return 200, None

    @staticmethod
    def _tool_name_conflict(
        conflicting_tool: Tool, detected_collision_result: ToolCollisionResult
    ) -> Dict[str, Any]:
        return {
            "error": "Another tool with the same name is already enabled.",
            "code": "tool_name_conflict",
            "conflict_tool": {
                "tool_id": conflicting_tool.tool_id,
                "external_app_id": conflicting_tool.external_app,
                "name": conflicting_tool.name,
                "built_in": conflicting_tool.built_in,
            },
            "colliding_tools_ids": list(detected_collision_result.colliding_tools_ids),
        }

    @staticmethod
    def _tool_collision_error(
        collision_results: ToolCollisionResult,
    ) -> Dict[str, Any]:
        return {
            "code": "tool_collision",
            "message": "Tool definition collides with existing tools.",
            "colliding_tools_ids": list(collision_results.colliding_tools_ids),
        }

    @staticmethod
    def _enabled_tools_to_comparable(
        enabled_tools: List[EnabledTool],
        tools_map: Dict[str, "Tool"],
    ) -> List[ComparableTool]:
        """
        Build a list of ComparableTool from enabled tools and the tools registry.

        Only includes enabled tools whose tool_id exists in tools_map.
        Used for collision detection without refetching from storage.
        """
        result: List[ComparableTool] = []
        for enabled_tool in enabled_tools:
            tool = tools_map.get(enabled_tool.tool_id)
            if tool is None:
                continue
            result.append(
                ComparableTool(
                    tool_id=enabled_tool.tool_id,
                    name=tool.name,
                    description=tool.description or "",
                )
            )
        return result

    def _detect_collisions_for_tool(
        self,
        tool_name: str,
        tool_description: str,
        existing_tools: List[ComparableTool],
    ) -> ToolCollisionResult:
        """
        Detect collisions between a tool and a list of existing tools.

        Callers must build and pass existing_tools (e.g. via _enabled_tools_to_comparable)
        so that storage is not queried repeatedly.
        """
        tool_metadata = ComparableTool(tool_name, tool_description or "")
        return self.tool_collision_detector.find_collisions(
            tool_metadata, existing_tools
        )

    def find_collisions(
        self, tool_ids: List[str], session_key: str
    ) -> Dict[str, List[str]]:
        tool_enabled_collection = ToolEnabledCollection(session_key)
        enabled_tools = tool_enabled_collection.get_all_enabled_tools()
        existing_comparable = self._enabled_tools_to_comparable(
            enabled_tools, self.tools
        )

        tools_to_compare: Set[ComparableTool] = set(existing_comparable)
        tools_to_check: Set[ComparableTool] = set()
        for tool_id in tool_ids:
            tool_to_check = self.tools.get(tool_id)
            if tool_to_check:
                comparable_tool = ComparableTool(
                    tool_id=tool_id,
                    name=tool_to_check.name,
                    description=tool_to_check.description,
                )
                tools_to_check.add(comparable_tool)
                tools_to_compare.add(comparable_tool)

        tools_collisions = {}
        for tool_to_check in tools_to_check:
            tools_to_compare.remove(tool_to_check)
            result = self.tool_collision_detector.find_collisions(
                tool_to_check, list(tools_to_compare)
            )
            tools_to_compare.add(tool_to_check)
            if len(result.colliding_tools_ids) > 0:
                tools_collisions[tool_to_check.tool_id] = list(
                    result.colliding_tools_ids
                )
        return tools_collisions

    @staticmethod
    def _update_collision_references_for_enabled_tool(
        tool_enabled_collection: ToolEnabledCollection,
        new_tool_id: str,
        colliding_tool_ids: Set[str],
    ) -> None:
        """
        Update existing enabled tool records to add new_tool_id to their collision_ids.

        Used after enabling a tool so that colliding tools reference each other.
        """
        if not colliding_tool_ids:
            return

        colliding_enabled_tools = tool_enabled_collection.get_by_tool_ids(
            list(colliding_tool_ids)
        )

        tools_to_save: List[EnabledTool] = []
        for colliding_enabled_tool in colliding_enabled_tools:
            colliding_enabled_tool.add_collision(new_tool_id)
            tools_to_save.append(colliding_enabled_tool)

        tool_enabled_collection.batch_save(tools_to_save)

    def _enable_tool(
        self,
        session_key: str,
        tool_name: str,
        tool_id: str,
        collisions_detection_result: ToolCollisionResult,
    ) -> None:
        enabled_tool = EnabledTool(
            tool_id=tool_id,
            name=tool_name,
            collision_ids=collisions_detection_result.colliding_tools_ids,
        )
        tool_enabled_collection = ToolEnabledCollection(session_key)
        tool_enabled_collection.upsert(enabled_tool)
        self._update_collision_references_for_enabled_tool(
            tool_enabled_collection,
            tool_id,
            collisions_detection_result.colliding_tools_ids,
        )
        self.invalidate_enabled_tool_cache()
        self.refresh_enabled_tools(session_key)

    def enable_tool(
        self,
        tool_name: str,
        tool_id: str,
        session_key: str,
        override: bool = False,
    ) -> Tuple[int, Optional[Dict[str, Any]]]:
        """
        Enable a tool by writing to the enablement KV store.

        Returns:
            Tuple of (status_code, error_payload_if_any)
        """
        # Always reload tools as PersistentServer spawn many processes, and they don't share in-memory state (two different Tool Managers with different tools cache).
        # Use refresh_tools_for_listing so the enabled-tool cache is invalidated
        # and builtin tools are re-seeded if the collection was cleared externally.
        self.refresh_tools_for_listing(session_key)

        tool = self.tools.get(tool_id)
        if tool is None:
            return 404, self._tool_not_found_error(tool_name)

        tool_enabled_collection = ToolEnabledCollection(session_key)
        already_enabled_tool = tool_enabled_collection.get(tool_name)
        existing_enabled = tool_enabled_collection.get_all_enabled_tools()
        existing_comparable = self._enabled_tools_to_comparable(
            existing_enabled, self.tools
        )
        collision_detection_result = self._detect_collisions_for_tool(
            tool_name, tool.description or "", existing_comparable
        )
        if not override:
            if already_enabled_tool:
                conflicting_tool = self.tools[already_enabled_tool.tool_id]
                return (
                    409,
                    self._tool_name_conflict(
                        conflicting_tool, collision_detection_result
                    ),
                )
            elif collision_detection_result.has_collisions():
                return (
                    409,
                    self._tool_collision_error(collision_detection_result),
                )

        # If we're overriding an existing tool, we need to disable it first to remove all collision references.
        if override and already_enabled_tool:
            self.disable_tool(
                already_enabled_tool.name, already_enabled_tool.tool_id, session_key
            )

        # Beware! Tool name in the enabled tools collection is something different from tool.name from the tools dictionary
        self._enable_tool(session_key, tool_name, tool_id, collision_detection_result)
        logger.info("Enabled tool '%s' with id '%s'", tool_name, tool_id)
        return 200, None

    def list_enabled_tools(self, session_key: str) -> List[EnabledTool]:
        # Always reload tools as PersistentServer spawn many processes, and they don't share in-memory state (two different Tool Managers with different tools cache).
        self.refresh_custom_tools(session_key)
        self.refresh_enabled_tools(session_key)

        tool_enabled_collection = ToolEnabledCollection(session_key)
        return tool_enabled_collection.get_all_enabled_tools()

    def list_tools(self, enabled_only: bool = True, installed_apps=None) -> List[Tool]:
        """
        List all available tools.

        Args:
            enabled_only: Deprecated parameter retained for compatibility.
            installed_apps: List of installed app names.

        Returns:
            List of Tool instances.
        """
        if installed_apps is None:
            installed_apps = set()
        # Filter tools based on required_app

        logger.info(
            "list_tools called - have %d total tools and %d enabled mappings",
            len(self.tools),
            len(self.enabled_tool_ids),
        )
        logger.info("Enabled tool mappings: %s", self.enabled_tool_ids)

        enabled_map = self.enabled_tool_ids
        enabled_ids = set(enabled_map.values())
        tools: List[Tool] = []
        for tool in self.tools.values():
            logger.info("Checking tool %s (key=%s)", tool.name, tool.tool_id)
            if tool.required_app and tool.required_app not in installed_apps:
                logger.info(
                    "Tool %s skipped - required_app %s not in installed apps",
                    tool.name,
                    tool.required_app,
                )
                continue
            enabled_tool_id = enabled_map.get(tool.name)
            logger.info(
                "Tool %s: enabled_tool_id=%s, tool.tool_id=%s",
                tool.name,
                enabled_tool_id,
                tool.tool_id,
            )
            if tool.tool_id not in enabled_ids:
                logger.info("Tool %s skipped - not enabled", tool.name)
                continue
            tools.append(tool)
            logger.info("Tool %s included in results", tool.name)

        logger.info("Listed %d tools (enabled_only=%s)", len(tools), enabled_only)
        return tools

    def reload_tools(self, session_key: Optional[str] = None) -> None:
        """
        Reload all tools from configuration files.

        This method clears existing tools and reloads from the default
        built-in tools configuration file.
        """
        logger.info("Reloading all tools")

        self.tools.clear()
        self._builtin_tools.clear()
        self.enabled_tool_ids.clear()
        self._enabled_tools_loaded = False

        # Compute base path once
        import os

        base_path = os.path.abspath(os.path.dirname(__file__))

        # Load built-in tools from default/builtin_tools.json
        default_dir = os.path.join(base_path, "../default")
        builtin_file = os.path.join(default_dir, "builtin_tools.json")

        if os.path.exists(builtin_file):
            self.load_tools_from_file(builtin_file, mark_as_builtin=True)
        else:
            logger.warning("Built-in tools file not found at %s", builtin_file)

        # Load local tools and override defaults if present
        local_dir = os.path.join(base_path, "../local")
        local_file = os.path.join(local_dir, "builtin_tools.json")
        if os.path.exists(local_file):
            logger.info("Merging local tools from: %s", local_file)
            self.load_tools_from_file(local_file)

        if session_key:
            self._load_tools_from_kvstore(session_key)

    def validate_tool_config(self, tool_data: Dict[str, Any]) -> List[str]:
        """
        Validate tool configuration without loading it.

        Args:
            tool_data: Tool configuration dictionary.

        Returns:
            List of validation error messages (empty if valid).
        """
        errors = []

        try:
            # Basic validation by attempting to create Tool
            Tool.from_dict(tool_data)

            # Additional custom validations
            errors.extend(self._validate_quoted_enum_constraint(tool_data))

        except Exception as e:
            errors.append(str(e))

        return errors

    def _validate_quoted_enum_constraint(self, tool_data: Dict[str, Any]) -> List[str]:
        """
        Validate that quoted arguments do not have enum constraints.

        Quoted arguments are meant for free-form text input and should not be
        restricted to predefined enum values, as this creates a logical conflict.

        Args:
            tool_data: Tool configuration dictionary.

        Returns:
            List of validation error messages.
        """
        errors = []
        tool_name = tool_data.get("name", "unknown")
        arguments = tool_data.get("arguments", [])

        for arg in arguments:
            arg_name = arg.get("name", "unknown")
            is_quoted = arg.get("quoted", True)  # Default is True
            has_enum = arg.get("enum") is not None

            if is_quoted and has_enum:
                errors.append(
                    f"Tool '{tool_name}', argument '{arg_name}': "
                    f"Quoted arguments cannot have enum constraints. "
                    f"Remove either 'quoted: true' or the 'enum' property."
                )

        return errors


def get_default_manager(reload: bool = False) -> ToolManager:
    """
    Get the default singleton ToolManager instance.

    Most callers should pass reload=False (the default). Tool definitions
    are static JSON schemas that don't change at runtime — they only need
    to be loaded once (which happens automatically on first creation).
    Enablement state is checked per-request via get_enabled_tool() against
    KV Store, so there's no need to reload definitions from disk on every
    request.  Use reload=True only for one-time initialization (e.g., the
    standalone HTTP server at startup).

    Note: When PersistentServer spawns a new process, _default_manager
    starts as None, so the first call always forces a full reload
    regardless of the reload flag. This means every new process gets
    a fresh tool load from disk — reload=False only prevents redundant
    reloads within the same process on subsequent requests.

    Args:
        reload: If True, reload tools from configuration files.

    Returns:
        ToolManager instance.
    """
    global _default_manager

    with _manager_lock:
        if _default_manager is None:
            logger.info("Creating default ToolManager instance")
            _default_manager = ToolManager()
            reload = True  # Force reload on first creation

        if reload:
            _default_manager.reload_tools()

    return _default_manager


# Public API exports
__all__ = [
    "ArgumentType",
    "ToolArgument",
    "ToolExample",
    "Tool",
    "ToolManager",
    "get_default_manager",
]
