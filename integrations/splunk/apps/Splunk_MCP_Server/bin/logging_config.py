"""
Centralized logging configuration for the MCP Splunk Server application.

This module provides a consistent logging setup across all components,
ensuring standardized log formats and levels throughout the application.
"""

from __future__ import annotations

import contextvars
import functools
import hashlib
import json
import logging
import logging.handlers
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

# Request/session scoped logging context
LogValue = Union[str, int, float]
_LOG_CONTEXT: contextvars.ContextVar[Dict[str, LogValue]] = contextvars.ContextVar(
    "mcp_log_context", default={}
)

# Request-scoped traceparent for distributed tracing propagation.
_TRACEPARENT: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "mcp_traceparent", default=None
)


def get_traceparent() -> Optional[str]:
    """Return the traceparent header stored for the current request."""
    return _TRACEPARENT.get()


def update_log_context_traceparent(traceparent: Optional[str]) -> None:
    """Store the raw traceparent and add it to the log context."""
    if not traceparent or not isinstance(traceparent, str):
        return
    _TRACEPARENT.set(traceparent)
    update_log_context(traceparent=traceparent)


def set_log_context(ctx: Dict[str, LogValue]) -> None:
    """Replace the current log context for this execution context."""
    _LOG_CONTEXT.set(dict(ctx or {}))


def update_log_context_req_id() -> None:
    """
    Set a request ID for the current execution context.
    """
    request_id = f"{os.urandom(6).hex()}"
    update_log_context(request_id=request_id)


def update_log_context_user_id(user_id: str) -> None:
    if user_id is str:
        hashed_user_id = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:16]
        update_log_context(user_id=hashed_user_id)


def update_log_context(**kwargs: Any) -> None:
    """Update the current log context with new key/values."""
    cur = dict(_LOG_CONTEXT.get())
    cur.update({k: v for k, v in kwargs.items() if v is not None})
    _LOG_CONTEXT.set(cur)


def log_telemetry(event_type: str, status_code: int, **kwargs: Any) -> None:
    """Write a telemetry event to mcp_monitoring_dashboard.log.

    Current log context fields are added automatically by MCPContextFilter; only telemetry-specific fields need to be passed here.
    """
    splunk_home = os.environ.get("SPLUNK_HOME")
    log_file = (
        os.path.join(
            splunk_home, "var", "log", "splunk", "mcp_monitoring_dashboard.log"
        )
        if splunk_home
        else None
    )
    telemetry_logger = setup_logging(logger_name="mcp_telemetry", log_file=log_file)
    extra: Dict[str, Any] = {
        "event_type": event_type,
        "status_code": status_code,
        "is_success": 200 <= status_code < 300,
    }
    extra.update({k: v for k, v in kwargs.items() if v is not None})
    telemetry_logger.info("telemetry", extra=extra)


def clear_log_context() -> None:
    """Clear the current log context and request-scoped traceparent."""
    _LOG_CONTEXT.set({})
    _TRACEPARENT.set(None)


class MCPContextFilter(logging.Filter):
    """Injects contextvars-based fields (e.g., source_ip) into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            ctx = _LOG_CONTEXT.get()
            for k, v in ctx.items():
                # Don't overwrite explicitly provided extras
                if not hasattr(record, k):
                    setattr(record, k, v)
        except Exception:
            pass
        return True


class MCPLogFormatter(logging.Formatter):
    """Custom JSON formatter for MCP application logs."""

    def formatTime(
        self, record: logging.LogRecord, datefmt: Optional[str] = None
    ) -> str:
        # ISO-8601 with milliseconds and Zulu timezone, e.g., 2025-08-28T12:34:56.789Z
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "pid": record.process,
            "message": record.getMessage(),
        }

        # Include optional context when available
        if hasattr(record, "source_ip"):
            log_obj["source_ip"] = record.source_ip
        if record.exc_info:
            try:
                log_obj["exception"] = self.formatException(record.exc_info)
            except Exception:
                log_obj["exception"] = "Exception info unavailable"

        # Merge any extra attributes (excluding default LogRecord attrs)
        default_keys = set(vars(logging.makeLogRecord({})).keys())
        for key, value in record.__dict__.items():
            if key not in default_keys and key not in log_obj:
                try:
                    json.dumps({key: value})  # test serializability
                    log_obj[key] = value
                except Exception:
                    log_obj[key] = str(value)

        return json.dumps(log_obj, separators=(",", ":"))


def _get_caller_module_name() -> str:
    """
    Get the name of the calling module.

    Returns:
        The name of the module that called the logging function.
    """
    frame = sys._getframe(2)  # Go up 2 frames to get the actual caller
    return frame.f_globals.get("__name__", "mcp_app")


def _create_file_handler(
    log_file: str,
    level: int,
    enable_rotation: bool = True,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Handler:
    """
    Create a file handler with optional rotation.

    Args:
        log_file: Path to the log file
        level: Logging level
        enable_rotation: Whether to enable log rotation
        max_bytes: Maximum size before rotation
        backup_count: Number of backup files to keep

    Returns:
        Configured file handler

    Raises:
        OSError: If the log file or directory cannot be created
    """

    if enable_rotation:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
    else:
        handler = logging.FileHandler(log_file)

    handler.setLevel(level)
    handler.setFormatter(MCPLogFormatter())
    return handler


def _create_stderr_handler(level: int) -> logging.Handler:
    """
    Create a stderr handler.

    Args:
        level: Logging level

    Returns:
        Configured stderr handler
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(MCPLogFormatter())
    return handler


def _configure_logger(
    logger: logging.Logger,
    level: int,
    log_file: Optional[str] = None,
    enable_rotation: bool = True,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    clear_handlers: bool = False,
) -> None:
    """
    Configure a logger with standardized settings.

    Args:
        logger: Logger instance to configure
        level: Logging level
        log_file: Optional log file path
        enable_rotation: Whether to enable log rotation
        max_bytes: Maximum size before rotation
        backup_count: Number of backup files to keep
        clear_handlers: Whether to clear existing handlers
    """
    logger.setLevel(level)

    if clear_handlers and logger.handlers:
        logger.handlers.clear()
    elif logger.handlers and not clear_handlers:
        # Update existing handler levels
        for handler in logger.handlers:
            handler.setLevel(level)
        return

    try:
        if log_file:
            handler = _create_file_handler(
                log_file, level, enable_rotation, max_bytes, backup_count
            )
        else:
            handler = _create_stderr_handler(level)

        # Attach the context filter so all records include context fields
        handler.addFilter(MCPContextFilter())
        logger.addHandler(handler)

    except (OSError, PermissionError) as e:
        # Fallback to stderr if file logging fails
        stderr_handler = _create_stderr_handler(level)
        stderr_handler.addFilter(MCPContextFilter())
        logger.addHandler(stderr_handler)
        if log_file:
            logger.error(
                f"Failed to create file handler for {log_file}, using stderr: {e}"
            )

    logger.propagate = False


def setup_logging(
    level: int = logging.INFO,
    logger_name: Optional[str] = None,
    log_file: Optional[str] = None,
    enable_rotation: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> logging.Logger:
    """
    Set up standardized logging for the MCP application with optional rotation.

    Args:
        level: Logging level (default: INFO)
        logger_name: Name of the logger. If None, uses the calling module's name.
        log_file: Path to log file. If provided, logs will be written to both stderr and the file.
        enable_rotation: Whether to enable log rotation (default: True)
        max_bytes: Maximum size of log file before rotation in bytes (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)

    Returns:
        Configured logger instance.
    """
    if logger_name is None:
        logger_name = _get_caller_module_name()

    logger = logging.getLogger(logger_name)

    # Avoid duplicate handlers if logger is already configured
    if logger.handlers:
        logger.setLevel(level)
        for handler in logger.handlers:
            handler.setLevel(level)
        return logger

    _configure_logger(logger, level, log_file, enable_rotation, max_bytes, backup_count)
    return logger


def _sanitize_logger_name(name: str) -> str:
    """Extract a clean module name from Splunk's mangled ``__name__``.

    Splunk's persistent connection framework rewrites ``__name__`` into a
    path-encoded string like::

        pschand__oauth_protected_resource_metadata_handler__in__Users_vishwupa_...

    This function detects the pattern and extracts just the module name
    (``oauth_protected_resource_metadata_handler``).  Non-mangled names are
    returned unchanged.
    """
    if "__in__" in name:
        # Strip the "pschand__" prefix and everything from "__in__" onward.
        name = name.split("__in__")[0]
        if name.startswith("pschand__"):
            name = name[len("pschand__") :]
    return name


def get_logger(name: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """
    Get a logger instance with standardized configuration.

    Args:
        name: Logger name. If None, uses the calling module's name.
        level: Logging level (default: INFO, can be overridden for debug mode).

    Returns:
        Configured logger instance.
    """
    if name is None:
        name = _get_caller_module_name()

    name = _sanitize_logger_name(name)

    # Use Splunk's standard log directory
    splunk_home = os.environ.get("SPLUNK_HOME")
    if splunk_home:
        log_file = os.path.join(splunk_home, "var", "log", "splunk", "mcp_server.log")
        return setup_logging(level=level, logger_name=name, log_file=log_file)

    return setup_logging(level=level, logger_name=name)


def set_debug_mode() -> None:
    """
    Enable debug mode for all MCP loggers.

    This function sets all existing MCP loggers to DEBUG level
    and configures the root logger appropriately.
    """
    # Set root logger to DEBUG
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Update all existing loggers that start with our module names
    for logger_name in logging.getLogger().manager.loggerDict:
        if any(
            logger_name.startswith(prefix)
            for prefix in ["mcp_", "tool_", "settings", "splunk_api", "logging_config"]
        ):
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.DEBUG)
            for handler in logger.handlers:
                handler.setLevel(logging.DEBUG)


def operation_logger(operation_type: str):
    """Decorator to log start/end timing and status of an operation.

    Apply it to a function that returns (status_code, payload).
    The decorator records timing, updates the contextual logging fields
    (operation_type, operation_phase, execution_time_seconds) and emits
    start / completion log lines at INFO or ERROR (>=400).

    Args:
        operation_type: Stable identifier describing the wrapped logical operation.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            log = get_logger("operation_logger")
            start_time = time.time()
            update_log_context(operation_type=operation_type, operation_phase="start")
            log.info("Operation started: %s", operation_type)
            update_log_context(
                operation_type=operation_type, operation_phase="in_progress"
            )
            status_code: int = 500
            try:
                result = func(*args, **kwargs)
                if isinstance(result, tuple) and result:
                    sc = result[0]
                    if isinstance(sc, int):
                        status_code = sc
                    else:
                        status_code = 200
                else:
                    status_code = 200
                return result
            except Exception:
                # status_code remains 500
                raise
            finally:
                execution_time = time.time() - start_time
                update_log_context(
                    operation_type=operation_type,
                    operation_phase="end",
                    status=status_code,
                    execution_time_seconds=round(execution_time, 3),
                )
                if status_code >= 400:
                    log.error("Operation completed: %s", operation_type)
                else:
                    log.info("Operation completed: %s", operation_type)

        return wrapper

    return decorator
