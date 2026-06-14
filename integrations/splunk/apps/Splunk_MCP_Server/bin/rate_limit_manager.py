from __future__ import annotations

import json
import os
import sys
import time
import types
from collections.abc import Collection
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from config_files_manager import ConfigFileManager
from filelock import FileLock, Timeout
from logging_config import get_logger
from typing_extensions import override

logger = get_logger(__name__)

GLOBAL_COUNTER_KEY = "global"


@dataclass
class RateLimits:
    data: Dict[str, int] = field(default_factory=dict)
    time_window_seconds: int = 60

    @property
    def global_limit(self) -> int:
        """Get the global rate limit. Returns 0 if no limit is set."""
        return self.data.get("global", 0)

    def get_tool_limit(self, tool_id: str) -> int:
        """Get the rate limit for a specific tool. Returns 0 if no limit is set."""
        return self.data.get(tool_id, 0)

    def limits_to_enforce(self, tool_id: str) -> list[Tuple[str, int]]:
        result: list[Tuple[str, int]] = []
        global_limit = self.data.get(GLOBAL_COUNTER_KEY, 0)
        if global_limit > 0:
            result.append((GLOBAL_COUNTER_KEY, global_limit))
        tool_limit = self.data.get(tool_id, 0)
        if tool_limit > 0 and tool_id != GLOBAL_COUNTER_KEY:
            result.append((tool_id, tool_limit))
        return result

    def prune_nonexistent_tools(
        self, existing_tool_ids: Collection[str]
    ) -> "RateLimits":
        """Return limits with entries for nonexistent tools removed. Keeps 'global'."""
        excluded_keys: Collection[str] = {GLOBAL_COUNTER_KEY}
        pruned = {
            tool_id: value
            for tool_id, value in self.data.items()
            if tool_id in existing_tool_ids or tool_id in excluded_keys
        }
        return RateLimits(data=pruned)


@dataclass
class RateLimitDTO:
    limits: Dict[str, int]

    @classmethod
    def from_json_string(cls, json_string: str) -> "RateLimitDTO":
        parsed = json.loads(json_string)
        data = {
            key: int(value["requests"])
            for key, value in parsed.items()
            if value["requests"] is not None
        }
        return cls(limits=data)

    @classmethod
    def from_settings(cls, rate_limits: RateLimits) -> "RateLimitDTO":
        return cls(limits=dict(rate_limits.data))

    def as_api_response(self) -> Dict[str, Any]:
        return {key: {"requests": value} for key, value in self.limits.items()}

    def validate(self) -> Dict[str, str]:
        """Return validation errors. Empty dict means valid."""
        return {
            k: "value must be non-negative" for k, v in self.limits.items() if v < 0
        }


class _RateLimitConfig:
    """
    RateLimitConfig is a class that manages the rate limits for the MCP server.
    """

    def __init__(self, config_file_manager: ConfigFileManager) -> None:
        self.config_file_manager = config_file_manager
        self.stanza_name = "rate_limits"
        self.config_file_name = "mcp"

    def get_rate_limits(self) -> RateLimits:
        """
        Get the rate limits from the config file.
        """
        rate_limits_data = self.config_file_manager.get_stanza(
            self.config_file_name, self.stanza_name
        )
        if rate_limits_data is None:
            return RateLimits(data={})

        rate_limits_parsed: Dict[str, int] = {}
        for key, value in rate_limits_data.items():
            try:
                # Parsing the values as config values are strings
                rate_limits_parsed[key] = int(value)
            except (ValueError, TypeError):
                # Config API doesn't support deletion of keys, so we ignore errors here.
                logger.error(
                    f"Error parsing rate limit for tool {key}: {value}. Value must be an integer. Ignoring."
                )
                continue

        return RateLimits(data=rate_limits_parsed)

    def update_rate_limits(self, new_rate_limits: RateLimits) -> bool:
        """
        Update the rate limits in the config file.
        """
        return self.config_file_manager.update_stanza(
            self.config_file_name, self.stanza_name, new_rate_limits.data
        )


@dataclass
class RateLimitCounterExceeded(Exception):
    """Raised when a rate limit is exceeded."""

    key: str
    count: int
    limit: int

    @override
    def __str__(self) -> str:
        return f"key={self.key} count={self.count} limit={self.limit}"


@dataclass
class _RateLimitCounter:
    """
    _RateLimitCounter is a class that represents a rate limit counter.
    """

    key: str
    count: int

    def _increment(self):
        self.count += 1

    def try_record(self, limit: int) -> None:
        """
        Try to record a request for the counter.

        Raises:
            RateLimitCounterExceeded: If the rate limit is exceeded.
        """
        if self.count >= limit:
            raise RateLimitCounterExceeded(key=self.key, count=self.count, limit=limit)

        self._increment()


LAST_RESET_AT_KEY = "last_reset_at"


class _RateLimitCounters:
    """
    RateLimitCounters is a class that represents the rate limit counters.
    """

    def __init__(
        self, last_reset_at: int, counters: dict[str, _RateLimitCounter]
    ) -> None:
        self.last_reset_at: int = last_reset_at
        self._counters: dict[str, _RateLimitCounter] = counters

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> "_RateLimitCounters":
        last_reset_at: int = data.get(LAST_RESET_AT_KEY, 0)
        counters = {
            key: _RateLimitCounter(key=key, count=value)
            for key, value in data.items()
            if key != LAST_RESET_AT_KEY
        }

        return cls(
            last_reset_at=last_reset_at,
            counters=counters,
        )

    def get_counter(self, key: str) -> _RateLimitCounter:
        if key not in self._counters:
            self._counters[key] = _RateLimitCounter(key=key, count=0)
        return self._counters[key]

    def check_time_window(self, now: int, time_window_seconds: int) -> None:
        """
        If the time window has expired, reset all counters and start a new window.
        """
        if self.last_reset_at + time_window_seconds < now:
            self._reset(timestamp=now)

    def _reset(self, timestamp: int) -> None:
        """Reset all counters and set the window start. For admin/manual reset."""
        self.last_reset_at = timestamp
        self._counters.clear()

    def to_dict(self) -> dict[str, int]:
        return {
            LAST_RESET_AT_KEY: self.last_reset_at,
            **{tool_id: counter.count for tool_id, counter in self._counters.items()},
        }


class RateLimitStorage:
    """
    Storage for rate limits. Must be called within lock context.

    Attributes:
        storage_file: Path to the storage file
    """

    def __init__(self, storage_file: Path):
        self.storage_file: Path = Path(storage_file)
        self.storage_file.parent.mkdir(parents=True, exist_ok=True)

    @override
    def get(self) -> _RateLimitCounters:
        if not self.storage_file.exists():
            return _RateLimitCounters(last_reset_at=0, counters={})
        try:
            with open(self.storage_file, "r") as f:
                data = json.load(f)
            return _RateLimitCounters.from_dict(data)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Error getting rate limit counters: {e}")
            # we assume there was something wrong with the db file and we want to proceed with fresh state
            return _RateLimitCounters(last_reset_at=0, counters={})

    @override
    def set(self, rate_limit_collection: _RateLimitCounters) -> None:
        temp_file = self.storage_file.with_suffix(".tmp")
        try:
            with temp_file.open("w") as f:
                json.dump(rate_limit_collection.to_dict(), f)
            _ = temp_file.replace(self.storage_file)
        except Exception:
            if temp_file.exists():
                temp_file.unlink()
            raise


@dataclass
class FileLockAcquisitionError(Exception):
    """Raised when a file lock cannot be acquired."""

    lock_file: str
    max_retries: int

    @override
    def __str__(self) -> str:
        return f"Failed to acquire lock on file {self.lock_file} with max retries {self.max_retries}"


class RateLimitStorageWithLock:
    """
    Storage for rate limits with lock. It will acquire a lock on the storage file and return the storage object.
    """

    def __init__(self, storage: RateLimitStorage):
        self.storage: RateLimitStorage = storage
        self.lock_file: str = str(storage.storage_file) + ".lock"
        self._max_retries: int = 20
        self._lock: FileLock = FileLock(self.lock_file, timeout=self._max_retries * 0.2)

    def __enter__(self) -> RateLimitStorage:
        try:
            self._lock.acquire()
        except Timeout:
            raise FileLockAcquisitionError(
                lock_file=self.lock_file, max_retries=self._max_retries
            )
        return self.storage

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[types.TracebackType],
    ) -> None:
        self._lock.release()


class RateLimitManager:
    """
    RateLimitManager is the main entry point for interacting with the rate limits.

    Uses file-based storage with filelock for correct behavior under
    concurrent requests on a single node.

    Note: Counting is per-node basis and does not provide synchronization across
    the Splunk cluster. Each node maintains its own counters independently.
    """

    def __init__(self, session_key: str) -> None:
        config_file_manager = ConfigFileManager(session_key=session_key)
        self._rate_limit_config: _RateLimitConfig = _RateLimitConfig(
            config_file_manager=config_file_manager,
        )
        storage_file = (
            Path(__file__).parent.parent / "local" / "data" / "rate_limit_counters.json"
        )
        storage = RateLimitStorage(storage_file=storage_file)
        self._rate_limit_storage_with_lock: RateLimitStorageWithLock = (
            RateLimitStorageWithLock(storage)
        )

    def get_rate_limits(self) -> RateLimits:
        """
        Get the rate limits from the config file.
        """
        return self._rate_limit_config.get_rate_limits()

    def update_rate_limits(self, new_rate_limits: RateLimits) -> bool:
        """
        Update the rate limits in the config file.
        """
        updated = self._rate_limit_config.update_rate_limits(new_rate_limits)
        if not updated:
            return False

        # Reset counters when limits change so enforcement starts from a
        # clean window under the new policy.
        with self._rate_limit_storage_with_lock as storage:
            rate_limit_counters = storage.get()
            rate_limit_counters._reset(timestamp=int(time.time()))
            storage.set(rate_limit_counters)
        return True

    def enforce_rate_limits(
        self, tool_id: str, rate_limits: Optional[RateLimits] = None
    ) -> None:
        """
        Enforce rate limits for a specific tool, recording the request if within limits.

        Args:
            tool_id: The tool identifier to enforce limits for.
            rate_limits: Pre-fetched rate limits to avoid a redundant REST call.
                If None, limits are fetched from the config store.

        Raises:
            RateLimitCounterExceeded: If the rate limit is exceeded.
        """
        if rate_limits is None:
            rate_limits = self.get_rate_limits()
        limits_list = rate_limits.limits_to_enforce(tool_id=tool_id)
        if not limits_list:
            return

        with self._rate_limit_storage_with_lock as storage:
            rate_limit_counters = storage.get()
            now = int(time.time())

            rate_limit_counters.check_time_window(
                now=now, time_window_seconds=rate_limits.time_window_seconds
            )
            for key, limit in limits_list:
                counter = rate_limit_counters.get_counter(key=key)
                counter.try_record(
                    limit=limit,
                )

            storage.set(rate_limit_counters)


__all__ = [
    "RateLimitDTO",
    "RateLimits",
    "RateLimitManager",
    "RateLimitCounterExceeded",
    "FileLockAcquisitionError",
]
