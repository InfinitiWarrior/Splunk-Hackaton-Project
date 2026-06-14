"""Small in-memory admission controls for MCP requests."""

from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple


@dataclass(frozen=True)
class RateLimitConfig:
    global_limit: int
    tenant_authenticated_limit: int = 240
    tenant_unauthenticated_limit: int = 60
    circuit_breaker_failure_threshold: int = 20
    circuit_breaker_cooldown_seconds: int = 30


class RequestAdmissionController:
    """Sliding-window quotas + basic circuit breaker."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._sweep_interval = 128
        self._admit_count = 0
        self._lock = threading.Lock()
        self._global_window: Deque[float] = deque()
        self._tenant_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def admit(
        self,
        source_ip: str,
        config: RateLimitConfig,
        is_authenticated: bool = False,
        authenticated_identity: Optional[str] = None,
        record: bool = True,
    ) -> Tuple[bool, int, str]:
        now = time.monotonic()
        with self._lock:
            vals = (
                config.tenant_authenticated_limit,
                config.tenant_unauthenticated_limit,
                config.circuit_breaker_failure_threshold,
                config.circuit_breaker_cooldown_seconds,
            )
            if config.global_limit < 0 or any(v <= 0 for v in vals):
                return False, 503, "Rate-limiting controls not satisfied"

            if now < self._circuit_open_until:
                return False, 503, "Circuit breaker is open"

            cutoff = now - self.window_seconds
            if config.global_limit > 0:
                while self._global_window and self._global_window[0] <= cutoff:
                    self._global_window.popleft()
                if len(self._global_window) >= config.global_limit:
                    return False, 429, "Global request budget exceeded"
            elif self._global_window:
                # Drop stale bookkeeping if global admission limiting is disabled.
                self._global_window.clear()

            if record:
                self._admit_count += 1
            if record and self._admit_count % self._sweep_interval == 0:
                self._prune_stale_tenant_windows(cutoff)

            if is_authenticated and authenticated_identity:
                token_hash = hashlib.sha256(
                    authenticated_identity.encode("utf-8")
                ).hexdigest()[:24]
                tenant_key = f"auth:{token_hash}"
                tenant_limit = config.tenant_authenticated_limit
            else:
                tenant_key = f"ip:{source_ip or 'unknown'}"
                tenant_limit = config.tenant_unauthenticated_limit

            tenant_window = self._tenant_windows[tenant_key]
            while tenant_window and tenant_window[0] <= cutoff:
                tenant_window.popleft()
            if len(tenant_window) >= tenant_limit:
                return False, 429, "Per-tenant request budget exceeded"

            if record and config.global_limit > 0:
                self._global_window.append(now)
            if record:
                tenant_window.append(now)
            return True, 200, ""

    def _prune_stale_tenant_windows(self, cutoff: float) -> None:
        """Prune expired entries and remove empty tenant buckets."""
        for key in list(self._tenant_windows.keys()):
            window = self._tenant_windows.get(key)
            if window is None:
                continue
            while window and window[0] <= cutoff:
                window.popleft()
            if not window:
                self._tenant_windows.pop(key, None)

    def record_result(self, status_code: int, config: RateLimitConfig) -> None:
        with self._lock:
            if status_code >= 500:
                self._consecutive_failures += 1
                if (
                    self._consecutive_failures
                    >= config.circuit_breaker_failure_threshold
                ):
                    self._circuit_open_until = (
                        time.monotonic() + config.circuit_breaker_cooldown_seconds
                    )
                    self._consecutive_failures = 0
            else:
                self._consecutive_failures = 0
