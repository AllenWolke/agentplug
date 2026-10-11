"""Resolve the Agent execution mode at one shared SDK boundary.

The modular-singleton production path must be platform-owned.  Local queue
execution remains useful for isolated development and unit tests, but it must
never be selected implicitly by a production container.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


class RuntimeModeError(RuntimeError):
    """Raised when an Agent execution mode would bypass the platform."""


@dataclass(frozen=True, slots=True)
class RuntimeMode:
    platform_base_url: str
    executor: str
    production: bool

    @property
    def platform_owned(self) -> bool:
        return bool(self.platform_base_url) and self.executor == "platform"


def resolve_runtime_mode(env: Mapping[str, str] | None = None) -> RuntimeMode:
    """Return a validated mode and fail closed for production fallbacks.

    ``env`` is injectable so the same boundary can be tested without mutating
    process globals.  A development process may explicitly use the SDK local
    provider; production must provide the platform URL and select the platform
    executor, otherwise a second ungoverned execution ledger could be started.
    """

    values = env if env is not None else os.environ
    base_url = str(values.get("PLATFORM_RUN_BASE_URL", "")).strip()
    executor = str(values.get("PLATFORM_RUN_EXECUTOR", "platform")).strip().lower()
    environment = str(values.get("APP_ENV", "development")).strip().lower()
    production = environment in {"production", "prod"}
    if executor not in {"platform", "local"}:
        raise RuntimeModeError("PLATFORM_RUN_EXECUTOR must be platform or local")
    if production and not base_url:
        raise RuntimeModeError(
            "production requires PLATFORM_RUN_BASE_URL; local execution is disabled"
        )
    if production and executor != "platform":
        raise RuntimeModeError(
            "production requires PLATFORM_RUN_EXECUTOR=platform"
        )
    if executor == "platform" and not base_url:
        raise RuntimeModeError(
            "PLATFORM_RUN_BASE_URL is required when PLATFORM_RUN_EXECUTOR=platform"
        )
    return RuntimeMode(base_url, executor, production)


__all__ = ["RuntimeMode", "RuntimeModeError", "resolve_runtime_mode"]
