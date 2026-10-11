from __future__ import annotations

import pytest

from agent_platform_sdk.runtime_mode import RuntimeModeError, resolve_runtime_mode


def test_production_requires_platform_url() -> None:
    with pytest.raises(RuntimeModeError, match="PLATFORM_RUN_BASE_URL"):
        resolve_runtime_mode({"APP_ENV": "production", "PLATFORM_RUN_EXECUTOR": "platform"})


def test_production_rejects_local_executor() -> None:
    with pytest.raises(RuntimeModeError, match="PLATFORM_RUN_EXECUTOR=platform"):
        resolve_runtime_mode(
            {
                "APP_ENV": "production",
                "PLATFORM_RUN_BASE_URL": "http://platform:8080",
                "PLATFORM_RUN_EXECUTOR": "local",
            }
        )


def test_development_may_explicitly_use_local_provider() -> None:
    mode = resolve_runtime_mode({"APP_ENV": "development", "PLATFORM_RUN_EXECUTOR": "local"})
    assert mode.platform_owned is False


def test_platform_executor_requires_url_even_in_development() -> None:
    with pytest.raises(RuntimeModeError, match="PLATFORM_RUN_BASE_URL"):
        resolve_runtime_mode({"APP_ENV": "development", "PLATFORM_RUN_EXECUTOR": "platform"})
