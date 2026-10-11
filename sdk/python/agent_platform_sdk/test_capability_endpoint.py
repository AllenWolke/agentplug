from __future__ import annotations

import pytest

from .capability_client import CapabilityGatewayClient, GatewayError
from .tool_client import ToolGatewayError, _platform_base_url


def test_model_gateway_requires_modular_platform_endpoint(monkeypatch) -> None:
    monkeypatch.delenv("PLATFORM_CAPABILITY_URL", raising=False)
    monkeypatch.delenv("LLM_GATEWAY_URL", raising=False)

    with pytest.raises(GatewayError) as error:
        CapabilityGatewayClient(context=object())

    assert error.value.code == "PLATFORM_CAPABILITY_URL_REQUIRED"


def test_tool_gateway_requires_modular_platform_endpoint(monkeypatch) -> None:
    monkeypatch.delenv("PLATFORM_CAPABILITY_URL", raising=False)
    monkeypatch.delenv("HARNESS_CAPABILITY_URL", raising=False)

    with pytest.raises(ToolGatewayError) as error:
        _platform_base_url()

    assert error.value.code == "PLATFORM_CAPABILITY_URL_REQUIRED"


def test_capability_endpoint_uses_only_the_new_platform_setting(monkeypatch) -> None:
    monkeypatch.setenv("PLATFORM_CAPABILITY_URL", " http://platform-app:8081/ ")
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://obsolete-harness:8081")
    monkeypatch.setenv("HARNESS_CAPABILITY_URL", "http://obsolete-harness:8081")

    assert _platform_base_url() == "http://platform-app:8081"
