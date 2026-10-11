"""Production model governance boundary / 生产模型治理边界。"""

import pytest

from agent_platform_sdk.security import validate_deployed_model_mode


@pytest.mark.parametrize("environment", ["production", "prod", "staging", ""])
@pytest.mark.parametrize(
    "name,value",
    [("EVAL_EXECUTION_MODE", "local_mock"), ("EVAL_DIRECT_PROVIDER", "deepseek")],
)
def test_deployed_agent_rejects_evaluation_bypass(
    monkeypatch, environment, name, value
):
    monkeypatch.setenv("APP_ENV", environment)
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="forbidden"):
        validate_deployed_model_mode()


def test_explicit_offline_development_can_use_mock(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("EVAL_EXECUTION_MODE", "local_mock")
    validate_deployed_model_mode()
