"""Verify mounted credentials preserve validation and fail-closed behavior."""
import pytest

from agent_platform_sdk.security import internal_token


TOKEN = "unit-fixture-0123456789abcdef-0123456789abcdef"


def test_read_only_mounted_token_is_trimmed_and_rotation_is_observed(monkeypatch, tmp_path):
    path = tmp_path / "internal-token"
    path.write_text("\n" + TOKEN + "\n", encoding="utf-8")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("INTERNAL_TOKEN_FILE", str(path))
    assert internal_token() == TOKEN
    path.write_text(TOKEN + "-rotated", encoding="utf-8")
    assert internal_token() == TOKEN + "-rotated"


def test_explicit_and_environment_tokens_take_precedence_over_file(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("INTERNAL_TOKEN_FILE", str(tmp_path / "missing"))
    monkeypatch.setenv("INTERNAL_TOKEN", TOKEN)
    assert internal_token() == TOKEN
    assert internal_token(TOKEN + "-explicit") == TOKEN + "-explicit"
    # 明确传入空值仍拒绝，不能被部署环境中的另一凭据替代。
    with pytest.raises(RuntimeError):
        internal_token("")


@pytest.mark.parametrize("environment", ["production", "test"])
@pytest.mark.parametrize("contents", [None, b" \n", b"confidential-unit-marker-\xff"])
def test_configured_unreadable_or_empty_file_does_not_fallback(
    monkeypatch, tmp_path, environment, contents
):
    path = tmp_path / "internal-token"
    if contents is not None:
        path.write_bytes(contents)
    monkeypatch.setenv("APP_ENV", environment)
    monkeypatch.delenv("INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("INTERNAL_TOKEN_FILE", str(path))
    with pytest.raises(RuntimeError) as error:
        internal_token()
    assert "confidential-unit-marker" not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize("value", ["change-me", "short", "x" * 40, "placeholder-" + TOKEN])
def test_mounted_production_token_keeps_existing_strength_checks(monkeypatch, tmp_path, value):
    path = tmp_path / "internal-token"
    path.write_text(value, encoding="utf-8")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("INTERNAL_TOKEN", raising=False)
    monkeypatch.setenv("INTERNAL_TOKEN_FILE", str(path))
    with pytest.raises(RuntimeError) as error:
        internal_token()
    assert value not in str(error.value)
