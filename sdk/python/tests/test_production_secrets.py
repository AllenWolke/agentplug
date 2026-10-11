import pytest

from agent_platform_sdk.security import internal_signing_secret, internal_token


@pytest.mark.parametrize("environment", ["production", "prod"])
@pytest.mark.parametrize("resolver", [internal_token, internal_signing_secret])
@pytest.mark.parametrize(
    "value",
    [
        "short",
        "x" * 32,
        "密" * 11,
        "changeme-" + "0123456789abcdef" * 3,
        "replace-" + "0123456789abcdef" * 3,
    ],
)
def test_production_rejects_weak_secrets_without_echo(
    monkeypatch, environment, resolver, value
):
    monkeypatch.setenv("APP_ENV", environment)
    with pytest.raises(RuntimeError) as error:
        resolver(value)
    assert value not in str(error.value)


def test_strong_file_signing_secret_and_explicit_token_are_accepted(
    monkeypatch, tmp_path
):
    value = "test-0123456789abcdef0123456789abcdef"
    path = tmp_path / "signing"
    path.write_text(value)
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.delenv("INTERNAL_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET_FILE", str(path))
    assert internal_signing_secret() == value
    assert internal_token(value) == value


def test_development_remains_explicit_and_compatible(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    assert internal_token("short") == "short"
    assert internal_signing_secret("short") == "short"
