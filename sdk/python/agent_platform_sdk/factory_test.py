from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .conformance import validate_manifest
from .factory import create_agent_app
from .lifecycle import MemoryRunStore


def test_factory_builds_one_standard_manifest():
    private_key = Ed25519PrivateKey.generate()
    app = create_agent_app(
        public_key=private_key.public_key(),
        issuer="platform",
        audience="agents",
        agent_id="example-agent",
        store=MemoryRunStore(),
        invoke=lambda _trusted: {"ok": True},
    )
    validate_manifest(app.server._manifest(), "example-agent")


def test_factory_requires_run_handler_for_advertised_run():
    private_key = Ed25519PrivateKey.generate()
    try:
        create_agent_app(
            public_key=private_key.public_key(),
            issuer="platform",
            audience="agents",
            agent_id="example-agent",
            store=MemoryRunStore(),
            capabilities=["run", "resume", "cancel", "events"],
        )
    except ValueError as exc:
        assert "run capability" in str(exc)
    else:
        raise AssertionError("factory accepted a run capability without business hook")
