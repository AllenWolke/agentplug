#!/usr/bin/env python3
"""Generate an ephemeral Ed25519 context key pair for modular Compose smoke tests.

The values are emitted as one JSON object so the PowerShell and POSIX platform
orchestrators can keep the private key in process memory only.  This helper is
for isolated development/acceptance stacks; production keys must come from a
secret manager or an explicitly mounted secret.
"""

from __future__ import annotations

import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    json.dump(
        {
            "private": base64.b64encode(private_raw).decode("ascii"),
            "public": base64.b64encode(public_raw).decode("ascii"),
        },
        sys.stdout,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
