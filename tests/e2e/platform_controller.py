"""Invoke platform-owned controller ports; never impersonate a browser user.

This is a local Compose test/deployment helper requiring container execution
access. Business Agents must not import it or obtain platform DB credentials.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def observe_catalog(installation_id: str, deployment_id: str, revision: int,
                    scope: dict[str, str], health: str = "ready") -> dict:
    observation = {
        "kind": "catalog", "installation_id": installation_id,
        "deployment_id": deployment_id, "revision": revision, "health": health,
        **{key: scope[key] for key in ("tenant_id", "department_id", "application_id")},
    }
    command = ["docker", "compose", "-f", str(ROOT / "compose.yaml"), "exec", "-T",
               "platform-app", "/app/deployment-observe"]

    def invoke(extra: list[str]) -> dict:
        result = subprocess.run(command + extra, input=json.dumps(observation),
                                text=True, capture_output=True, cwd=ROOT, timeout=45)
        if result.returncode:
            # Do not expose environment, raw Docker errors or database credentials.
            raise RuntimeError("platform controller observation failed; check image, scope, revision and controller access")
        try:
            reply = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("invalid platform controller receipt") from exc
        if reply.get("observation") != observation:
            raise RuntimeError("controller receipt does not match the observation")
        return reply

    preview = invoke([])
    digest = preview.get("source_hash", "")
    if preview.get("applied") is not False or len(digest) != 64:
        raise RuntimeError("invalid controller preview")
    receipt = invoke(["--apply", "--expected-source-hash", digest])
    if receipt.get("applied") is not True or receipt.get("source_hash") != digest:
        raise RuntimeError("controller did not commit the confirmed observation")
    return receipt
