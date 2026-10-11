"""Black-box Agent Execution v2 conformance runner.

黑盒一致性测试仅通过 HTTP 验证 Manifest、签名上下文和运行生命周期，
不导入 SDK 或 Agent 的业务代码。
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def fetch(url: str, request: urllib.request.Request | None = None) -> tuple[int, bytes, str]:
    """Read a bounded HTTP response; transport failures remain explicit.

    读取有界 HTTP 响应；网络失败不能被误判为一致性通过。
    """

    try:
        with urllib.request.urlopen(request or url, timeout=10) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES + 1), response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE_BYTES + 1), exc.headers.get("Content-Type", "")


def request_json(url: str, payload: dict[str, Any]) -> tuple[int, bytes, str]:
    token = payload.get("context_token", "")
    request = urllib.request.Request(
        url,
        json.dumps(payload, separators=(",", ":")).encode(),
        {"Content-Type": "application/json", "Authorization": "Bearer " + token},
        method="POST",
    )
    return fetch("", request)


def assert_response(status: int, raw: bytes, content_type: str, expected: set[int], run_id: str) -> None:
    assert status in expected, f"unexpected HTTP status {status}: {raw[:512]!r}"
    assert len(raw) <= MAX_RESPONSE_BYTES, "response exceeds conformance response limit"
    assert "application/json" in content_type, f"expected JSON response, got {content_type!r}"
    response = json.loads(raw)
    assert response["protocol_version"] == "agent-execution/v2"
    assert response["run_id"] == run_id


def assert_sse(status: int, raw: bytes, content_type: str, run_id: str) -> None:
    assert status == 200, f"events failed: {status} {raw[:512]!r}"
    assert "text/event-stream" in content_type, f"expected SSE, got {content_type!r}"
    text = raw.decode("utf-8")
    # Strictly require all three SSE fields; a partial stream must fail instead
    # of being treated as a successful empty event replay.
    # 严格要求 SSE 三个字段；不允许把截断流伪装为成功的空重放。
    fields = dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)
    assert fields.get("id", "").isdigit() and int(fields["id"]) > 0
    assert fields.get("event") in {"accepted", "started", "progress", "waiting", "artifact", "completed", "failed", "cancelled"}
    event = json.loads(fields["data"])
    assert event["run_id"] == run_id and event["seq"] == int(fields["id"])


def load_lifecycle(path: str) -> dict[str, dict[str, Any]]:
    """Load externally signed fixtures; runner never mints platform capabilities.

    仅加载网关生成的已签名 fixture；runner 永远不自行签发平台能力令牌。
    """

    fixture = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"invoke", "run", "resume", "cancel", "events"}
    missing = required.difference(fixture)
    assert not missing, f"lifecycle fixture is missing {sorted(missing)}"
    for name in required:
        assert fixture[name].get("context_token"), f"{name} fixture lacks a signed context token"
    return fixture


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--lifecycle-fixture", help="Gateway-signed invoke/run/resume/cancel/events JSON fixture")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    status, raw, _ = fetch(base + "/.well-known/agent-manifest.json")
    manifest = json.loads(raw)
    # The canonical manifest contract uses a namespaced version and the
    # explicit execution_protocols field. / 统一 Manifest 契约使用带命名空间
    # 的版本值，并通过 execution_protocols 声明执行协议。
    assert status == 200 and manifest["manifest_version"] == "agent-manifest/v1"
    assert "agent-execution/v2" in manifest.get("execution_protocols", [])
    capabilities = set(manifest.get("capabilities", []))
    # Agents may expose a capability subset (for example validation is run-only
    # while QA also exposes invoke). Conformance must validate the declaration,
    # not require unrelated operations. / Agent 可声明能力子集，Conformance
    # 应按声明逐项验证，而不是强制所有 Agent 都实现无关操作。
    assert capabilities & {"invoke", "run"}, "manifest must expose invoke or run"

    malformed = Path("conformance/fixtures/malformed.json").read_bytes()
    probe_operation = "invoke" if "invoke" in capabilities else "runs"
    request = urllib.request.Request(
        base + "/internal/agent-execution/v2/" + probe_operation, malformed,
        {"Content-Type": "application/json", "Authorization": "Bearer invalid"}, method="POST",
    )
    status, _, _ = fetch("", request)
    assert status in {400, 401, 422}, f"malformed request unexpectedly returned {status}"

    if args.lifecycle_fixture:
        fixture = load_lifecycle(args.lifecycle_fixture)
        run_id = fixture["run"]["scope"]["run_id"]
        if "invoke" in capabilities:
            status, raw, content_type = request_json(base + "/internal/agent-execution/v2/invoke", fixture["invoke"])
            assert_response(status, raw, content_type, {200, 202}, fixture["invoke"]["scope"]["run_id"])
        if "run" in capabilities:
            status, raw, content_type = request_json(base + "/internal/agent-execution/v2/runs", fixture["run"])
            assert_response(status, raw, content_type, {200, 202}, run_id)
        if "resume" in capabilities:
            status, raw, content_type = request_json(base + f"/internal/agent-execution/v2/runs/{run_id}/resume", fixture["resume"])
            assert_response(status, raw, content_type, {200, 202}, run_id)
        if "events" in capabilities:
            status, raw, content_type = request_json(base + f"/internal/agent-execution/v2/runs/{run_id}/events", fixture["events"])
            assert_sse(status, raw, content_type, run_id)
        if "cancel" in capabilities:
            status, raw, content_type = request_json(base + f"/internal/agent-execution/v2/runs/{run_id}/cancel", fixture["cancel"])
            assert_response(status, raw, content_type, {200, 202}, run_id)

    print(json.dumps({"status": "passed", "agent_id": manifest["agent_id"], "version": manifest["version"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
