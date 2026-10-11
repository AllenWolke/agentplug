"""Template-managed v2 entry point; business code belongs under domain/.

传输、PEP 校验与运行生命周期来自 vendored 平台 SDK（agent_platform_sdk/）；
业务代码只实现本文件中的两个接缝，绝不重复实现传输或状态机。

The transport, PEP verification and run lifecycle come from the vendored
platform SDK (agent_platform_sdk/); business code only implements the two
seams in this file and never re-implements transport or the state machine.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_platform_sdk import AgentApp, MemoryRunStore, create_agent_app
from agent_platform_sdk import telemetry as sdk_telemetry

# Must equal the agent_id advertised in the manifest so the Gateway signs tokens
# for exactly this Agent.
# 必须与 manifest 中宣告的 agent_id 一致，使网关只为该 Agent 签发令牌。
DEFAULT_AUDIENCE = "generated-python-agent"

# The lifecycle entries travel together so a started run can always be
# observed, resumed and cancelled.
# 生命周期入口同行，已启动的运行始终可观察、可恢复、可取消。
CAPABILITIES = ["invoke", "run", "resume", "cancel", "events"]


def invoke_business(trusted: Any) -> dict[str, Any]:
    """Synchronous business seam behind the verified boundary.

    同步业务接缝：位于已验证边界之后。
    """
    return {"echo": trusted.request.input}


def run_business(trusted: Any, events: Any, cancelled: Any) -> dict[str, Any]:
    """Asynchronous business seam: report progress, observe cancellation.

    异步业务接缝：汇报进度并观察取消；返回输出交给 SDK 状态机收尾。
    """
    events.append("progress", {"stage": "business"})
    if cancelled.is_set():
        raise RuntimeError("run was cancelled")
    return {"echo": trusted.request.input}


def build_execution_server(
    public_key: Ed25519PublicKey,
    *,
    agent_id: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    store: MemoryRunStore | None = None,
    invoke: Callable[[Any], dict[str, Any]] | None = None,
    run: Callable[..., dict[str, Any]] | None = None,
    now: Callable[[], int] | None = None,
    tracer: Any | None = None,
    validate_input: Callable[[Any], None] | None = None,
) -> AgentApp:
    """Wire the vendored SDK Factory with the template's business seams.

    Tests reuse this exact wiring; the generated Agent supplies only hooks and
    the SDK Factory owns transport, security, lifecycle and telemetry wiring.
    用模板业务接缝装配 SDK Factory；生成 Agent 只提供 Hook，传输、安全、
    生命周期和遥测均由 SDK 持有，测试复用同一接线，now 用于钉住时钟。
    """
    return create_agent_app(
        public_key=public_key,
        issuer=issuer or issuer_from_env(),
        audience=audience or audience_from_env(),
        agent_id=agent_id or agent_id_from_env(),
        # NOT FOR L2/L3: swap in a scoped durable RunStore for production.
        # 不可用于 L2/L3：生产环境请替换为带 Scope 的持久化 RunStore。
        store=store if store is not None else MemoryRunStore(),
        capabilities=CAPABILITIES,
        invoke=invoke or invoke_business,
        run=run or run_business,
        now=now,
        tracer=tracer,
        validate_input=validate_input,
    )


def main() -> None:
    # Fail closed: without platform-injected verification material the Agent
    # refuses to start rather than accepting unverified callers.
    # 失败闭合：没有平台注入的校验材料时，Agent 拒绝启动，而不是接受未验证的调用方。
    key = public_key_from_env()
    agent_id = agent_id_from_env()
    # Absence of a collector must never fail startup; an empty endpoint yields
    # the no-op tracer. / 缺失收集器绝不能导致启动失败；空端点返回 no-op tracer。
    tracer, shutdown = sdk_telemetry.setup(agent_id, os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""))
    execution = build_execution_server(key, tracer=tracer)
    httpd = execution.serve(("0.0.0.0", int(os.getenv("PORT", "8080"))))
    try:
        httpd.serve_forever()
    finally:
        shutdown()


def issuer_from_env() -> str:
    if issuer := os.getenv("AGENT_PLATFORM_ISSUER", "").strip():
        return issuer
    return "platform-runtime-gateway"


def audience_from_env() -> str:
    if audience := os.getenv("AGENT_PLATFORM_AUDIENCE", "").strip():
        return audience
    return DEFAULT_AUDIENCE


def agent_id_from_env() -> str:
    if agent_id := os.getenv("AGENT_PLATFORM_AGENT_ID", "").strip():
        return agent_id
    return audience_from_env()


def public_key_from_env() -> Ed25519PublicKey:
    """Load the platform-injected Ed25519 public key, failing closed when it
    is absent. / 加载平台注入的 Ed25519 公钥；缺失即失败闭合。
    """
    candidates: list[str] = []
    for name in ("AGENT_PLATFORM_PUBLIC_KEY_BASE64", "PLATFORM_CONTEXT_PUBLIC_KEY"):
        if value := os.getenv(name, "").strip():
            candidates.append(value)
    for name in ("AGENT_PLATFORM_PUBLIC_KEY_FILE", "PLATFORM_CONTEXT_PUBLIC_KEY_FILE"):
        path = os.getenv(name, "").strip()
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError as exc:
            raise RuntimeError(f"{name} is unreadable: {exc}") from exc
        if value:
            candidates.append(value)
    if not candidates:
        raise RuntimeError("AGENT_PLATFORM_PUBLIC_KEY_BASE64 is required")
    for value in candidates:
        padded = value + "=" * (-len(value) % 4)
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                raw = decoder(padded)
            except Exception:
                continue
            if len(raw) == 32:
                return Ed25519PublicKey.from_public_bytes(raw)
    raise RuntimeError("AGENT_PLATFORM_PUBLIC_KEY_BASE64 must be a raw Ed25519 public key")


if __name__ == "__main__":
    main()
