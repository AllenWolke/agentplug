"""LangGraph business graph behind the vendored platform SDK.

业务图（LangGraph StateGraph）运行在 vendored 平台 SDK（agent_platform_sdk/）
的已验证边界之后：run 命中人工审核门时挂起（interrupt），平台 resume 事件驱动
Command(resume=...) 继续；thread_id 一律从已验证作用域派生，绝不取自原始输入。
Checkpointer 由 SDK 管理 PostgreSQL 连接，生产环境禁止内存回退。
"""

from __future__ import annotations

import base64
import os
import threading
import time
from typing import Any, Callable, TypedDict
from types import SimpleNamespace
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from langgraph.types import Command, interrupt

from agent_platform_sdk import ExecutionServer, MemoryRunStore, ServerConfig, scoped_config
from agent_platform_sdk import SyncPostgresCheckpointProvider
from agent_platform_sdk import telemetry as sdk_telemetry
from agent_platform_sdk.lifecycle import EVENT_STARTED

# Must equal the agent_id advertised in the manifest so the Gateway signs tokens
# for exactly this Agent.
# 必须与 manifest 中宣告的 agent_id 一致，使网关只为该 Agent 签发令牌。
DEFAULT_AUDIENCE = "generated-python-langgraph-agent"

# The lifecycle entries travel together so a started run can always be
# observed, resumed and cancelled.
# 生命周期入口同行，已启动的运行始终可观察、可恢复、可取消。
CAPABILITIES = ["invoke", "run", "resume", "cancel", "events"]


class AgentState(TypedDict, total=False):
    input: dict
    approval: str
    output: dict


def plan_node(state: AgentState) -> dict[str, Any]:
    """Business node: echo the verified input into the planned output.

    业务节点：把已验证输入回显进计划输出。
    """
    return {"output": {"planned": True, "input": dict(state.get("input", {}))}}


def review_node(state: AgentState) -> dict[str, Any]:
    """Human-in-the-loop gate: park until the platform resume leg delivers the
    answer through the run store. / 人工审核门：挂起直到平台 resume 腿送达答案。
    """
    answer = interrupt({"question": "approve the plan?"})
    approval = answer.get("approval", "") if isinstance(answer, dict) else ""
    return {"approval": approval}


def finish_node(state: AgentState) -> dict[str, Any]:
    output = dict(state.get("output", {}))
    output["approval"] = state.get("approval", "not_required")
    return {"output": output}


def build_graph(checkpointer: Any) -> Any:
    """Compile the StateGraph with real nodes and thread-scoped checkpoints.

    编译带真实节点与线程作用域检查点的 StateGraph。
    """
    from langgraph.graph import END, StateGraph

    graph = StateGraph(AgentState)
    graph.add_node("plan", plan_node)
    graph.add_node("review", review_node)
    graph.add_node("finish", finish_node)
    graph.set_entry_point("plan")

    def route(state: AgentState) -> str:
        # Business-owned code may replace this predicate; it must remain
        # deterministic and side-effect free for replay.
        # 业务代码可替换该谓词，但必须保持确定性且无副作用，保证可重放。
        return "review" if state.get("input", {}).get("requires_review") else "finish"

    graph.add_conditional_edges("plan", route, {"review": "review", "finish": "finish"})
    graph.add_edge("review", "finish")
    graph.add_edge("finish", END)
    return graph.compile(checkpointer=checkpointer)


def thread_id_for(scope: Any) -> str:
    """Derive the LangGraph thread id from the VERIFIED scope only.

    thread_id 一律派生自已验证作用域（会话与运行），绝不解析令牌或原始输入。
    """
    if not all(isinstance(value, str) and value.strip() for value in (scope.session_id, scope.run_id)):
        raise ValueError('complete trusted session and run scope is required')
    dimensions = {name: getattr(scope, name) for name in (
        'tenant_id', 'department_id', 'application_id', 'installation_id',
        'agent_instance_id', 'agent_id', 'agent_version_id', 'principal_type')}
    dimensions.update(actor_id=scope.principal_id, session_id=scope.session_id,
                      thread_id=json.dumps([scope.session_id, scope.run_id], separators=(',', ':')))
    return scoped_config(SimpleNamespace(**dimensions))['configurable']['thread_id']


def _resume_payload(store: MemoryRunStore, run_id: str) -> dict[str, Any]:
    """Read the resume input the platform leg relayed through the run store.

    MemoryRunStore 把 resume 请求的输入记录为 started 事件负载；此处读取最后一
    条非空 started 事件作为 Command(resume=...) 的值（开发存储约定；持久化
    RunStore 应提供一等读取接口）。
    """
    record = store.get_run(run_id)
    if record is None:
        return {}
    for event in reversed(record.events):
        if event.event_type == EVENT_STARTED and event.payload:
            return dict(event.payload)
    return {}


def make_invoke_business(graph: Any) -> Callable[[Any], dict[str, Any]]:
    def invoke_business(trusted: Any) -> dict[str, Any]:
        config = {"configurable": {"thread_id": thread_id_for(trusted.request.scope)}}
        state = graph.invoke({"input": dict(trusted.request.input)}, config)
        output = dict(state.get("output", {}))
        if "__interrupt__" in state:
            # Synchronous invoke cannot complete a human-in-the-loop gate: the
            # graph stays parked and the question is surfaced so the caller
            # switches to run/resume. / 同步 invoke 无法完成人工审核门：图保持
            # 挂起，问题随输出返回，调用方应改用 run/resume。
            value = state["__interrupt__"][0].value
            output["status"] = "review_required"
            output["review"] = value if isinstance(value, dict) else {"question": str(value)}
        return output

    return invoke_business


def make_run_business(graph: Any, store: MemoryRunStore) -> Callable[..., dict[str, Any]]:
    def run_business(trusted: Any, events: Any, cancelled: threading.Event) -> dict[str, Any]:
        run_id = trusted.request.scope.run_id
        thread_id = thread_id_for(trusted.request.scope)
        config = {"configurable": {"thread_id": thread_id}}
        events.append("progress", {"stage": "langgraph", "thread_id": thread_id})
        state = graph.invoke({"input": dict(trusted.request.input)}, config)
        if "__interrupt__" not in state:
            return dict(state.get("output", {}))
        # Park on the human gate: waiting is observable through the events
        # endpoint, and the platform resume leg drives Command(resume=...).
        # 挂起在人工门：waiting 可经 events 端点观察，平台 resume 驱动继续。
        question = state["__interrupt__"][0].value
        store.mark_waiting(run_id, question if isinstance(question, dict) else {"question": str(question)})
        resume_signal = store.resume_signal(run_id)
        while not resume_signal.is_set() and not cancelled.is_set():
            time.sleep(0.01)
        if cancelled.is_set():
            raise RuntimeError("run was cancelled")
        state = graph.invoke(Command(resume=_resume_payload(store, run_id)), config)
        return dict(state.get("output", {}))

    return run_business


def build_execution_server(
    public_key: Ed25519PublicKey,
    *,
    agent_id: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    store: MemoryRunStore | None = None,
    graph: Any = None,
    invoke: Callable[[Any], dict[str, Any]] | None = None,
    run: Callable[..., dict[str, Any]] | None = None,
    now: Callable[[], int] | None = None,
    tracer: Any | None = None,
) -> ExecutionServer:
    """Wire the vendored SDK around the LangGraph business graph.

    Tests reuse this exact wiring; the graph and store stay injectable.
    用 LangGraph 业务图装配 vendored SDK；测试复用同一接线，图与存储可注入。
    """
    store = store if store is not None else MemoryRunStore()
    graph = graph if graph is not None else build_graph(resolve_checkpointer())
    return ExecutionServer(ServerConfig(
        public_key=public_key,
        issuer=issuer or issuer_from_env(),
        audience=audience or audience_from_env(),
        agent_id=agent_id or agent_id_from_env(),
        # NOT FOR L2/L3: swap in a scoped durable RunStore for production.
        # 不可用于 L2/L3：生产环境请替换为带 Scope 的持久化 RunStore。
        store=store,
        capabilities=CAPABILITIES,
        invoke=invoke or make_invoke_business(graph),
        run=run or make_run_business(graph, store),
        now=now,
        tracer=tracer,
    ))


def main() -> None:
    # Fail closed: without platform-injected verification material the Agent
    # refuses to start rather than accepting unverified callers.
    # 失败闭合：没有平台注入的校验材料时，Agent 拒绝启动，而不是接受未验证的调用方。
    key = public_key_from_env()
    agent_id = agent_id_from_env()
    # Absence of a collector must never fail startup; an empty endpoint yields
    # the no-op tracer. / 缺失收集器绝不能导致启动失败；空端点返回 no-op tracer。
    tracer, shutdown = sdk_telemetry.setup(agent_id, os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""))
    checkpointer = None
    httpd = None
    try:
        checkpointer = resolve_checkpointer()
        execution = build_execution_server(key, graph=build_graph(checkpointer), tracer=tracer)
        httpd = execution.serve(("0.0.0.0", int(os.getenv("PORT", "8080"))))
        httpd.serve_forever()
    finally:
        if httpd is not None:
            httpd.server_close()
        try:
            close_checkpointer(checkpointer)
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


# Production persists workflow state only in PostgreSQL through the SDK.
# Memory is an explicit ephemeral development/test choice, never another SQL DB.
def _is_production(env: dict[str, str]) -> bool:
    return any(env.get(key, '').strip().lower() in {'production', 'prod'}
               for key in ('PLATFORM_ENV', 'APP_ENV'))


def close_checkpointer(checkpointer: Any) -> None:
    provider = getattr(checkpointer, '_platform_checkpoint_provider', None)
    if provider is not None:
        provider.close()


def resolve_checkpointer(env: dict[str, str] | None = None) -> Any:
    env = os.environ if env is None else env
    kind = env.get('PLATFORM_CHECKPOINTER', '').strip().lower()
    if kind in {'', 'memory'}:
        if _is_production(env):
            raise RuntimeError('PLATFORM_CHECKPOINTER must select postgres in production; in-process MemorySaver is forbidden')
        from langgraph.checkpoint.memory import MemorySaver
        return MemorySaver()
    if kind == 'postgres':
        dsn = env.get('PLATFORM_CHECKPOINTER_POSTGRES_DSN', '').strip() or env.get('CHECKPOINT_DSN', '').strip()
        if not dsn:
            raise RuntimeError('PLATFORM_CHECKPOINTER_POSTGRES_DSN or CHECKPOINT_DSN is required')
        if env.get('CHECKPOINT_SETUP', '').strip().lower() in {'1', 'true', 'yes'}:
            raise RuntimeError('Checkpoint runtime must not apply schema migrations; use checkpoint_bootstrap')
        provider = SyncPostgresCheckpointProvider(dsn)
        try:
            saver = provider.get()
            saver._platform_checkpoint_provider = provider
            return saver
        except BaseException:
            provider.close()
            raise
    raise RuntimeError(f'unknown PLATFORM_CHECKPOINTER {kind!r}; expected memory|postgres')


if __name__ == "__main__":
    main()
