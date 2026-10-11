"""Protocol-only protobuf gRPC bridge for Agent Execution v2.

The bridge delegates all Agent behavior to the existing HTTP/core handlers.
It accepts the canonical generated Protobuf service and forwards the signed
execution envelope to that handler without changing its body.

Agent Execution v2 的纯协议 Protobuf gRPC 桥；业务仍由 Agent 自己的 HTTP/core
handler 执行。请求体保持原样转发，并使用唯一 canonical 生成服务契约。
"""

from __future__ import annotations

import json
import math
from typing import Any, AsyncIterator

import grpc
import httpx
from google.protobuf.json_format import MessageToDict, ParseDict

from .proto import agent_execution_v2_pb2 as pb
from .proto import agent_execution_v2_pb2_grpc as pb_grpc
from .models import validate_event_cursor, validate_event_sequence

_MAX_SSE_LINE_BYTES = 1 << 20
_MAX_HTTP_RESPONSE_BYTES = 8 << 20
_MIN_CONTEXT_TOKEN_BYTES = 32
_MAX_CONTEXT_TOKEN_BYTES = 8192


def _normalize_protobuf_numbers(value):
    """Match Go's JSON encoding when reconstructing Protobuf Struct values.

    Protobuf Struct stores every JSON number as IEEE-754 double. Go's
    encoding/json emits finite integral doubles without a decimal suffix,
    while Python would normally emit e.g. ``5.0``. Normalize the reconstructed
    envelope before forwarding so the Agent's signed canonical body hash is
    identical across HTTP and gRPC. Reject NaN/Infinity because they are not
    valid JSON request values.

    Protobuf Struct 会把 JSON 数值统一存为 IEEE-754 double。Go 的
    encoding/json 会把有限整数值输出为无小数形式，而 Python 默认会输出
    ``5.0``；转发前统一规范化，保证 HTTP/gRPC 的签名正文哈希一致。拒绝
    JSON 不允许的 NaN/Infinity。
    """
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite Protobuf number is not valid JSON")
        return int(value) if value.is_integer() else value
    if isinstance(value, list):
        return [_normalize_protobuf_numbers(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_protobuf_numbers(item) for key, item in value.items()}
    return value


class AgentExecutionBridge(pb_grpc.AgentExecutionServiceServicer):
    """Adapt canonical v2 protobuf RPCs to the Agent's HTTP protocol routes."""

    def __init__(self, http_base_url: str) -> None:
        self._base = http_base_url.rstrip("/")

    @staticmethod
    def _metadata_pairs(context: grpc.aio.ServicerContext) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for item in context.invocation_metadata():
            # grpc.aio returns grpc.aio.Metadata items, while a tuple fallback
            # keeps this adapter straightforward to exercise with test doubles.
            if hasattr(item, "key") and hasattr(item, "value"):
                key, value = item.key, item.value
            else:
                key, value = item[0], item[1]
            pairs.append((str(key).lower(), str(value)))
        return pairs

    @classmethod
    def _attach_trace_context(cls, context: grpc.aio.ServicerContext) -> Any | None:
        """Restore only a valid W3C parent for the gRPC-to-HTTP bridge.

        只恢复合法 W3C 父级，避免 gRPC 转 HTTP 时丢失平台 Trace；
        不接受 baggage，且追踪元数据绝不参与执行授权。
        """
        parents = [
            value for key, value in cls._metadata_pairs(context) if key == "traceparent"
        ]
        if len(parents) != 1:
            return None
        try:
            from opentelemetry import context as otel_context, trace
            from opentelemetry.trace.propagation.tracecontext import (
                TraceContextTextMapPropagator,
            )
        except ImportError:
            return None
        parent = TraceContextTextMapPropagator().extract({"traceparent": parents[0]})
        if not trace.get_current_span(parent).get_span_context().is_valid:
            return None
        return otel_context.attach(parent)

    @staticmethod
    def _detach_trace_context(token: Any | None) -> None:
        if token is not None:
            from opentelemetry import context as otel_context

            otel_context.detach(token)

    async def _headers(
        self,
        request: pb.ExecuteRequest | pb.EventRequest,
        context: grpc.aio.ServicerContext,
    ) -> dict[str, str]:
        token = request.context_token
        token_size = len(token.encode("utf-8"))
        if (
            token_size < _MIN_CONTEXT_TOKEN_BYTES
            or token_size > _MAX_CONTEXT_TOKEN_BYTES
        ):
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED, "invalid execution credential"
            )
        pairs = self._metadata_pairs(context)
        by_key: dict[str, list[str]] = {}
        for key, value in pairs:
            by_key.setdefault(key, []).append(value)

        authorization = by_key.get("authorization", [])
        if len(authorization) != 1 or authorization[0] != f"Bearer {token}":
            await context.abort(
                grpc.StatusCode.UNAUTHENTICATED, "execution credential mismatch"
            )
        headers = {"Authorization": authorization[0]}

        dispatch_values = by_key.get("x-platform-resume-dispatch", [])
        input_values = by_key.get("x-platform-resume-input", [])
        if dispatch_values or input_values:
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "unsigned resume metadata is forbidden",
            )
        return headers

    async def _unary(
        self,
        request: pb.ExecuteRequest,
        context: grpc.aio.ServicerContext,
        suffix: str,
    ) -> pb.ExecuteResponse:
        try:
            payload = _normalize_protobuf_numbers(
                MessageToDict(request, preserving_proto_field_name=True)
            )
        except (TypeError, ValueError, OverflowError):
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, "invalid numeric execution payload"
            )
            raise AssertionError("context.abort must terminate the RPC")
        headers = await self._headers(request, context)
        trace_token = self._attach_trace_context(context)
        try:
            async with httpx.AsyncClient(timeout=310.0, trust_env=False, follow_redirects=False) as client:
                async with client.stream(
                    "POST", self._base + suffix, json=payload, headers=headers
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > _MAX_HTTP_RESPONSE_BYTES:
                            await context.abort(
                                grpc.StatusCode.RESOURCE_EXHAUSTED,
                                "Agent response exceeds size limit",
                            )
                        body.extend(chunk)
                    try:
                        response_body = json.loads(body)
                        if response.status_code >= 400:
                            # Preserve the safe error contract instead of collapsing
                            # all business/policy failures to FAILED_PRECONDITION.
                            # 保留安全错误分类，不把业务/策略错误统一折叠为 gRPC 失败。
                            from .models import AppError

                            app_error = AppError.model_validate(response_body)
                            return ParseDict(
                                {
                                    "protocol_version": "agent-execution/v2",
                                    "run_id": request.scope.run_id,
                                    "status": "failed",
                                    "error": app_error.model_dump(exclude_none=True),
                                },
                                pb.ExecuteResponse(),
                            )
                        return ParseDict(response_body, pb.ExecuteResponse())
                    except (ValueError, TypeError):
                        await context.abort(
                            grpc.StatusCode.DATA_LOSS,
                            "Agent HTTP endpoint returned an invalid response",
                        )
                        raise AssertionError("context.abort must terminate the RPC")
        except httpx.HTTPError as exc:
            await context.abort(grpc.StatusCode.UNAVAILABLE, type(exc).__name__)
            raise AssertionError("context.abort must terminate the RPC")
        finally:
            self._detach_trace_context(trace_token)

    async def Invoke(self, request, context):
        return await self._unary(
            request, context, "/internal/agent-execution/v2/invoke"
        )

    async def Run(self, request, context):
        return await self._unary(request, context, "/internal/agent-execution/v2/runs")

    async def Resume(self, request, context):
        suffix = f"/internal/agent-execution/v2/runs/{request.scope.run_id}/resume"
        return await self._unary(request, context, suffix)

    async def Cancel(self, request, context):
        suffix = f"/internal/agent-execution/v2/runs/{request.scope.run_id}/cancel"
        return await self._unary(request, context, suffix)

    async def Events(  # type: ignore[override]
        self, request: pb.EventRequest, context: grpc.aio.ServicerContext
    ) -> AsyncIterator[pb.ExecutionEvent]:
        try:
            validate_event_cursor(request.after_seq)
        except (TypeError, ValueError):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid event cursor")
            raise AssertionError("context.abort must terminate the RPC")
        try:
            payload = _normalize_protobuf_numbers(
                MessageToDict(request, preserving_proto_field_name=True)
            )
        except (TypeError, ValueError, OverflowError):
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, "invalid numeric event payload"
            )
            raise AssertionError("context.abort must terminate the RPC")
        headers = await self._headers(request, context)
        path = f"/internal/agent-execution/v2/runs/{request.scope.run_id}/events"
        trace_token = self._attach_trace_context(context)
        try:
            async with httpx.AsyncClient(timeout=None, trust_env=False, follow_redirects=False) as client:
                async with client.stream(
                    "POST", self._base + path, json=payload, headers=headers
                ) as response:
                    if response.status_code >= 400:
                        await context.abort(
                            grpc.StatusCode.FAILED_PRECONDITION,
                            "Agent event endpoint rejected the request",
                        )
                    if (
                        "text/event-stream"
                        not in response.headers.get("content-type", "").lower()
                    ):
                        await context.abort(
                            grpc.StatusCode.DATA_LOSS,
                            "Agent event endpoint returned an invalid content type",
                        )
                    async for event in self._iter_events(
                        response, request.scope.run_id, request.after_seq, context
                    ):
                        yield event
        except httpx.HTTPError as exc:
            await context.abort(grpc.StatusCode.UNAVAILABLE, type(exc).__name__)
        finally:
            self._detach_trace_context(trace_token)

    @staticmethod
    async def _iter_events(
        response: httpx.Response,
        run_id: str,
        after_seq: int,
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb.ExecutionEvent]:
        try:
            validate_event_cursor(after_seq)
        except (TypeError, ValueError):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "invalid event cursor")
            raise AssertionError("context.abort must terminate the RPC")
        event_id = ""
        event_type = ""
        data_lines: list[str] = []
        previous = after_seq

        async def dispatch() -> pb.ExecutionEvent | None:
            nonlocal event_id, event_type, data_lines, previous
            if not event_id and not event_type and not data_lines:
                return None
            try:
                if not event_id.isascii() or not event_id.isdecimal():
                    raise ValueError("invalid event id")
                seq = int(event_id)
                validate_event_sequence(seq)
                value = json.loads("\n".join(data_lines))
                event = ParseDict(value, pb.ExecutionEvent())
            except (ValueError, TypeError):
                await context.abort(
                    grpc.StatusCode.DATA_LOSS, "Agent returned a malformed event"
                )
                raise AssertionError("context.abort must terminate the RPC")
            if (
                seq <= previous
                or event.seq < 1
                or event.seq >= 1 << 53
                or event.run_id != run_id
                or event.seq != seq
                or not event_type
                or event.event_type != event_type
                or not event.HasField("occurred_at")
                or not event.HasField("payload")
            ):
                await context.abort(
                    grpc.StatusCode.DATA_LOSS,
                    "Agent returned an invalid event sequence",
                )
                raise AssertionError("context.abort must terminate the RPC")
            previous = seq
            event_id, event_type, data_lines = "", "", []
            return event

        async for line in response.aiter_lines():
            if len(line.encode("utf-8")) > _MAX_SSE_LINE_BYTES:
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED, "Agent event exceeds size limit"
                )
            if line == "":
                event = await dispatch()
                if event is not None:
                    yield event
                continue
            if line.startswith(":"):
                continue
            field, separator, value = line.partition(":")
            if not separator:
                await context.abort(
                    grpc.StatusCode.DATA_LOSS, "Agent returned malformed event framing"
                )
            if value.startswith(" "):
                value = value[1:]
            if field == "id":
                if event_id:
                    await context.abort(
                        grpc.StatusCode.DATA_LOSS, "Agent returned duplicate event id"
                    )
                event_id = value
            elif field == "event":
                if event_type:
                    await context.abort(
                        grpc.StatusCode.DATA_LOSS, "Agent returned duplicate event type"
                    )
                event_type = value
            elif field == "data":
                data_lines.append(value)
            else:
                await context.abort(
                    grpc.StatusCode.DATA_LOSS, "Agent returned unsupported event field"
                )
        if event_id or event_type or data_lines:
            await context.abort(
                grpc.StatusCode.DATA_LOSS,
                "Agent event stream ended before the event boundary",
            )


async def start_grpc_bridge(port: int, http_base_url: str) -> grpc.aio.Server:
    """Start one Agent-local canonical protobuf gRPC endpoint.

    启动一个注册 canonical protobuf 服务的 Agent 本地 gRPC 端点。
    """
    import ipaddress
    import os

    host = os.environ.get("AGENT_GRPC_BIND_HOST", "0.0.0.0").strip()
    address = ipaddress.ip_address(host)
    endpoint = f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"
    server = grpc.aio.server(
        options=[
            ("grpc.max_receive_message_length", 8 << 20),
            ("grpc.max_send_message_length", 8 << 20),
        ]
    )
    pb_grpc.add_AgentExecutionServiceServicer_to_server(
        AgentExecutionBridge(http_base_url), server
    )
    if server.add_insecure_port(endpoint) == 0:
        raise OSError("failed to bind Agent gRPC endpoint")
    await server.start()
    return server
