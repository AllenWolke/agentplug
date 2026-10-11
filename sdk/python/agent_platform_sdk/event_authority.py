"""Current events-only read authority; never substitutes a business capability."""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .capability_client import GatewayError
from .models import EventRequest, validate_event_cursor
from .security import internal_token, signed_internal_headers


class EventAuthorityClient:
    def __init__(self, *, base_url: str | None = None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.base = (base_url or os.getenv("PLATFORM_CAPABILITY_URL", "")).strip().rstrip("/")
        target = httpx.URL(self.base)
        if target.scheme not in ("http", "https") or not target.host or target.userinfo or target.query or target.fragment:
            raise GatewayError("CAPABILITY_CONFIG_INVALID", "event authority URL required")
        self.transport = transport

    async def check(self, request: EventRequest) -> None:
        try:
            validate_event_cursor(request.after_seq)
        except (TypeError, ValueError):
            raise GatewayError("INVALID_REQUEST", "event cursor is invalid") from None
        path = "/internal/context/events/check"
        body = json.dumps(request.model_dump(mode="json"), ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode()
        if len(body) > 32768:
            raise GatewayError("INVALID_REQUEST", "event request exceeds limit")
        target = httpx.URL(self.base + path)
        headers = signed_internal_headers(body, internal_token(), request.scope.trace_id,
            request.context_token, method="POST", request_target=target.raw_path.decode("ascii"))
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=5.0,
                                         follow_redirects=False) as client:
                async with client.stream("POST", target, content=body, headers=headers) as response:
                    if response.status_code in (401, 403):
                        raise PermissionError("current event read denied")
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(raw) + len(chunk) > 32768:
                            raise GatewayError("EVENT_AUTHORIZATION_UNAVAILABLE", "event response exceeds limit")
                        raw.extend(chunk)
                    if response.status_code != 200:
                        raise GatewayError("EVENT_AUTHORIZATION_UNAVAILABLE", "event authority unavailable")
                    value: Any = json.loads(raw)
                    if not isinstance(value, dict) or not isinstance(value.get("data"), dict) or value["data"].get("allowed") is not True:
                        raise GatewayError("EVENT_AUTHORIZATION_UNAVAILABLE", "invalid event authority response")
        except (httpx.HTTPError, ValueError):
            raise GatewayError("EVENT_AUTHORIZATION_UNAVAILABLE", "event authority unavailable") from None
