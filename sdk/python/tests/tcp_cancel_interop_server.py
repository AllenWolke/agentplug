"""Disposable real-TCP cancellation fixture; never a deployed Agent.

临时真实 TCP 取消夹具，不是业务 Agent，不读取项目凭据。
"""

import asyncio
import base64
import json
import os
import socket

import uvicorn
from fastapi import HTTPException

from agent_platform_sdk import ContextVerifier
from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app

verifier = ContextVerifier(
    base64.b64decode(os.environ["FIXTURE_PUBLIC_KEY"]), "platform", "agent-runtime"
)
state = {"started": 0, "stopped": 0, "effects": 0, "controls": 0}
release = asyncio.Event()


async def authorize(request, authorization):
    if authorization != "Bearer " + request.context_token:
        raise PermissionError
    try:
        verifier.verify(request.context_token, request)
    except ValueError:
        raise HTTPException(401, "invalid fixture capability") from None


async def graph(request):
    state["started"] += 1
    try:
        # Deliberately suppress cooperative cancellation to test the platform's
        # unknown-stop state, not to recommend this business implementation.
        # 故意抑制取消验证平台安全边界，禁止作为业务实现范例。
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue
        return {"fixture": "stopped"}
    finally:
        state["stopped"] += 1


async def cancel(run_id, request):
    if state["stopped"] != state["started"]:
        raise AssertionError("stop acknowledgment preceded graph cleanup")
    state["controls"] += 1
    return {}


app = create_fastapi_agent_app(
    title="cancel-interoperability-fixture",
    agent_id="agent",
    version="1",
    capabilities=["invoke", "cancel"],
    authorize=authorize,
    invoke=graph,
    cancel=cancel,
)


@app.get("/fixture/state")
async def read_state():
    return state


@app.post("/fixture/release")
async def release_graph():
    release.set()
    return {"released": True}


@app.post("/fixture/reset")
async def reset_graph():
    release.clear()
    return {"reset": True}


if __name__ == "__main__":
    listener = socket.socket()
    # A test may restart the Agent on the same port while the platform keeps
    # its durable cancellation intent. / 测试重启后复用端口验证平台持久化取消意图。
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", int(os.getenv("FIXTURE_PORT", "0"))))
    listener.listen(128)
    print(
        json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}"}), flush=True
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    server.run(sockets=[listener])
