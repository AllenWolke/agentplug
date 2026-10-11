import asyncio
import copy

import pytest

from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.graph_context import bind_graph_context, close_graph_context, resolve_graph_context
from test_tool_workflow import context, request


@pytest.mark.parametrize("field", ["tenant_id", "installation_id", "actor_id", "task_id", "runtime_policy_id"])
def test_checkpoint_scope_and_policy_cannot_be_replaced(field):
    req = request()
    fresh = context(req)
    saved = copy.deepcopy(fresh)
    saved.platform_context_token = "expired-secret"
    binding, token = bind_graph_context(req, fresh)
    try:
        assert resolve_graph_context(saved) is fresh
        setattr(saved, field, "different")
        with pytest.raises(DomainExecutionError):
            resolve_graph_context(saved)
    finally:
        close_graph_context(binding, token)
    assert resolve_graph_context(saved) is saved


@pytest.mark.asyncio
async def test_concurrent_graph_contexts_and_detached_tasks_are_isolated():
    async def dispatch(run_id):
        ready = asyncio.Event()
        req = request()
        req.scope.run_id = run_id
        fresh = context(req)
        binding, token = bind_graph_context(req, fresh)
        async def detached():
            await ready.wait()
            with pytest.raises(DomainExecutionError):
                resolve_graph_context(fresh)
        task = asyncio.create_task(detached())
        try:
            await asyncio.sleep(0)
            assert resolve_graph_context(copy.deepcopy(fresh)).task_id == run_id
        finally:
            close_graph_context(binding, token)
        ready.set()
        await task

    await asyncio.gather(dispatch("run-one"), dispatch("run-two"))
