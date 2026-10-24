import asyncio
import copy
import json
from pathlib import Path

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.step_workflow import run_step_workflow
from test_step_workflow import StateClient

FIXTURE = json.loads((Path(__file__).resolve().parents[3] / "contracts/fixtures/workflow-recovery-public-v1.json").read_text(encoding="utf-8"))


@pytest.mark.asyncio
@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
async def test_shared_workflow_recovery(case):
    name = case["name"]

    class Client(StateClient):
        async def validate_current_execution(self):
            if name == "revoked":
                raise GatewayError("CAPABILITY_DENIED", "revoked fixture")
            await super().validate_current_execution()

    class Executor:
        sends = recoveries = 0

        async def execute(self, step, runtime, results):
            if name == "budget_exhausted":
                await runtime.admit_calls([("tool", "left"), ("tool", "right")])
            await runtime.admit_call("tool", runtime.operation_key)
            self.sends += 1
            if name in ("lost_tool_reply", "readonly_pending"):
                raise GatewayError("UPSTREAM_TIMEOUT", "original receipt retained")
            return self.receipt()

        async def recover(self, step, runtime, results):
            assert runtime.recovering
            self.recoveries += 1
            return self.receipt()

        def receipt(self):
            return {"status": "completed", "covered_slots": ["answer"], "output": {"receipt": "original"}}

    client, executor = Client(), Executor()
    step = copy.deepcopy(FIXTURE["step"])
    options = dict(key="shared", required_slots=["answer"], max_calls={"tool": 1 if name == "budget_exhausted" else 8})
    if name == "timeout":
        options["deadline_ms"] = 1

    async def run():
        return await run_step_workflow(client, [step], executor, **options)

    result = None
    try:
        if name == "cancelled_before_dispatch":
            task = asyncio.create_task(run())
            task.cancel()
            await task
        else:
            if name in ("lost_tool_reply", "readonly_pending"):
                with pytest.raises(GatewayError) as unknown:
                    await run()
                assert unknown.value.code == "UPSTREAM_TIMEOUT"
                options["inspect_only"] = name == "readonly_pending"
            result = await run()
            if name in ("duplicate", "parameter_conflict"):
                if name == "parameter_conflict":
                    step["payload"]["query"] = "different"
                result = await run()
    except asyncio.CancelledError:
        assert case.get("error") == "CANCELLED"
    except GatewayError as error:
        assert error.code == case.get("error")
    else:
        assert "error" not in case
        assert result["status"] == case["status"]
        if "finish_reason" in case:
            assert result["finish_reason"] == case["finish_reason"]
    assert executor.sends == case["sends"]
    assert executor.recoveries == case["recoveries"]
