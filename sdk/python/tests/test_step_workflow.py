import asyncio
import copy
import time

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.step_workflow import run_step_workflow, STATE_SCHEMA
from test_public_harness import Fixture


class StateClient(Fixture):
    def __init__(self):
        super().__init__()
        self.fail_done = False
        self.fail_intent = False
        self.conflict = False
        self.authorized = 0

    async def validate_current_execution(self):
        self.authorized += 1

    async def save_checkpoint(self, namespace, key, schema, value, expected, operation_key, **kwargs):
        assert namespace == "step-workflow" and schema == STATE_SCHEMA
        assert operation_key == f"steps-{expected + 1}"
        if self.conflict:
            raise GatewayError("STATE_CONFLICT", "fixed")
        if self.fail_intent and value["phase"] == "dispatch":
            self.fail_intent = False
            raise GatewayError("STATE_UNAVAILABLE", "fixed")
        if self.fail_done and value["results"]:
            self.fail_done = False
            raise GatewayError("STATE_UNAVAILABLE", "fixed")
        assert expected == self.revision
        self.revision += 1
        self.checkpoint = {"revision": self.revision, "value": copy.deepcopy(value)}
        return {"checkpoint": copy.deepcopy(self.checkpoint)}


def step(name="one", slots=None, dependencies=None):
    return {"id": name, "payload": {"query": name}, "depends_on": dependencies or [],
            "required_slots": slots if slots is not None else [name]}


class Executor:
    def __init__(self):
        self.calls = self.recoveries = 0
        self.receipts = {}
        self.unknown = False
        self.partial = False
        self.delay = 0
        self.started = asyncio.Event()

    async def execute(self, task, runtime, results):
        await runtime.admit_call("retrieval", task["id"])
        self.calls += 1
        self.started.set()
        if self.delay:
            await asyncio.sleep(self.delay)
        result = {"status": "incomplete" if self.partial else "completed",
                  "covered_slots": [] if self.partial else task["required_slots"],
                  "output": {"query": task["payload"]["query"]}}
        self.receipts[runtime.operation_key] = result
        if self.unknown:
            raise GatewayError("MODEL_RESULT_UNKNOWN", "fixed")
        return copy.deepcopy(result)

    async def recover(self, task, runtime, results):
        assert runtime.recovering
        self.recoveries += 1
        return copy.deepcopy(self.receipts.get(runtime.operation_key, {"status": "unknown"}))


async def run(client, executor, tasks=None, **kwargs):
    return await run_step_workflow(client, tasks or [step()], executor, key="ordered",
                                  required_slots=kwargs.pop("required_slots", ["one"]),
                                  max_calls={"retrieval": kwargs.pop("retrieval_limit", 10)}, **kwargs)


@pytest.mark.asyncio
async def test_ordered_steps_dependencies_and_finished_replay_do_not_charge_twice():
    client, executor = StateClient(), Executor()
    tasks = [step(), step("two", dependencies=["one"])]
    first = await run(client, executor, tasks, required_slots=["one", "two"])
    assert first["status"] == "completed" and first["calls"] == {"retrieval": 2}
    assert await run(client, executor, tasks, required_slots=["one", "two"]) == first
    assert executor.calls == client.authorized == 2 and executor.recoveries == 0


@pytest.mark.asyncio
async def test_atomic_independent_reservations_and_terminal_ack_loss_never_redispatch():
    class LostAckClient(StateClient):
        async def save_checkpoint(self, *args, **kwargs):
            result = await super().save_checkpoint(*args, **kwargs)
            if args[3]["phase"] == "completed":
                raise GatewayError("STATE_UNAVAILABLE", "commit succeeded; reply lost")
            return result
    class PairExecutor(Executor):
        async def execute(self, task, runtime, results):
            await runtime.admit_calls([("retrieval", "left"), ("retrieval", "right")])
            assert client.checkpoint["value"]["reservations"] == {"left": "retrieval", "right": "retrieval"}
            self.calls += 1
            return {"status": "completed", "covered_slots": ["one"], "output": {}}
    client, executor = LostAckClient(), PairExecutor()
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await run(client, executor)
    # Initial plan, intent, atomic two-call reservation, final result/status.
    assert client.revision == 4 and executor.calls == 1
    result = await run(client, executor)
    assert result["status"] == "completed" and result["calls"]["retrieval"] == 2
    assert client.revision == 4 and executor.calls == 1 and executor.recoveries == 0


@pytest.mark.asyncio
async def test_invalid_batch_and_failed_reservation_save_cannot_leave_local_admission():
    class FailedReservationClient(StateClient):
        attempts = 0
        async def save_checkpoint(self, *args, **kwargs):
            if args[3]["reservations"]:
                self.attempts += 1
                raise GatewayError("STATE_UNAVAILABLE", "reservation not acknowledged")
            return await super().save_checkpoint(*args, **kwargs)
    class PairExecutor(Executor):
        async def execute(self, task, runtime, results):
            with pytest.raises(GatewayError, match="STEP_CALL_LIMIT_EXCEEDED"):
                await runtime.admit_calls([("retrieval", "left"), ("retrieval", "right")])
            for _ in range(2):
                with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
                    await runtime.admit_calls([("retrieval", "left")])
            assert client.attempts == 2
            assert client.checkpoint["value"]["reservations"] == {}
            raise GatewayError("STEP_RECONCILIATION_REQUIRED", "no work was dispatched")
    client, executor = FailedReservationClient(), PairExecutor()
    with pytest.raises(GatewayError, match="STEP_RECONCILIATION_REQUIRED"):
        await run(client, executor, retrieval_limit=1)
    assert executor.calls == 0 and client.revision == 2


@pytest.mark.asyncio
async def test_old_running_result_checkpoint_and_expired_recovery_keep_original_semantics():
    client, executor = StateClient(), Executor()
    result = await run(client, executor)
    client.checkpoint["value"].update(phase="running", finish_reason="running")
    assert (await run(client, executor))["status"] == "completed"
    assert executor.calls == 1
    client, executor = StateClient(), Executor()
    executor.unknown = True
    with pytest.raises(GatewayError, match="MODEL_RESULT_UNKNOWN"):
        await run(client, executor)
    original = int(time.time() * 1000) - 100
    client.checkpoint["value"]["deadline_ms"] = original
    recovered = await run(client, executor)
    assert recovered["status"] == "incomplete" and recovered["finish_reason"] == "elapsed_limit"
    assert recovered["deadline_ms"] == original and list(recovered["results"]) == ["one"]
    assert executor.calls == executor.recoveries == 1


@pytest.mark.asyncio
async def test_prequeue_admission_freezes_original_plan_deadline_without_dispatch():
    client, executor = StateClient(), Executor()
    first = await run(client, executor, timeout=30, prepare_only=True)
    assert client.revision == 1 and executor.calls == executor.recoveries == 0
    assert first["calls"] == {"retrieval": 0} and first["admission"]["phase"] == "running"
    original = copy.deepcopy(client.checkpoint)
    # Server time is millisecond precision; observe a real elapsed interval
    # rather than compare two sub-millisecond monotonic clock estimates.
    await asyncio.sleep(0.005)
    second = await run(client, executor, timeout=30, deadline_ms=first["deadline_ms"] + 10000, prepare_only=True)
    assert second["deadline_ms"] == first["deadline_ms"] and client.checkpoint == original
    assert second["admission"]["remaining_seconds"] <= first["admission"]["remaining_seconds"]
    result = await run(client, executor, timeout=30, deadline_ms=first["deadline_ms"])
    assert result["status"] == "completed" and result["deadline_ms"] == first["deadline_ms"]
    assert executor.calls == 1


@pytest.mark.asyncio
async def test_inspection_without_checkpoint_does_not_create_or_execute():
    client, executor = StateClient(), Executor()
    with pytest.raises(GatewayError, match="STEP_RECONCILIATION_REQUIRED"):
        await run(client, executor, inspect_only=True)
    assert client.checkpoint is None and client.revision == 0
    assert executor.calls == executor.recoveries == client.authorized == 0


@pytest.mark.asyncio
async def test_inspection_preserves_expired_dispatch_results_reservations_and_unknown_fence():
    client = StateClient()
    class PartialExecutor(Executor):
        async def execute(self, task, runtime, results):
            self.unknown = task["id"] == "two"
            return await super().execute(task, runtime, results)
    executor = PartialExecutor()
    tasks = [step(), step("two", dependencies=["one"])]
    with pytest.raises(GatewayError, match="MODEL_RESULT_UNKNOWN"):
        await run(client, executor, tasks, required_slots=["one", "two"])
    client.checkpoint["value"]["deadline_ms"] = int(time.time() * 1000) - 100
    original = copy.deepcopy(client.checkpoint)
    inspected = await run(client, executor, tasks, required_slots=["one", "two"], inspect_only=True)
    assert inspected["inspection"] == {"read_only": True, "phase": "dispatch", "pending_step": "two",
        "reconciliation_required": True, "expired": True}
    assert inspected["missing_slots"] == ["two"] and list(inspected["results"]) == ["one"]
    assert inspected["calls"] == {"retrieval": 2}
    assert executor.calls == client.authorized == 2 and executor.recoveries == 0
    assert client.checkpoint == original
    inspected["results"]["one"]["output"]["query"] = "caller mutation"
    assert client.checkpoint == original


@pytest.mark.asyncio
async def test_inspection_revalidates_saved_evidence_and_propagates_authority_denial():
    client, executor = StateClient(), Executor()
    await run(client, executor)
    original = copy.deepcopy(client.checkpoint)
    checked = []
    async def denied(task, result):
        checked.append(task["id"])
        return False
    executor.revalidate = denied
    with pytest.raises(GatewayError, match="STEP_RESULT_AUTHORITY_DENIED"):
        await run(client, executor, inspect_only=True)
    assert checked == ["one"] and client.checkpoint == original
    assert executor.calls == 1 and executor.recoveries == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("options", [{"prepare_only": True}, {"additional_steps": []}, {"inspect_only": 1}])
async def test_inspection_rejects_mutating_or_invalid_configuration(options):
    client, executor = StateClient(), Executor()
    with pytest.raises(GatewayError, match="STEP_CONFIG_INVALID"):
        await run(client, executor, **{"inspect_only": True, **options})
    assert client.revision == executor.calls == executor.recoveries == 0


@pytest.mark.asyncio
async def test_expired_prequeue_plan_is_not_given_a_new_deadline_or_operation():
    client, executor = StateClient(), Executor()
    await run(client, executor, timeout=30, prepare_only=True)
    client.checkpoint["value"]["deadline_ms"] = int(time.time() * 1000) - 100
    deadline = client.checkpoint["value"]["deadline_ms"]
    prepared = await run(client, executor, timeout=30, deadline_ms=deadline, prepare_only=True)
    assert prepared["deadline_ms"] == deadline and prepared["admission"]["remaining_seconds"] == 0
    result = await run(client, executor, timeout=30, deadline_ms=deadline)
    assert result["status"] == "incomplete" and executor.calls == 0


@pytest.mark.asyncio
async def test_lost_admission_acknowledgement_reads_original_state_without_another_write():
    client, executor = StateClient(), Executor()
    original_save = client.save_checkpoint
    async def lost_ack(*args, **kwargs):
        await original_save(*args, **kwargs)
        raise GatewayError("STATE_UNAVAILABLE", "controlled lost admission acknowledgement")
    client.save_checkpoint = lost_ack
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await run(client, executor, prepare_only=True)
    assert client.revision == 1 and executor.calls == 0
    client.save_checkpoint = original_save
    prepared = await run(client, executor, prepare_only=True)
    assert prepared["deadline_ms"] == client.checkpoint["value"]["deadline_ms"] and client.revision == 1


@pytest.mark.asyncio
async def test_admission_cas_conflict_never_starts_executor():
    client, executor = StateClient(), Executor()
    client.conflict = True
    with pytest.raises(GatewayError, match="STATE_CONFLICT"):
        await run(client, executor, prepare_only=True)
    assert executor.calls == executor.recoveries == 0


@pytest.mark.asyncio
async def test_reply_lost_recovers_receipt_without_redispatch_or_resetting_budget():
    client, executor = StateClient(), Executor()
    executor.unknown = True
    with pytest.raises(GatewayError, match="MODEL_RESULT_UNKNOWN"):
        await run(client, executor)
    deadline = client.checkpoint["value"]["deadline_ms"]
    result = await run(client, executor)
    assert result["status"] == "completed" and result["deadline_ms"] == deadline
    assert executor.calls == executor.recoveries == result["calls"]["retrieval"] == 1


@pytest.mark.asyncio
async def test_unknown_receipt_stays_unknown_and_never_runs_again():
    client, executor = StateClient(), Executor()
    client.fail_done = True
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await run(client, executor)
    executor.receipts.clear()
    for _ in range(2):
        with pytest.raises(GatewayError, match="STEP_RECONCILIATION_REQUIRED"):
            await run(client, executor)
    assert executor.calls == 1 and client.checkpoint["value"]["phase"] == "dispatch"


@pytest.mark.asyncio
async def test_lost_result_save_recovers_completed_result_once():
    client, executor = StateClient(), Executor()
    client.fail_done = True
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await run(client, executor)
    assert (await run(client, executor))["status"] == "completed"
    assert executor.calls == executor.recoveries == 1


@pytest.mark.asyncio
async def test_intent_save_failure_and_cas_conflict_prevent_adapter_dispatch():
    client, executor = StateClient(), Executor()
    client.fail_intent = True
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await run(client, executor)
    assert executor.calls == 0
    client.conflict = True
    with pytest.raises(GatewayError, match="STATE_CONFLICT"):
        await run(client, executor)
    assert executor.calls == 0


@pytest.mark.asyncio
async def test_append_only_extension_preserves_required_slots_and_prior_results():
    client, executor = StateClient(), Executor()
    tasks = [step(slots=["one"])]
    result = await run(client, executor, tasks, required_slots=["one", "two"])
    assert result["missing_slots"] == ["two"] and result["status"] == "incomplete"
    extension = [step("two", dependencies=["one"])]
    result = await run(client, executor, tasks, required_slots=["one", "two"], additional_steps=extension)
    assert result["status"] == "completed" and result["extensions"] == 1
    assert await run(client, executor, tasks, required_slots=["one", "two"], additional_steps=extension) == result
    with pytest.raises(GatewayError, match="STEP_STATE_REJECTED"):
        await run(client, executor, tasks, required_slots=["one"])
    with pytest.raises(GatewayError, match="STEP_EXTENSION_REJECTED"):
        await run(client, executor, tasks, required_slots=["one", "two"], additional_steps=[step("other", slots=["two"])])
    assert executor.calls == 2


@pytest.mark.asyncio
async def test_unmet_dependency_prevents_following_step():
    client, executor = StateClient(), Executor()
    executor.partial = True
    result = await run(client, executor, [step(), step("two", dependencies=["one"])], required_slots=["one", "two"])
    assert result["finish_reason"] == "dependency_incomplete" and executor.calls == 1


@pytest.mark.asyncio
async def test_future_or_cyclic_dependency_rejected_before_state_or_execution():
    client, executor = StateClient(), Executor()
    with pytest.raises(GatewayError, match="STEP_PLAN_REJECTED"):
        await run(client, executor, [step(dependencies=["two"]), step("two")])
    assert client.revision == executor.calls == 0


@pytest.mark.asyncio
async def test_call_limit_cannot_be_exceeded_or_reset_on_resume():
    client, executor = StateClient(), Executor()
    tasks = [step(), step("two")]
    with pytest.raises(GatewayError, match="STEP_CALL_LIMIT_EXCEEDED"):
        await run(client, executor, tasks, required_slots=["one", "two"], retrieval_limit=1)
    assert executor.calls == 1
    with pytest.raises(GatewayError, match="STEP_RECONCILIATION_REQUIRED"):
        await run(client, executor, tasks, required_slots=["one", "two"], retrieval_limit=1)
    assert executor.calls == 1
    with pytest.raises(GatewayError, match="STEP_STATE_REJECTED"):
        await run(client, executor, tasks, required_slots=["one", "two"], retrieval_limit=2)


@pytest.mark.asyncio
async def test_expired_initial_deadline_stops_without_model_or_tool():
    client, executor = StateClient(), Executor()
    result = await run(client, executor, deadline_ms=int(time.time() * 1000) - 100)
    assert result["finish_reason"] == "elapsed_limit" and executor.calls == 0


@pytest.mark.asyncio
async def test_cancel_before_dispatch_and_cancel_during_execution():
    client, executor = StateClient(), Executor()
    result = await run(client, executor, cancelled=lambda: True)
    assert result["status"] == "cancelled" and executor.calls == 0
    client, executor = StateClient(), Executor()
    executor.delay = 60
    task = asyncio.create_task(run(client, executor))
    await executor.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client.checkpoint["value"]["phase"] == "dispatch"
    with pytest.raises(GatewayError, match="STEP_RECONCILIATION_REQUIRED"):
        await run(client, executor)
    assert executor.calls == 1
