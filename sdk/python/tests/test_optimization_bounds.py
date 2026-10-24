import asyncio
import pytest
from agent_platform_sdk.optimization import DeadlineBudget,StageRecorder,decisive_error,bounded_map,retry_bounded,authority_failure
from agent_platform_sdk.capability_client import GatewayError


@pytest.mark.parametrize("code", ["CAPABILITY_UNAVAILABLE", "STATE_UNAVAILABLE",
    "MODEL_BUDGET_UNAVAILABLE", "MODEL_BUDGET_ADMISSION_DEFERRED", "RUNTIME_BUDGET_UNAVAILABLE"])
def test_unfinished_current_check_is_not_a_confirmed_revocation(code):
    unfinished = GatewayError(code, "no access granted; original result may require recovery")
    unfinished.status_code = 503
    assert not authority_failure(unfinished)
    denied = GatewayError("CAPABILITY_DENIED", "revoked")
    denied.status_code = 403
    assert authority_failure(denied)
    assert decisive_error(ExceptionGroup("mixed", [unfinished, denied])) is denied


@pytest.mark.parametrize("code", ["MODEL_BUDGET_UNAVAILABLE", "MODEL_BUDGET_ADMISSION_DEFERRED", "RUNTIME_BUDGET_UNAVAILABLE"])
def test_operational_budget_error_cannot_override_explicit_denial(code):
    denied = GatewayError(code, "contradictory envelope")
    denied.status_code = 403
    assert authority_failure(denied)


@pytest.mark.parametrize("code", ["MODEL_BUDGET_EXCEEDED", "BUDGET_EXHAUSTED", "RUNTIME_BUDGET_SCOPE_DENIED", "MODEL_BUDGET_UNKNOWN"])
def test_unrecognized_or_confirmed_budget_boundaries_remain_fatal(code):
    assert authority_failure(GatewayError(code, "no new work"))


def test_nested_authority_error_takes_precedence_over_transient_sibling():
    denied=GatewayError('TOOL_PERMISSION_DENIED','sensitive message')
    errors=ExceptionGroup('parallel failures',[TimeoutError(),ExceptionGroup('nested',[denied])])
    assert decisive_error(errors) is denied


@pytest.mark.asyncio
async def test_fixed_workers_cancel_and_await_siblings_on_authority_failure():
    active=0;peak=0;finished=0
    async def handle(value,budget):
        nonlocal active,peak,finished
        active+=1;peak=max(peak,active)
        try:
            if value==0:
                await asyncio.sleep(.01)
                raise GatewayError('POLICY_REVISION_DENIED','private detail')
            await asyncio.sleep(5)
            return value
        finally:active-=1;finished+=1
    with pytest.raises(GatewayError,match='POLICY_REVISION_DENIED'):
        await bounded_map(range(10000),handle,workers=4)
    assert peak<=4 and active==0 and finished<=4


@pytest.mark.asyncio
async def test_unconfirmed_model_timeout_is_not_retried_and_counts_one_call():
    attempts=0;budget=DeadlineBudget.after(2)
    async def call():
        nonlocal attempts
        attempts+=1;raise TimeoutError('charge unknown')
    with pytest.raises(TimeoutError):
        await retry_bounded(call,budget=budget,safe_to_retry=lambda _error:False,attempts=3)
    assert attempts==1 and budget.calls==1


@pytest.mark.asyncio
async def test_pending_items_do_not_consume_the_item_deadline():
    recorder=StageRecorder()
    finished_at = {}
    async def handle(value,budget):
        # Assert the scheduling boundary itself. A 30ms sleep inside a 50ms
        # budget depends on Windows timer jitter and unrelated host load.
        if value:
            assert budget.created_at >= finished_at[value - 1]
        await asyncio.sleep(0)
        budget.remaining()
        finished_at[value] = asyncio.get_running_loop().time()
        return value
    # The next item's deadline must be created after the prior worker frees
    # capacity. Starting all deadlines at batch start violates this relation.
    assert await bounded_map(range(10),handle,workers=1,item_timeout=5,recorder=recorder) == list(range(10))
    assert len(finished_at) == 10


@pytest.mark.asyncio
async def test_admission_latency_is_charged_inside_the_item_deadline():
    entered,recorder=[],StageRecorder()
    async def admit(value,budget):
        await asyncio.sleep(.06)
    async def handle(value,budget):
        entered.append(value)
        budget.remaining()
        return value
    with pytest.raises(TimeoutError):
        await bounded_map([0,1],handle,workers=1,item_timeout=.05,admit_item=admit,recorder=recorder)
    assert entered == [0]
    assert recorder.samples[-1]['admission_ms'] >= 60


def test_stage_metrics_are_bounded_and_do_not_include_exception_messages():
    recorder=StageRecorder()
    with pytest.raises(ValueError):
        with recorder.stage('controlled.fail',calls=1):raise ValueError('secret-never-log')
    assert recorder.samples[0]['status']=='failed'
    assert 'secret-never-log' not in str(recorder.samples)
    with pytest.raises(ValueError):
        with recorder.stage('bad label'):pass


@pytest.mark.asyncio
async def test_optional_durable_admission_runs_before_enqueue_and_cannot_extend_deadline():
    events, elapsed = [], []
    async def admit(value, budget):
        events.append(("admit", value))
        original = budget.expires_at
        budget.expires_at += 100
        elapsed.append(original)
    async def handle(value, budget):
        events.append(("handle", value))
        assert budget.expires_at == elapsed[value]
        return value
    assert await bounded_map(range(3), handle, workers=1, admit_item=admit) == [0, 1, 2]
    for value in range(3): assert events.index(("admit", value)) < events.index(("handle", value))


@pytest.mark.asyncio
async def test_unknown_durable_admission_stops_before_item_execution():
    executed = []
    async def admit(value, budget): raise GatewayError("STATE_RESULT_UNKNOWN", "no dispatch proof")
    async def handle(value, budget): executed.append(value); return value
    with pytest.raises(GatewayError, match="STATE_RESULT_UNKNOWN"):
        await bounded_map([0], handle, admit_item=admit)
    assert executed == []
