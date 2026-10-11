import asyncio
import pytest
from agent_platform_sdk.optimization import DeadlineBudget,StageRecorder,decisive_error,bounded_map,retry_bounded
from agent_platform_sdk.capability_client import GatewayError


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
async def test_queued_item_deadline_begins_before_worker_admission():
    recorder=StageRecorder()
    async def handle(value,budget):
        await asyncio.sleep(.03)
        budget.remaining()
        return value
    with pytest.raises(TimeoutError):
        await bounded_map(range(10),handle,workers=1,item_timeout=.05,recorder=recorder)
    assert any(sample['queue_wait_ms']>=20 for sample in recorder.samples)


def test_stage_metrics_are_bounded_and_do_not_include_exception_messages():
    recorder=StageRecorder()
    with pytest.raises(ValueError):
        with recorder.stage('controlled.fail',calls=1):raise ValueError('secret-never-log')
    assert recorder.samples[0]['status']=='failed'
    assert 'secret-never-log' not in str(recorder.samples)
    with pytest.raises(ValueError):
        with recorder.stage('bad label'):pass
