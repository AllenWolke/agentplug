"""Parallel admission reads must not weaken send, failure or recovery fences."""
import asyncio
import copy

import pytest

from agent_platform_sdk.capability_client import GatewayError
from test_public_harness import Fixture, input


@pytest.mark.asyncio
async def test_initial_reads_overlap_without_sending_before_both_complete():
    class Overlapped(Fixture):
        def __init__(self):
            super().__init__()
            self.policy_started = asyncio.Event()
            self.checkpoint_started = asyncio.Event()

        async def load_harness_policy(self, **kwargs):
            self.policy_started.set()
            await self.checkpoint_started.wait()
            assert self.models == self.effects == self.revision == 0
            return await super().load_harness_policy(**kwargs)

        async def load_checkpoint(self, *args, **kwargs):
            self.checkpoint_started.set()
            await self.policy_started.wait()
            assert self.models == self.effects == self.revision == 0
            return await super().load_checkpoint(*args, **kwargs)

    client = Overlapped()
    result = await asyncio.wait_for(client.run_harness(input(), key="parallel-entry"), 1)
    assert result['status'] == 'approval_required'
    assert client.models == 1 and client.effects == 0


@pytest.mark.asyncio
async def test_policy_failure_drains_checkpoint_read_without_mutation():
    class Denied(Fixture):
        def __init__(self):
            super().__init__()
            self.started = asyncio.Event()
            self.drained = False

        async def load_harness_policy(self, **kwargs):
            await self.started.wait()
            raise GatewayError('CAPABILITY_DENIED', 'fixed')

        async def load_checkpoint(self, *args, **kwargs):
            self.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.drained = True

    client = Denied()
    with pytest.raises(GatewayError, match='CAPABILITY_DENIED'):
        await client.run_harness(input(), key='denied-entry')
    assert client.drained and client.models == client.effects == client.revision == 0


@pytest.mark.asyncio
async def test_checkpoint_error_remains_original_and_does_not_send():
    class Missing(Fixture):
        async def load_checkpoint(self, *args, **kwargs):
            raise GatewayError('STATE_UNAVAILABLE', 'fixed')

    client = Missing()
    with pytest.raises(GatewayError, match='STATE_UNAVAILABLE'):
        await client.run_harness(input(), key='unavailable-entry')
    assert client.models == client.effects == client.revision == 0


@pytest.mark.asyncio
async def test_outer_cancellation_drains_both_readers_without_sending():
    class Waiting(Fixture):
        def __init__(self):
            super().__init__()
            self.started = [asyncio.Event(), asyncio.Event()]
            self.drained = []

        async def wait(self, ordinal):
            self.started[ordinal].set()
            try:
                await asyncio.Event().wait()
            finally:
                self.drained.append(ordinal)

        async def load_harness_policy(self, **kwargs):
            return await self.wait(0)

        async def load_checkpoint(self, *args, **kwargs):
            return await self.wait(1)

    client = Waiting()
    task = asyncio.create_task(client.run_harness(input(), key='cancelled-entry'))
    await asyncio.gather(*(event.wait() for event in client.started))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert sorted(client.drained) == [0, 1]
    assert client.models == client.effects == client.revision == 0


@pytest.mark.asyncio
async def test_saved_approval_replay_retains_deadline_and_never_resends_model():
    client = Fixture()
    original = await client.run_harness(input(), key='saved-entry')
    saved = copy.deepcopy(client.checkpoint)
    replay = await client.run_harness(input(), key='saved-entry')
    assert replay == original and client.checkpoint == saved
    assert client.models == 1 and client.effects == 0
