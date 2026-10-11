import asyncio
import sys
import pytest

@pytest.fixture(scope='session')
def event_loop_policy():
    if sys.platform=='win32':
        return asyncio.WindowsSelectorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()
