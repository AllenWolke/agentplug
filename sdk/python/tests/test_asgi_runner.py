import asyncio, sys
import pytest
from agent_platform_sdk import asgi_runner


def test_real_native_postgres_loop_is_selector_on_windows():
    loop=asgi_runner.event_loop_factory()
    try:
        if sys.platform=='win32':assert isinstance(loop,asyncio.SelectorEventLoop)
        assert not loop.is_running()
        async def probe():return asyncio.get_running_loop() is loop
        assert loop.run_until_complete(probe())
    finally:loop.close()


@pytest.mark.parametrize('port',['0','65536','-1'])
def test_invalid_port_rejected_before_service_creation(port):
    with pytest.raises(SystemExit) as e:asgi_runner.main(['app.main:app','--port',port])
    assert e.value.code==2
