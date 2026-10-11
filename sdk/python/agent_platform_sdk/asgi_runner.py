"""Run an SDK ASGI Agent with the PostgreSQL-compatible native event loop."""
from __future__ import annotations
import argparse
import asyncio
import sys


def event_loop_factory():
    # Psycopg async I/O requires Selector on Windows. Do not change global policy.
    return asyncio.SelectorEventLoop() if sys.platform == 'win32' else asyncio.new_event_loop()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('application', help='ASGI import path, e.g. app.main:app')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--log-level', choices=('critical','error','warning','info','debug','trace'), default='info')
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error('port must be between 1 and 65535')
    import uvicorn
    config = uvicorn.Config(args.application, host=args.host, port=args.port, loop='none', log_level=args.log_level)
    server = uvicorn.Server(config)
    with asyncio.Runner(loop_factory=event_loop_factory) as runner:
        runner.run(server.serve())


if __name__ == '__main__':
    main()
