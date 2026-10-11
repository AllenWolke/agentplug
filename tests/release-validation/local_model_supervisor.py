"""Cross-platform supervisor for the local OpenAI-compatible model process.

Docker handles container-level restart; this process also detects a hung/unhealthy
model child and replaces it without depending on systemd or Windows Task Scheduler.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


SCRIPT = Path(__file__).with_name("local_openai_server.py")
HEALTH_URL = os.getenv("LOCAL_MODEL_HEALTH_URL", "http://127.0.0.1:18000/health")
CHECK_INTERVAL = max(1, int(os.getenv("LOCAL_MODEL_HEALTH_INTERVAL_SECONDS", "15")))
STARTUP_GRACE = max(1, int(os.getenv("LOCAL_MODEL_STARTUP_GRACE_SECONDS", "300")))
FAILURE_THRESHOLD = max(1, int(os.getenv("LOCAL_MODEL_HEALTH_FAILURE_THRESHOLD", "4")))
RESTART_DELAY = max(0, int(os.getenv("LOCAL_MODEL_RESTART_DELAY_SECONDS", "5")))

stopping = False
child: subprocess.Popen[bytes] | None = None


def _signal_stop(_signum: int, _frame: object) -> None:
    global stopping
    stopping = True
    _stop_child()


def _stop_child() -> None:
    global child
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)


def _healthy() -> bool:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=5) as response:
            return response.status == 200
    except Exception:
        return False


def _wait_until_ready() -> bool:
    deadline = time.monotonic() + STARTUP_GRACE
    while not stopping and time.monotonic() < deadline:
        if child is None or child.poll() is not None:
            return False
        if _healthy():
            return True
        time.sleep(min(CHECK_INTERVAL, 5))
    return False


def main() -> int:
    global child
    signal.signal(signal.SIGTERM, _signal_stop)
    signal.signal(signal.SIGINT, _signal_stop)
    while not stopping:
        print("local-model-supervisor: starting model child", flush=True)
        child = subprocess.Popen([sys.executable, str(SCRIPT)])
        if not _wait_until_ready():
            exit_code = child.poll()
            print(
                f"local-model-supervisor: startup failed or child exited ({exit_code}); restarting",
                flush=True,
            )
            _stop_child()
            if not stopping:
                time.sleep(RESTART_DELAY)
            continue

        print("local-model-supervisor: model is healthy", flush=True)
        failures = 0
        while not stopping and child.poll() is None:
            time.sleep(CHECK_INTERVAL)
            if _healthy():
                failures = 0
                continue
            failures += 1
            print(
                f"local-model-supervisor: health failure {failures}/{FAILURE_THRESHOLD}",
                flush=True,
            )
            if failures >= FAILURE_THRESHOLD:
                print("local-model-supervisor: replacing unhealthy model child", flush=True)
                _stop_child()
                break

        if not stopping:
            time.sleep(RESTART_DELAY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
