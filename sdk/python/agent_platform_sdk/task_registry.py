"""Scoped cooperative task supervision. / 作用域隔离的协作式任务监督。"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
import threading
import os
import uuid
from .generation_exit import GenerationExitStore, PostgresGenerationExitStore
from contextlib import suppress
from collections.abc import Awaitable, Callable
from typing import TypeVar

from .errors import DomainExecutionError
from .models import ExecuteRequest

T = TypeVar("T")


class ExecutionTaskRegistry:
    """Own tasks until they stop, not merely until cancellation is requested.

    取消完成必须等待任务真正退出；本地登记不替代平台持久化取消状态。
    """

    def __init__(self, *, exit_store: GenerationExitStore | None = None) -> None:
        dsn = os.getenv('EXECUTION_EXIT_STORE_DSN', '').strip()
        self._exit_store = exit_store if exit_store is not None else (PostgresGenerationExitStore(dsn) if dsn else None)
        self._admitting: set[str] = set()
        self._tasks: dict[str, asyncio.Task] = {}
        # Exit is a property of the supervised execute() parent, not merely
        # its child action task. A cancel acknowledgment waits for this event
        # after the parent has recorded the proof.
        self._exit_events: dict[str, asyncio.Event] = {}
        self._cancelled: dict[str, float] = {}
        self._exited: dict[str, float] = {}
        self._background: dict[str, asyncio.Task] = {}
        self._lock = threading.RLock()

    @staticmethod
    def key(request: ExecuteRequest) -> str:
        # Trace and authorization refresh are not execution identities.
        # Trace 与授权刷新不是执行身份；完整业务作用域和 Run 才是身份。
        scope = request.scope.model_dump(exclude={"trace_id", "authorization_epoch"})
        # Called only after the authorization hook verified the signature.
        # 仅在授权 Hook 验签之后读取世代，不能以此解析器代替验签。
        try:
            payload = request.context_token.split(".")[1]
            claims = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            )
            revision = claims["execution_revision"]
            token_hash = claims["lease_token_hash"]
            if (
                type(revision) is not int
                or revision < 1
                or not isinstance(token_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", token_hash)
            ):
                raise ValueError
        except (ValueError, KeyError, IndexError, TypeError):
            raise DomainExecutionError("INVALID_REQUEST") from None
        return json.dumps(
            [scope, revision, token_hash], sort_keys=True, separators=(",", ":")
        )

    def _prune(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._cancelled = {
                key: until for key, until in self._cancelled.items() if until > now
            }
            self._exited = {key: until for key, until in self._exited.items() if until > now}

    def has_exit_proof(self, request: ExecuteRequest) -> bool:
        """Only a locally observed task exit proves this generation stopped."""
        return self.has_generation_exit_proof(self.key(request))

    def has_generation_exit_proof(self, key: str) -> bool:
        """For SDK lifecycle adapters retaining a verified generation key."""
        with self._lock:
            self._prune()
            return key in self._exited

    def generation_replay_state(self, key: str) -> str:
        """Return active/exited/unknown for one exact private generation key.

        The lifecycle may expose a same-generation replay only after current
        authorization and a fresh call to this registry-owned snapshot.
        """
        if not isinstance(key, str) or not key:
            return "unknown"
        with self._lock:
            self._prune()
            try:
                decoded = json.loads(key)
                run_id = decoded[0]["run_id"]
                if not isinstance(run_id, str) or not run_id:
                    return "unknown"
            except (ValueError, IndexError, KeyError, TypeError):
                return "unknown"
            for other_key, other_task in self._tasks.items():
                if other_key == key or other_task.done():
                    continue
                try:
                    if json.loads(other_key)[0]["run_id"] == run_id:
                        return "unknown"
                except (ValueError, IndexError, KeyError, TypeError):
                    return "unknown"
            task = self._tasks.get(key)
            if task is not None and not task.done():
                try:
                    # A request may be running inside this same Registry entry.
                    # That transport task is not the previously admitted Agent
                    # handler and must never count as its private active proof.
                    if task is asyncio.current_task():
                        return "unknown"
                except RuntimeError:
                    return "unknown"
                return "active"
            if key in self._exited:
                return "exited"
            return "unknown"

    def has_other_active_generation(self, request: ExecuteRequest) -> bool:
        """Exclude the transport's current supervised resume task itself."""
        current_key = self.key(request)
        with self._lock:
            for key, task in self._tasks.items():
                if key == current_key or task.done():
                    continue
                try:
                    if json.loads(key)[0]["run_id"] == request.scope.run_id:
                        return True
                except (ValueError, IndexError, KeyError, TypeError):
                    return True
        return False

    async def execute(
        self,
        request: ExecuteRequest,
        action: Callable[[], Awaitable[T]],
        disconnected: Callable[[], Awaitable[bool]] | None = None,
        *,
        registered: asyncio.Event | None = None,
    ) -> T:
        key = self.key(request)
        async def run_action() -> T:
            # The public Port accepts any Awaitable; create_task requires a
            # coroutine. Invoke inside the supervised task, including sync errors.
            # 公共Port接受任意Awaitable；在受监督协程内调用，亦覆盖同步抛错。
            return await action()

        owner = str(uuid.uuid4())
        admitted = False
        with self._lock:
            self._prune()
            if key in self._cancelled:
                raise DomainExecutionError("EXECUTION_CANCELLED")
            if key in self._tasks or key in self._admitting:
                raise DomainExecutionError("EXECUTION_ALREADY_ACTIVE")
            if len(self._tasks) + len(self._admitting) >= 4096:
                raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
            self._admitting.add(key)
        try:
            if self._exit_store is not None:
                await self._exit_store.admit(key, owner)
                admitted = True
            with self._lock:
                # Cancel may have arrived while durable admission was pending.
                if key in self._cancelled:
                    raise DomainExecutionError("EXECUTION_CANCELLED")
                if self._exit_store is not None:
                    self._exited.pop(key, None)
                task: asyncio.Task[T] = asyncio.create_task(run_action())
                self._tasks[key] = task
                exit_event = asyncio.Event()
                self._exit_events[key] = exit_event
                if registered is not None:
                    registered.set()
        except BaseException:
            if admitted:
                await self._exit_store.exit(key, owner)
            raise
        finally:
            with self._lock:
                self._admitting.discard(key)

        async def watch_connection() -> None:
            assert disconnected is not None
            while not task.done():
                try:
                    lost = await disconnected()
                except Exception:
                    # Failed supervision must not permit unattended graph work.
                    # 监督失败不能让无人监管的业务图继续执行。
                    lost = True
                    logging.getLogger(__name__).warning(
                        "execution supervision failed code=CONNECTION_CHECK_FAILED"
                    )
                if lost:
                    task.cancel()
                    return
                await asyncio.sleep(0.05)

        monitor = asyncio.create_task(watch_connection()) if disconnected else None
        try:
            return await task
        except asyncio.CancelledError:
            parent = asyncio.current_task()
            if parent is not None and parent.cancelling():
                raise
            raise DomainExecutionError("EXECUTION_CANCELLED") from None
        finally:
            if monitor is not None:
                monitor.cancel()
                with suppress(asyncio.CancelledError):
                    await monitor
            # The receipt commits only after the exact action task has exited.
            # Active/unknown generations cannot be restored as exit evidence.
            durable_exit = self._exit_store is None
            if task.done() and self._exit_store is not None:
                try:
                    await self._exit_store.exit(key, owner)
                    durable_exit = True
                except (Exception, asyncio.CancelledError):
                    logging.getLogger(__name__).warning(
                        "execution exit persistence code=EXIT_RECEIPT_UNCONFIRMED"
                    )
            # Identity check prevents an old finally block removing another task.
            # 身份校验防止旧执行的 finally 删除后续执行任务。
            with self._lock:
                if self._tasks.get(key) is task:
                    del self._tasks[key]
                if task.done() and durable_exit:
                    # Bound development-only proof retention; absence fails closed.
                    if len(self._exited) >= 4096:
                        self._exited.pop(next(iter(self._exited)))
                    self._exited[key] = time.monotonic() + 900
                    supervised_exit = self._exit_events.pop(key, None)
                    if supervised_exit is not None:
                        # Publish proof only after the exact supervised
                        # generation has been removed and recorded as exited.
                        supervised_exit.set()

    async def start_background(
        self, request: ExecuteRequest, action: Callable[[], Awaitable[object]]
    ) -> None:
        """Return only after the verified generation is supervised.

        The action must persist lifecycle results through RunStore. This
        registry owns task exit proofs, not business state or durable recovery.
        """
        key = self.key(request)
        ready = asyncio.Event()
        with self._lock:
            if key in self._background or key in self._tasks:
                raise DomainExecutionError("EXECUTION_ALREADY_ACTIVE")
            if len(self._background) >= 4096:
                raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
            driver = asyncio.create_task(
                self.execute(request, action, registered=ready)
            )
            self._background[key] = driver

        def finished(task: asyncio.Task) -> None:
            with self._lock:
                if self._background.get(key) is task:
                    del self._background[key]
            if not task.cancelled() and task.exception() is not None:
                # Retrieve failures without logging payload, token, or upstream
                # exception text. The lifecycle action owns durable failure.
                logging.getLogger(__name__).warning(
                    "background execution ended code=EXECUTION_ACTION_FAILED"
                )

        driver.add_done_callback(finished)
        notification = asyncio.create_task(ready.wait())
        try:
            await asyncio.wait({notification, driver}, return_when=asyncio.FIRST_COMPLETED)
            if driver.done():
                driver.result()  # Admission errors must not become a false ACK.
            if not ready.is_set():
                raise DomainExecutionError("EXECUTION_START_UNCONFIRMED")
        except BaseException:
            driver.cancel()
            # A cancelled HTTP registration cannot leave unknown business work.
            # Do not wait indefinitely if an action suppresses cancellation.
            done, _ = await asyncio.wait({driver}, timeout=5.0)
            if not done:
                logging.getLogger(__name__).warning(
                    "background registration stop code=CANCELLATION_NOT_CONFIRMED"
                )
            raise
        finally:
            notification.cancel()
            with suppress(asyncio.CancelledError):
                await notification

    async def shutdown(self, timeout: float = 5.0) -> None:
        """Drain actual local tasks before transport dependencies are closed."""
        with self._lock:
            tasks = set(self._tasks.values()) | set(self._background.values())
        for task in tasks:
            task.cancel()
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=timeout)
            for task in done:
                if not task.cancelled():
                    task.exception()
            if pending:
                raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")

    async def cancel(self, request: ExecuteRequest, timeout: float = 5.0) -> bool:
        key = self.key(request)
        with self._lock:
            self._prune()
            if key not in self._cancelled and len(self._cancelled) >= 4096:
                raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
            # Persisted platform intent prevents renewing this generation. Keep a
            # local tombstone longer than the maximum five-minute signed lifetime
            # so cancel arriving before Invoke registration also prevents execution.
            # 平台持久化意图阻止续签；本地墓碑长于五分钟令牌 TTL，拒绝迟到 Invoke。
            self._cancelled[key] = time.monotonic() + 900
            task = self._tasks.get(key)
            exit_event = self._exit_events.get(key)
        if task is None:
            with self._lock:
                if key in self._admitting:
                    return False
            if self._exit_store is None or not await self._exit_store.stop_exited(key):
                return False
            with self._lock:
                # A concurrent admission invalidates a previously read receipt.
                if key in self._tasks or key in self._admitting:
                    return False
                if len(self._exited) >= 4096:
                    self._exited.pop(next(iter(self._exited)))
                self._exited[key] = time.monotonic() + 900
            return True
        if exit_event is None:
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
        deadline = asyncio.get_running_loop().time() + timeout
        task.cancel()
        # wait_for would wait indefinitely if a handler suppressed cancellation.
        # 使用有界 wait；业务抑制取消时不能伪造停止确认。
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if not done:
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
        if not task.cancelled():
            task.exception()  # Retrieve a terminal exception without logging data.
        # Child completion can wake asyncio.wait before execute()'s parent
        # finally stores its exit proof. Wait for that exact supervisor receipt
        # instead of treating task.done() as proof or relying on a scheduling
        # yield. The shared deadline keeps cancellation bounded.
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
        try:
            await asyncio.wait_for(exit_event.wait(), timeout=remaining)
        except asyncio.TimeoutError:
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED") from None
        if self._exit_store is not None and not await self._exit_store.stop_exited(key):
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
        return True
