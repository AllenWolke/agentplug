"""模型队列隔离、过载和取消回归；不加载模型权重。"""
import asyncio
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("local_model_admission_test_target", Path(__file__).with_name("local_openai_server.py"))
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_admission_import_does_not_require_model_backend(self):
        # Reproduce a quality runner without heavyweight inference packages,
        # even when the developer machine happens to have them installed.
        target = importlib.util.spec_from_file_location(
            "local_model_without_backend", Path(__file__).with_name("local_openai_server.py")
        )
        isolated = importlib.util.module_from_spec(target)
        sys.modules[target.name] = isolated
        try:
            with patch.dict(sys.modules, {"torch": None, "transformers": None}):
                target.loader.exec_module(isolated)
                route = isolated.AdmissionController(1, 0)
                await route.enter()
                self.assertEqual(route.snapshot()["running"], 1)
                await route.leave()
                self.assertEqual(route.admitted, 0)
        finally:
            sys.modules.pop(target.name, None)

    async def test_full_queue_and_cancel_release(self):
        route = module.AdmissionController(1, 1)
        await route.enter()
        waiting = asyncio.create_task(route.enter())
        await asyncio.sleep(0)
        with self.assertRaises(module.HTTPException) as caught:
            await route.enter()
        self.assertEqual(caught.exception.status_code, 429)
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        self.assertEqual(route.admitted, 1)
        await route.leave()
        self.assertEqual(route.admitted, 0)

    async def test_independent_routes(self):
        chat = module.AdmissionController(1, 0)
        rerank = module.AdmissionController(1, 32)
        await chat.enter()
        await rerank.enter()
        self.assertEqual(chat.snapshot()["queue_size"], 0)
        self.assertEqual(rerank.snapshot()["queue_size"], 32)
        await rerank.leave()
        await chat.leave()


if __name__ == "__main__":
    unittest.main()
