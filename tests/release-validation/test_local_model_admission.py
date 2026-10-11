"""模型队列隔离、过载和取消回归；不加载模型权重。"""
import asyncio
import importlib.util
from pathlib import Path
import sys
import unittest

spec = importlib.util.spec_from_file_location("local_model_admission_test_target", Path(__file__).with_name("local_openai_server.py"))
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
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
