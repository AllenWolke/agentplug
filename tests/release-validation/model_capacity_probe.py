"""Measure concurrent-user capacity of an OpenAI-compatible chat endpoint."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import time

import httpx


async def request_once(
    client: httpx.AsyncClient, endpoint: str, model: str, index: int
) -> tuple[int | str, float]:
    started = time.perf_counter()
    try:
        response = await client.post(
            endpoint,
            json={
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": f"用一句话说明银行监管数据质量校验的目标。请求{index}",
                    }
                ],
                "temperature": 0,
                "max_tokens": 16,
            },
        )
        status: int | str = response.status_code
    except Exception as exc:  # result artifact must include transport failures
        status = type(exc).__name__
    return status, (time.perf_counter() - started) * 1000


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--endpoint", default="http://127.0.0.1:18000/v1/chat/completions"
    )
    parser.add_argument("--model", default="Qwen2.5-3B-Instruct")
    parser.add_argument("--levels", default="1,2,4,8")
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    levels = [int(item) for item in args.levels.split(",")]
    output: list[dict] = []
    async with httpx.AsyncClient(timeout=args.timeout, trust_env=False) as client:
        for users in levels:
            started = time.perf_counter()
            rows = await asyncio.gather(
                *(
                    request_once(client, args.endpoint, args.model, index)
                    for index in range(users)
                )
            )
            wall_seconds = time.perf_counter() - started
            successful_latencies = sorted(row[1] for row in rows if row[0] == 200)
            rejected_latencies = sorted(row[1] for row in rows if row[0] == 429)
            successful = len(successful_latencies)
            output.append(
                {
                    "concurrent_users": users,
                    "success": successful,
                    "rejected_429": len(rejected_latencies),
                    "wall_seconds": round(wall_seconds, 3),
                    "completed_throughput_rps": round(successful / wall_seconds, 3),
                    "success_p50_ms": round(statistics.median(successful_latencies), 1),
                    "success_p95_ms": round(successful_latencies[max(0, math.ceil(successful * 0.95) - 1)], 1),
                    "rejected_p95_ms": (
                        round(rejected_latencies[max(0, math.ceil(len(rejected_latencies) * 0.95) - 1)], 1)
                        if rejected_latencies
                        else None
                    ),
                    "statuses": [row[0] for row in rows],
                }
            )
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
