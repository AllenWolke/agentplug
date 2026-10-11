"""Verify that chat saturation does not consume embedding/rerank queues."""

from __future__ import annotations

import asyncio
import json
import time

import httpx


async def timed_post(
    client: httpx.AsyncClient, url: str, payload: dict
) -> dict[str, float | int]:
    started = time.perf_counter()
    response = await client.post(url, json=payload)
    return {
        "status": response.status_code,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
    }


async def main() -> None:
    base_url = "http://127.0.0.1:18000/v1"
    chat_payload = {
        "model": "Qwen2.5-3B-Instruct",
        "messages": [
            {
                "role": "user",
                "content": "用一句话说明银行监管数据质量校验的目标。",
            }
        ],
        "temperature": 0,
        "max_tokens": 16,
    }
    embedding_payload = {
        "model": "BAAI/bge-small-zh-v1.5",
        "input": ["监管报送数据应满足完整性、准确性和一致性要求。"],
    }
    rerank_payload = {
        "model": "BAAI/bge-reranker-base",
        "query": "监管数据质量要求",
        "documents": ["报送数据应准确完整。", "今天天气晴朗。"],
        "top_n": 2,
    }
    async with httpx.AsyncClient(timeout=120, trust_env=False) as client:
        chat_tasks = [
            asyncio.create_task(
                timed_post(client, f"{base_url}/chat/completions", chat_payload)
            )
            for _ in range(9)
        ]
        await asyncio.sleep(0.1)
        embedding_task = asyncio.create_task(
            timed_post(client, f"{base_url}/embeddings", embedding_payload)
        )
        rerank_task = asyncio.create_task(
            timed_post(client, f"{base_url}/rerank", rerank_payload)
        )
        embedding, rerank = await asyncio.gather(embedding_task, rerank_task)
        chat = await asyncio.gather(*chat_tasks)
    print(
        json.dumps(
            {
                "chat": chat,
                "embedding_during_chat_saturation": embedding,
                "rerank_during_chat_saturation": rerank,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
