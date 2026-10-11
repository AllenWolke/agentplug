"""发布验证专用的本地 OpenAI 兼容推理服务。"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from transformers import (
    AutoModel,
    AutoModelForCausalLM,
    AutoModelForSequenceClassification,
    AutoTokenizer,
)


MODEL_PATH = Path(
    os.getenv("LOCAL_MODEL_PATH", "tmp/models/Qwen2.5-0.5B-Instruct")
).resolve()
MODEL_NAME = os.getenv("LOCAL_MODEL_NAME", MODEL_PATH.name)
EMBEDDING_MODEL_PATH = Path(
    os.getenv("LOCAL_EMBEDDING_MODEL_PATH", "tmp/models/bge-small-zh-v1.5")
).resolve()
EMBEDDING_MODEL_NAME = os.getenv(
    "LOCAL_EMBEDDING_MODEL_NAME", EMBEDDING_MODEL_PATH.name
)
RERANK_MODEL_PATH = Path(
    os.getenv("LOCAL_RERANK_MODEL_PATH", "tmp/models/bge-reranker-base")
).resolve()
RERANK_MODEL_NAME = os.getenv("LOCAL_RERANK_MODEL_NAME", RERANK_MODEL_PATH.name)
MAX_NEW_TOKENS = int(os.getenv("LOCAL_MODEL_MAX_NEW_TOKENS", "512"))
MAX_INPUT_TOKENS = int(os.getenv("LOCAL_MODEL_MAX_INPUT_TOKENS", "8192"))
EMBEDDING_MAX_INPUT_TOKENS = int(
    os.getenv("LOCAL_EMBEDDING_MAX_INPUT_TOKENS", "512")
)
RERANK_MAX_INPUT_TOKENS = int(os.getenv("LOCAL_RERANK_MAX_INPUT_TOKENS", "512"))
CHAT_CONCURRENCY = int(os.getenv("LOCAL_CHAT_CONCURRENCY", "1"))
EMBEDDING_CONCURRENCY = int(os.getenv("LOCAL_EMBEDDING_CONCURRENCY", "1"))
RERANK_CONCURRENCY = int(os.getenv("LOCAL_RERANK_CONCURRENCY", "1"))
ROUTE_QUEUE_SIZE = int(os.getenv("LOCAL_MODEL_QUEUE_SIZE", "8"))
CHAT_QUEUE_SIZE = int(os.getenv("LOCAL_CHAT_QUEUE_SIZE", str(ROUTE_QUEUE_SIZE)))
EMBEDDING_QUEUE_SIZE = int(os.getenv("LOCAL_EMBEDDING_QUEUE_SIZE", str(ROUTE_QUEUE_SIZE)))
RERANK_QUEUE_SIZE = int(os.getenv("LOCAL_RERANK_QUEUE_SIZE", str(ROUTE_QUEUE_SIZE)))
QUEUE_WAIT_SECONDS = float(os.getenv("LOCAL_MODEL_QUEUE_WAIT_SECONDS", "300"))


class ChatRequest(BaseModel):
    model: str = ""
    messages: list[dict[str, Any]] = Field(min_length=1)
    temperature: float = 0.3
    max_tokens: int = 512
    stream: bool = False


class EmbeddingRequest(BaseModel):
    model: str = ""
    input: str | list[str]


class RerankRequest(BaseModel):
    model: str = ""
    query: str = Field(min_length=1)
    documents: list[str] = Field(min_length=1)
    top_n: int | None = Field(default=None, gt=0)


class Runtime:
    chat_tokenizer: Any = None
    chat_model: Any = None
    embedding_tokenizer: Any = None
    embedding_model: Any = None
    rerank_tokenizer: Any = None
    rerank_model: Any = None
    routes: dict[str, "AdmissionController"] = {}


class AdmissionController:
    """Bounded per-model admission with observable queue state."""

    def __init__(self, concurrency: int, queue_size: int):
        if concurrency < 1 or queue_size < 0:
            raise ValueError("invalid model route capacity")
        self.concurrency = concurrency
        self.queue_size = queue_size
        self.semaphore = asyncio.Semaphore(concurrency)
        self.lock = asyncio.Lock()
        self.admitted = 0

    async def enter(self) -> None:
        async with self.lock:
            if self.admitted >= self.concurrency + self.queue_size:
                raise HTTPException(status_code=429, detail="model route queue is full")
            self.admitted += 1
        try:
            await asyncio.wait_for(
                self.semaphore.acquire(), timeout=QUEUE_WAIT_SECONDS
            )
        except TimeoutError:
            async with self.lock:
                self.admitted -= 1
            raise HTTPException(status_code=504, detail="model route queue timeout") from None
        except asyncio.CancelledError:
            # 等待者取消时归还排队计数，不能永久占用等待位。
            async with self.lock:
                self.admitted -= 1
            raise

    async def leave(self) -> None:
        self.semaphore.release()
        async with self.lock:
            self.admitted -= 1

    def snapshot(self) -> dict[str, int]:
        running = self.concurrency - self.semaphore._value
        return {
            "concurrency": self.concurrency,
            "queue_size": self.queue_size,
            "running": running,
            "queued": max(0, self.admitted - running),
        }


runtime = Runtime()


@asynccontextmanager
async def lifespan(_: FastAPI):
    required_paths = (MODEL_PATH, EMBEDDING_MODEL_PATH, RERANK_MODEL_PATH)
    missing = [str(path) for path in required_paths if not path.is_dir()]
    if missing:
        raise RuntimeError("model directories do not exist: " + ", ".join(missing))
    torch.set_num_threads(max(1, int(os.getenv("LOCAL_MODEL_CPU_THREADS", "8"))))
    runtime.chat_tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    runtime.chat_model = AutoModelForCausalLM.from_pretrained(MODEL_PATH, dtype="auto")
    runtime.chat_model.eval()
    runtime.embedding_tokenizer = AutoTokenizer.from_pretrained(EMBEDDING_MODEL_PATH)
    runtime.embedding_model = AutoModel.from_pretrained(EMBEDDING_MODEL_PATH)
    runtime.embedding_model.eval()
    runtime.rerank_tokenizer = AutoTokenizer.from_pretrained(RERANK_MODEL_PATH)
    runtime.rerank_model = AutoModelForSequenceClassification.from_pretrained(
        RERANK_MODEL_PATH
    )
    runtime.rerank_model.eval()
    runtime.routes = {
        "chat": AdmissionController(CHAT_CONCURRENCY, CHAT_QUEUE_SIZE),
        "embedding": AdmissionController(EMBEDDING_CONCURRENCY, EMBEDDING_QUEUE_SIZE),
        "rerank": AdmissionController(RERANK_CONCURRENCY, RERANK_QUEUE_SIZE),
    }
    yield


app = FastAPI(title="local-release-validation-model", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "chat_model": MODEL_NAME,
        "embedding_model": EMBEDDING_MODEL_NAME,
        "rerank_model": RERANK_MODEL_NAME,
        "backend": "transformers-cpu",
        "routes": {name: route.snapshot() for name, route in runtime.routes.items()},
    }


async def _run_inference(route_name: str, function: Any, argument: Any) -> dict[str, Any]:
    """客户端取消后仍持有槽位，直到不可取消的 CPU 推理线程真正结束。"""
    route = runtime.routes[route_name]
    await route.enter()
    try:
        task = asyncio.create_task(asyncio.to_thread(function, argument))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise
    finally:
        await route.leave()


def _generate(request: ChatRequest) -> dict[str, Any]:
    prompt = runtime.chat_tokenizer.apply_chat_template(
        request.messages, tokenize=False, add_generation_prompt=True
    )
    encoded = runtime.chat_tokenizer(
        prompt,
        return_tensors="pt",
        truncation=True,
        max_length=MAX_INPUT_TOKENS,
    )
    prompt_tokens = int(encoded["input_ids"].shape[1])
    max_new_tokens = min(max(1, request.max_tokens), MAX_NEW_TOKENS)
    sampling = request.temperature > 0
    generation_args: dict[str, Any] = {
        "max_new_tokens": max_new_tokens,
        "do_sample": sampling,
        "pad_token_id": runtime.chat_tokenizer.eos_token_id,
    }
    if sampling:
        generation_args["temperature"] = max(request.temperature, 0.01)
    with torch.inference_mode():
        output = runtime.chat_model.generate(**encoded, **generation_args)
    generated = output[0, prompt_tokens:]
    text = runtime.chat_tokenizer.decode(generated, skip_special_tokens=True).strip()
    completion_tokens = int(generated.shape[0])
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": MODEL_NAME,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": (
                    "length" if completion_tokens >= max_new_tokens else "stop"
                ),
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest) -> dict[str, Any]:
    if request.stream:
        raise HTTPException(status_code=400, detail="streaming is not enabled")
    if request.model and request.model != MODEL_NAME:
        raise HTTPException(status_code=404, detail="chat model is not loaded")
    return await _run_inference("chat", _generate, request)


def _embed(texts: list[str]) -> dict[str, Any]:
    encoded = runtime.embedding_tokenizer(
        texts,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=EMBEDDING_MAX_INPUT_TOKENS,
    )
    with torch.inference_mode():
        result = runtime.embedding_model(**encoded, return_dict=True)
    # BGE 官方模型卡使用 CLS 向量，并在相似度计算前执行 L2 归一化。
    pooled = result.last_hidden_state[:, 0]
    pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
    vectors = pooled.cpu().float().tolist()
    prompt_tokens = int(encoded["attention_mask"].sum().item())
    return {
        "object": "list",
        "model": EMBEDDING_MODEL_NAME,
        "data": [
            {"object": "embedding", "embedding": vector, "index": index}
            for index, vector in enumerate(vectors)
        ],
        "usage": {"prompt_tokens": prompt_tokens, "total_tokens": prompt_tokens},
    }


@app.post("/v1/embeddings")
async def embeddings(request: EmbeddingRequest) -> dict[str, Any]:
    if request.model and request.model != EMBEDDING_MODEL_NAME:
        raise HTTPException(status_code=404, detail="embedding model is not loaded")
    texts = [request.input] if isinstance(request.input, str) else request.input
    if not texts or any(not isinstance(text, str) or not text.strip() for text in texts):
        raise HTTPException(status_code=400, detail="input must contain text")
    return await _run_inference("embedding", _embed, texts)


def _rerank(request: RerankRequest) -> dict[str, Any]:
    pairs = [[request.query, document] for document in request.documents]
    encoded = runtime.rerank_tokenizer(
        pairs,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=RERANK_MAX_INPUT_TOKENS,
    )
    with torch.inference_mode():
        logits = runtime.rerank_model(**encoded, return_dict=True).logits
    scores = torch.sigmoid(logits.reshape(-1)).cpu().float().tolist()
    ranked = sorted(enumerate(scores), key=lambda item: item[1], reverse=True)
    if request.top_n is not None:
        ranked = ranked[: min(request.top_n, len(ranked))]
    return {
        "id": f"rerank-{uuid.uuid4().hex}",
        "model": RERANK_MODEL_NAME,
        "results": [
            {"index": index, "relevance_score": score}
            for index, score in ranked
        ],
        "usage": {"total_tokens": int(encoded["attention_mask"].sum().item())},
    }


@app.post("/v1/rerank")
async def rerank(request: RerankRequest) -> dict[str, Any]:
    if request.model and request.model != RERANK_MODEL_NAME:
        raise HTTPException(status_code=404, detail="rerank model is not loaded")
    if any(not document.strip() for document in request.documents):
        raise HTTPException(status_code=400, detail="documents must contain text")
    return await _run_inference("rerank", _rerank, request)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("LOCAL_MODEL_HOST", "127.0.0.1"),
        port=int(os.getenv("LOCAL_MODEL_PORT", "18000")),
        log_level=os.getenv("LOCAL_MODEL_LOG_LEVEL", "info"),
    )
