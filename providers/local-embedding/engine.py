"""独立CPU模型Provider；不持有平台数据库连接或业务Agent凭证。"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import math
import os
import time
from typing import Any

QUERY_INSTRUCTION = "Given a financial regulatory question, retrieve relevant passages that answer the question"


@dataclass(frozen=True)
class ModelSpec:
    id: str
    repository: str
    revision: str
    max_input_tokens: int
    dimensions: int
    pooling: str

    @classmethod
    def load(cls, lock_path: Path, label: str) -> "ModelSpec":
        document = json.loads(lock_path.read_text(encoding="utf-8"))
        if document.get("version") != "local-embedding-model-lock/v1":
            raise ValueError("unsupported model lock")
        matches = [row for row in document["models"] if row["id"] == label]
        if len(matches) != 1:
            raise ValueError("locked model not found")
        row = matches[0]
        if len(row["revision"]) != 40 or any(c not in "0123456789abcdef" for c in row["revision"]):
            raise ValueError("commit revision required")
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


def encoding_text(spec: ModelSpec, text: str, purpose: str) -> str:
    if purpose not in {"query", "document"} or not isinstance(text, str) or not text.strip():
        raise ValueError("explicit encoding purpose and nonempty text required")
    if spec.id == "e5-large":
        return ("query: " if purpose == "query" else "passage: ") + text
    if spec.id == "qwen3-0.6b" and purpose == "query":
        return f"Instruct: {QUERY_INSTRUCTION}\nQuery:{text}"
    return text


class Tokenizer:
    """真实本地Tokenizer，完整前缀/特殊Token纳入长度，不静默截断。"""

    def __init__(self, spec: ModelSpec, directory: Path):
        from transformers import AutoTokenizer
        self.spec = spec
        self.directory = directory
        self.tokenizer = AutoTokenizer.from_pretrained(str(directory), local_files_only=True,
                                                       trust_remote_code=False, use_fast=True)
        if not self.tokenizer.is_fast:
            raise ValueError("offset-capable fast tokenizer required")
        self.tokenizer.padding_side = "left" if spec.pooling == "last" else "right"

    def count(self, text: str, purpose: str = "document") -> int:
        encoded = self.tokenizer(encoding_text(self.spec, text, purpose), truncation=False,
                                 add_special_tokens=True, return_attention_mask=False)
        return len(encoded["input_ids"])

    def offsets(self, text: str) -> list[tuple[int, int]]:
        values = self.tokenizer(text, truncation=False, add_special_tokens=False,
                                return_offsets_mapping=True)["offset_mapping"]
        return [(start, end) for start, end in values if end > start]


class Engine:
    def __init__(self, spec: ModelSpec, directory: Path, *, cpu_threads: int = 4):
        import torch
        from transformers import AutoModel
        if not 1 <= cpu_threads <= 4:
            raise ValueError("CPU threads must be 1..4")
        torch.set_num_threads(cpu_threads)
        torch.set_num_interop_threads(1)
        self.spec = spec
        self.codec = Tokenizer(spec, directory)
        started = time.perf_counter()
        self.model = AutoModel.from_pretrained(str(directory), local_files_only=True,
                                              trust_remote_code=False, dtype=torch.float32,
                                              attn_implementation="sdpa", weights_only=True)
        self.model.to("cpu").eval()
        self.load_ms = (time.perf_counter() - started) * 1000
        if int(self.model.config.hidden_size) != spec.dimensions:
            raise ValueError("locked dimension differs from actual model")

    def embed(self, texts: list[str], *, purpose: str, dimensions: int = 1024,
              batch_size: int = 16, maximum_batch_tokens: int = 16384) -> tuple[list[list[float]], dict[str, Any]]:
        import torch
        import torch.nn.functional as F
        if not texts or len(texts) > 128 or not 1 <= batch_size <= 32:
            raise ValueError("bounded input and batch required")
        if dimensions != 1024 and not (self.spec.id == "qwen3-0.6b" and dimensions in {256, 512}):
            raise ValueError("MRL reduction is supported only in separate Qwen experiments")
        prepared = [encoding_text(self.spec, text, purpose) for text in texts]
        raw = self.codec.tokenizer(prepared, truncation=False, add_special_tokens=True,
                                   return_attention_mask=True)
        lengths = [len(ids) for ids in raw["input_ids"]]
        if any(count > self.spec.max_input_tokens for count in lengths):
            raise ValueError("INPUT_TOKEN_LIMIT_EXCEEDED")
        vectors: list[list[float]] = []
        offset, padded_tokens = 0, 0
        started, cpu = time.perf_counter(), time.process_time()
        with torch.inference_mode():
            while offset < len(texts):
                end = offset
                while end < len(texts) and end - offset < batch_size:
                    maximum = max(lengths[offset:end+1])
                    if maximum * (end-offset+1) > maximum_batch_tokens:
                        break
                    end += 1
                if end == offset:
                    raise ValueError("BATCH_TOKEN_LIMIT_EXCEEDED")
                encoded = self.codec.tokenizer.pad(
                    {key: value[offset:end] for key, value in raw.items()},
                    padding=True, return_tensors="pt")
                padded_tokens += int(encoded["input_ids"].numel())
                hidden = self.model(**encoded).last_hidden_state
                mask = encoded["attention_mask"]
                if self.spec.pooling == "cls":
                    pooled = hidden[:, 0]
                elif self.spec.pooling == "mean":
                    weighted = hidden.masked_fill(~mask.bool().unsqueeze(-1), 0)
                    pooled = weighted.sum(dim=1) / mask.sum(dim=1).unsqueeze(-1)
                elif self.spec.pooling == "last":
                    positions = torch.arange(mask.shape[1]).expand_as(mask)
                    last = positions.masked_fill(~mask.bool(), -1).max(dim=1).values
                    pooled = hidden[torch.arange(hidden.shape[0]), last]
                else:
                    raise ValueError("unknown locked pooling")
                pooled = F.normalize(pooled[:, :dimensions].float(), p=2, dim=1)
                if not torch.isfinite(pooled).all() or torch.any(pooled.norm(dim=1) < .99):
                    raise ValueError("nonfinite or zero vector")
                vectors.extend(pooled.cpu().tolist())
                offset = end
        usage = {"prompt_tokens": sum(lengths), "total_tokens": sum(lengths),
                 "padding_tokens": padded_tokens-sum(lengths),
                 "silent_truncations": 0, "input_purpose": purpose,
                 "model_revision": self.spec.revision, "dimensions": dimensions,
                 "wall_ms": (time.perf_counter()-started)*1000,
                 "process_cpu_ms": (time.process_time()-cpu)*1000,
                 "dtype": "float32", "device": "cpu"}
        return vectors, usage


def verify_asset_manifest(directory: Path, spec: ModelSpec) -> None:
    document = json.loads((directory / "asset-manifest.json").read_text(encoding="utf-8"))
    if document["repository"] != spec.repository or document["revision"] != spec.revision:
        raise ValueError("model asset provenance mismatch")
    for row in document["files"]:
        path = (directory / row["path"]).resolve()
        if not path.is_relative_to(directory.resolve()) or not path.is_file():
            raise ValueError("invalid model asset path")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1<<20), b""):
                digest.update(block)
        if digest.hexdigest() != row["sha256"] or path.stat().st_size != row["bytes"]:
            raise ValueError("model asset digest mismatch")
