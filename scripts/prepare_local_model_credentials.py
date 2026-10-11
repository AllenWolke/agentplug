"""Prepare ignored, key-only mounts from operator-provided local credential files.

Never prints secrets and never changes the input files. This is local setup,
not a deployment secret manager or an alternative to model catalog approval.
"""
import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit


def read_bundle(path):
    raw = path.read_text(encoding="utf-8-sig").strip()
    if not raw or len(raw) > 16384:
        raise ValueError("missing or oversized credential file")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) == 1 and not any(c.isspace() for c in raw) and not raw.startswith("{") and ":" not in raw and "=" not in raw:
        return {"key": raw}
    try:
        data = json.loads(raw)
        pairs = list(data.items()) if isinstance(data, dict) else []
    except ValueError:
        pairs = []
        for line in lines:
            match = re.fullmatch(r"([^:=：]{1,60})\s*[:=：]\s*(.*)", line)
            if not match:
                raise ValueError("unrecognized credential configuration line")
            pairs.append((match.group(1).strip(), match.group(2).strip().strip("\"'")))
    result = {}
    for label, value in pairs:
        label = label.lower().strip().replace("-", "_").replace(" ", "_")
        field = "key" if label in {"api_key", "apikey", "key", "密钥"} else "model" if label in {"model", "model_name", "模型", "模型名", "模型名称"} else "base_url" if label in {"base_url", "url", "endpoint", "api_url", "api_base_url", "调用路径", "调用地址", "接口地址"} else None
        if field is None or field in result or not isinstance(value, str) or not value:
            raise ValueError("unknown, duplicate or invalid credential field")
        result[field] = value
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--embedding-model", required=True)
    parser.add_argument("--embedding-base-url", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / ".local-secrets" / "model-providers"
    destination = root / "runtime-mounts"
    if root.is_symlink() or destination.is_symlink():
        raise ValueError("credential directories must not be links")
    configuration = {}
    mounts = {}
    for provider, filename in (("embedding", "embedding.key"), ("llm", "deepseek.key")):
        source = root / filename
        if source.is_symlink() or not source.is_file():
            raise ValueError("credential input must be a regular file")
        bundle = read_bundle(source)
        key = bundle.get("key", "")
        if not key or len(key) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ValueError("credential must be one nonempty ASCII token")
        model = bundle.get("model", args.embedding_model if provider == "embedding" else "")
        endpoint = bundle.get("base_url", args.embedding_base_url if provider == "embedding" else "")
        url = urlsplit(endpoint)
        if not re.fullmatch(r"[A-Za-z0-9_./:-]{1,150}", model) or url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("model and clean HTTPS base URL are required")
        configuration[provider] = {"model": model, "base_url": endpoint, "key_file": filename}
        mounts[filename] = key
    # Windows mkdir(0700) on recent Python versions can deny the operator's
    # Go process when preparation runs under the workspace sandbox identity.
    # Inherit the operator-provided secret directory ACL on Windows instead.
    destination.mkdir(mode=0o777 if os.name == "nt" else 0o700, parents=True, exist_ok=True)
    for filename, key in mounts.items():
        output = destination / filename
        if output.is_symlink():
            raise ValueError("credential destination must not be a link")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(key + "\n")
    (destination / "providers.json").write_text(json.dumps(configuration, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"prepared": True, "metadata": configuration, "input_files_unchanged": True}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        raise SystemExit("Local credential preparation failed; inspect file format without exposing secret values")
