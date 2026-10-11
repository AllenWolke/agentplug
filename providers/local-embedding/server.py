"""独立、限流的OpenAI兼容Embedding服务，仅平台持有其访问凭证。"""
from __future__ import annotations
import argparse
import hmac
import json
from pathlib import Path
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from engine import Engine, ModelSpec, verify_asset_manifest


class LimitedServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    # 此上限在接收socket前约束线程，避免ThreadingHTTPServer无界创建线程。
    request_queue_size = 8
    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(*args, **kwargs)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("models.lock.json"))
    parser.add_argument("--weights", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args()
    spec = ModelSpec.load(args.lock, args.model)
    verify_asset_manifest(args.weights, spec)
    secret = args.key_file.read_bytes().strip()
    if len(secret) < 32:
        raise ValueError("independent provider credential required")
    engine = Engine(spec, args.weights)
    inference = threading.BoundedSemaphore(1)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(120)
        def log_message(self, *_args):
            pass  # 不记录请求正文、URL查询、凭证或原始错误。
        def reply(self, status, value):
            body = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            if self.path == "/healthz":
                self.reply(200, {"status":"ready", "model":spec.id,"revision":spec.revision})
            else:
                self.reply(404,{"error":{"code":"NOT_FOUND"}})
        def do_POST(self):
            provided = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(provided, b"Bearer "+secret):
                self.reply(401,{"error":{"code":"UNAUTHORIZED"}})
                return
            if self.path != "/v1/embeddings":
                self.reply(404,{"error":{"code":"NOT_FOUND"}})
                return
            if not inference.acquire(blocking=False):
                self.reply(429,{"error":{"code":"MODEL_PROVIDER_NOT_SUBMITTED"}})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 1<<20 or self.headers.get("Transfer-Encoding"):
                    raise ValueError("REQUEST_LIMIT_EXCEEDED")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("INCOMPLETE_REQUEST")
                value = json.loads(body)
                if value.get("model") not in {spec.id, spec.repository}:
                    raise ValueError("MODEL_SELECTION_MISMATCH")
                texts = value["input"]
                if isinstance(texts,str): texts=[texts]
                if not isinstance(texts,list) or any(not isinstance(text,str) for text in texts):
                    raise ValueError("INVALID_INPUT")
                purpose = self.headers.get("X-Agentplug-Embedding-Purpose", "")
                vectors, usage = engine.embed(texts, purpose=purpose,
                                               dimensions=value.get("dimensions",1024))
                self.reply(200,{"object":"list", "model":value["model"],
                    "data":[{"object":"embedding","index":i,"embedding":vector}
                            for i,vector in enumerate(vectors)],"usage":usage})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                self.reply(400,{"error":{"code":"INVALID_OR_OVERSIZED_INPUT"}})
            except Exception:
                self.reply(503,{"error":{"code":"MODEL_PROVIDER_FAILURE"}})
            finally:
                inference.release()
    LimitedServer((args.host,args.port), Handler).serve_forever(poll_interval=.25)


if __name__ == "__main__": main()
