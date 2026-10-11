"""Local gateway fixtures verify safe CLI auth/refresh and unknown-command handling."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("dlq_cli", Path(__file__).parents[1] / "scripts/kafka_dead_letter.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def reply(self, code, body, cookie=None):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie + "; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(raw)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/auth/refresh":
            self.server.refreshes += 1
            self.reply(200, {"private": "SECRET_REFRESH"}, "session=renewed")
        else:
            self.server.commands += 1
            self.reply(503, {"private": "SECRET_ERROR_BODY"})
    def do_GET(self):
        if self.headers.get("Cookie") != "session=renewed":
            self.reply(401, {"private": "SECRET_AUTH_BODY"})
        else:
            self.reply(200, {"version": "kafka-dead-letter/v1", "items": [], "next": ""})


class DeadLetterCliTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        self.server.refreshes = self.server.commands = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = cli.Client("http://127.0.0.1:" + str(self.server.server_port), 2)
    def tearDown(self):
        self.client.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
    def test_access_expiration_refreshes_same_cookie_session(self):
        result = self.client.request("/api/modules/notification/dead-letters")
        self.assertEqual(result["items"], [])
        self.assertEqual(self.server.refreshes, 1)
        self.assertEqual(self.server.commands, 0)
    def test_server_failure_never_replays_uncertain_command(self):
        with self.assertRaisesRegex(cli.ClientError, "^HTTP_503$") as failure:
            self.client.request("/api/modules/notification/dead-letters/" + "a" * 64 + "/actions", {"idempotency_key": "stable"})
        self.assertNotIn("SECRET_", str(failure.exception))
        self.assertEqual(self.server.commands, 1)
        self.assertEqual(self.server.refreshes, 0)
    def test_credentials_origins_and_private_response_fields(self):
        for origin in ("http://external.example", "https://user:SECRET@example.com", "https://example.com/?token=SECRET"):
            with self.assertRaises(cli.ClientError):
                cli.gateway_origin(origin)
        public = cli.metadata({"version": "kafka-dead-letter/v1", "id": "a" * 64,
            "source": {"source_topic": "events", "password": "SECRET_SOURCE"}, "raw_value": "SECRET_BODY"})
        self.assertNotIn("SECRET_", json.dumps(public))


if __name__ == "__main__":
    unittest.main()
