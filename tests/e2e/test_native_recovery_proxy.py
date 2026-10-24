import http.client
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("native_recovery_proxy", Path(__file__).with_name("native_recovery_proxy.py"))
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


@pytest.fixture
def fixture(tmp_path):
    calls = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append((self.path, raw, self.headers.get("X-Context-Signature")))
            if self.path == "/internal/tool/receipt":
                data = {"version": "tool-receipt/v1", "status": "completed", "call_id": "original"}
            else:
                data = {"data": {"message_id": "agent-tool-original"}}
            body = json.dumps({"data": data}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    directory = tmp_path / "go"; directory.mkdir()
    (directory / "active.json").write_text(json.dumps({"run_id": "owned-new-run"}))
    (directory.parent / "budget.json").write_text(json.dumps({"limit": 5, "reserved_upper_bound": 0, "reservations": []}))
    (directory / "drop").touch(); (directory / "abort").touch()
    gate = proxy.server(directory, port=0, upstream_host="127.0.0.1", upstream_port=upstream.server_port)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (upstream, gate)]
    for thread in threads: thread.start()
    yield gate, calls, directory
    for s in (gate, upstream): s.shutdown(); s.server_close()
    for thread in threads: thread.join(timeout=2)


def request(gate, path, run="owned-new-run", payload=None):
    raw = json.dumps({"context": {"task_id": run}, "input": {"name": "notify.self", "call_id": "original", "payload": payload or {"text": "fixed"}}}).encode()
    client = http.client.HTTPConnection("127.0.0.1", gate.server_port, timeout=2)
    try:
        client.request("POST", path, raw, {"X-Context-Signature": "opaque-test-signature"})
        response = client.getresponse()
        return response.status, response.read(), raw
    finally: client.close()


def test_real_response_loss_queries_original_and_never_forwards_again(fixture):
    gate, calls, directory = fixture
    with pytest.raises(http.client.RemoteDisconnected): request(gate, "/internal/tool/invoke")
    status, _, raw = request(gate, "/internal/tool/receipt")
    assert status == 200 and calls[-1] == ("/internal/tool/receipt", raw, "opaque-test-signature")
    assert request(gate, "/internal/tool/invoke")[0] == 503
    assert request(gate, "/internal/model/generate")[0] == 503
    assert [c[0] for c in calls] == ["/internal/tool/invoke", "/internal/tool/receipt"]
    events = (directory / "events.jsonl").read_text()
    assert "original_receipt_returned" in events and "opaque-test-signature" not in events and '"text"' not in events


def test_changed_operation_is_not_a_recovery_success(fixture):
    gate, _, directory = fixture
    with pytest.raises(http.client.RemoteDisconnected): request(gate, "/internal/tool/invoke")
    assert request(gate, "/internal/tool/receipt", payload={"text": "changed"})[0] == 503
    assert not gate.gate.recovered


def test_other_runs_are_transparent_and_not_in_fault_journal(fixture):
    gate, calls, directory = fixture
    status, _, raw = request(gate, "/internal/tool/invoke", run="unrelated")
    assert status == 200 and calls == [("/internal/tool/invoke", raw, "opaque-test-signature")]
    assert not (directory / "events.jsonl").exists()


def test_budget_exhaustion_precedes_any_upstream_send(fixture):
    gate, calls, _ = fixture
    assert request(gate, "/internal/knowledge/search")[0] == 200
    assert request(gate, "/internal/model/generate")[0] == 200
    assert request(gate, "/internal/model/generate")[0] == 503
    assert len(calls) == 2
