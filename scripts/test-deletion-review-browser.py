"""Run the built UI in Chrome against an isolated, explicit HTTP fixture.

This verifies rendering and permission refresh, not production authentication.
Only a loopback fixture server is used; no original service/database is touched.
"""
import http.server
import json
import pathlib
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid

import websocket

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHROME = pathlib.Path("C:/Program Files/Google/Chrome/Application/chrome.exe")
OWNER = "deletion-review-browser-" + uuid.uuid4().hex
PROFILE = ROOT / ".tmp" / OWNER
ARTIFACT = ROOT / "artifacts" / "user-permissions-deletion-review-browser-20261001.json"
state = {"mode": "qualified", "requests": [], "approved": False}


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def send(self, data, status=200):
        payload=json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.end_headers(); self.wfile.write(payload)
    def do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        if path.startswith(("/auth/","/api/")):
            state["requests"].append({"method":"GET","path":path})
            if path=="/auth/me": data={"username":"reviewer","id":"reviewer","display_name":"审批浏览器夹具","tenant_id":"t","department_id":"d","application_id":"a"}
            elif path.endswith("/identity/me/permissions"): data={"policy_mode":"v2","capabilities":[],"data_capabilities":["business.review"] if state["mode"]=="qualified" else [],"scope":{"scope_type":"application","tenant_id":"t","department_id":"d","application_id":"a"}}
            elif path.endswith("/identity/me/workspaces"): data={"application_workspaces":[]}
            elif path.endswith("/conversation/deletion-requests"):
                data={"items":[{"id":"request","session_id":"session","owner_id":"owner","status":"pending","reason":"deletion-private-browser-fixture"}] if state["mode"]=="qualified" and not state["approved"] else [],"total":1}
                time.sleep(state.get("delay",0))
            else: self.send({"error":{"code":"UNEXPECTED_ROUTE"}},404); return
            self.send(data); return
        target=(ROOT/"frontend/dist"/path.lstrip("/")).resolve()
        dist=(ROOT/"frontend/dist").resolve()
        if not target.is_relative_to(dist) or not target.is_file(): target=dist/"index.html"
        self.send_response(200); self.send_header("Content-Type", "text/javascript" if target.suffix==".js" else "text/css" if target.suffix==".css" else "text/html"); self.end_headers(); self.wfile.write(target.read_bytes())
    def do_POST(self):
        payload=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
        state["requests"].append({"method":"POST","path":self.path,"body":payload})
        if self.path.endswith("/deletion-requests/request/approve") and state["mode"]=="qualified":
            state["approved"]=True; self.send({"id":"request","status":"approved"})
        else: self.send({"error":{"code":"FORBIDDEN"}},403)


def main():
    if not CHROME.is_file():
        raise RuntimeError("Installed Chrome required for this browser test")
    if PROFILE.parent.is_symlink() or not PROFILE.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Unsafe profile directory")
    PROFILE.mkdir(parents=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    process = connection = None
    chrome_log = (ROOT / "artifacts" / "user-permissions-deletion-review-chrome-20261001.log").open("wb")
    result = {"passed": False, "fixture_only": True, "owner": OWNER, "checks": []}
    try:
        process = subprocess.Popen([str(CHROME), "--headless=new", "--disable-gpu", "--renderer-process-limit=1", "--js-flags=--single-threaded", "--disable-extensions", "--disable-background-networking", "--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0", "--user-data-dir=" + str(PROFILE), "about:blank"], stdout=subprocess.DEVNULL, stderr=chrome_log, creationflags=subprocess.CREATE_NO_WINDOW)
        deadline = time.monotonic() + 30
        active = PROFILE / "DevToolsActivePort"
        while not active.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("Chrome did not start its owned debugging endpoint")
            time.sleep(.1)
        port = active.read_text().splitlines()[0]
        targets = json.load(urllib.request.urlopen("http://127.0.0.1:" + port + "/json/list", timeout=5))
        connection = websocket.create_connection(next(target["webSocketDebuggerUrl"] for target in targets if target["type"] == "page"), timeout=10, suppress_origin=True)
        serial = 0

        def command(method, params):
            nonlocal serial
            serial += 1
            connection.send(json.dumps({"id": serial, "method": method, "params": params}))
            while True:
                response = json.loads(connection.recv())
                if response.get("method") == "Runtime.exceptionThrown":
                    result.setdefault("browser_errors", []).append(response.get("params", {}))
                if response.get("id") == serial:
                    if "error" in response:
                        raise RuntimeError(response["error"])
                    return response.get("result", {})

        def evaluate(expression):
            response = command("Runtime.evaluate", {"expression": expression, "returnByValue": True})
            if "exceptionDetails" in response:
                raise RuntimeError(response["exceptionDetails"])
            return response.get("result", {}).get("value")

        def expect(expression, label):
            deadline = time.monotonic() + 15
            while not evaluate(expression):
                if time.monotonic() > deadline:
                    raise AssertionError(label + ": " + str(evaluate("document.body.innerText")))
                time.sleep(.1)
            result["checks"].append(label)

        command("Runtime.enable", {})
        command("Page.navigate", {"url": f"http://127.0.0.1:{server.server_port}/admin/conversation-governance"})
        expect("!!document.querySelector('[data-testid=deletion-review]')", "Qualified v2 reviewer opens the governance entry without an admin role")
        expect("document.body.innerText.includes('deletion-private-browser-fixture')", "Actual pending/owner/session contract renders an authorized request")
        evaluate("Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='批准删除申请').click()")
        expect("document.body.innerText.includes('会话已从普通历史入口隐藏')", "Explicit approval reports the implemented disposal state")
        assert len([r for r in state['requests'] if r['method']=='POST'])==1
        assert state['requests'][-1]['method']=='GET' or state['approved']
        result['checks'].append('Approval sends one mutation after permission and list preflight')
        state['approved']=False
        evaluate("window.dispatchEvent(new Event('focus'))")
        expect("document.body.innerText.includes('deletion-private-browser-fixture')", "Focus reloads current authorized scope")
        state['delay']=.5
        evaluate("window.dispatchEvent(new Event('focus'))")
        time.sleep(.1)
        state['mode']='revoked'
        evaluate("window.dispatchEvent(new Event('focus'))")
        expect("!document.querySelector('[data-testid=deletion-review]')", "Revocation removes the page and its controls")
        time.sleep(.7)
        expect("!document.body.innerText.includes('deletion-private-browser-fixture')", "Late list response cannot restore revoked request content")
        expect("!Array.from(document.querySelectorAll('a')).some(a=>a.textContent.includes('会话治理'))", "Revocation removes the navigation entry")
        assert len([r for r in state['requests'] if r['method']=='POST'])==1
        result['checks'].append('Permission refresh produces no business mutation')
        result["passed"] = True
    finally:
        if connection:
            connection.close()
        if process:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        server.shutdown()
        server.server_close()
        chrome_log.close()
        size = sum(path.stat().st_size for path in PROFILE.rglob("*") if path.is_file())
        if PROFILE.is_symlink() or PROFILE.is_junction() or any(path.is_symlink() or path.is_junction() for path in PROFILE.rglob("*")):
            raise RuntimeError("Profile cleanup encountered a link")
        shutil.rmtree(PROFILE)
        result.update({"requests": state["requests"], "deleted_profile_bytes": size, "profile_remaining": PROFILE.exists(), "process_stopped": process is None or process.poll() is not None})
        ARTIFACT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"passed": result["passed"], "checks": result["checks"], "deleted_profile_bytes": result["deleted_profile_bytes"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
