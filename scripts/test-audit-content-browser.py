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
OWNER = "audit-content-browser-" + uuid.uuid4().hex
PROFILE = ROOT / ".tmp" / OWNER
ARTIFACT = ROOT / "artifacts" / "user-permissions-audit-content-browser-20261001.json"
state = {"mode": "metadata", "requests": []}


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def send(self, data, status=200):
        payload=json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.end_headers(); self.wfile.write(payload)
    def do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        if path.startswith(("/auth/","/api/")):
            state["requests"].append({"method":"GET","path":path})
            if path=="/auth/me": data={"username":"auditor","id":"auditor","display_name":"审计浏览器夹具","tenant_id":"t","department_id":"d","application_id":"a"}
            elif path.endswith("/identity/me/permissions"): data={"policy_mode":"v2","capabilities":["audit.metadata.read"],"scope":{"scope_type":"application","tenant_id":"t","department_id":"d","application_id":"a"}}
            elif path.endswith("/identity/me/workspaces"): data={"application_workspaces":[]}
            elif path.endswith("/audit/events"): data={"items":[{"id":"e","action":"run.complete","tenant_id":"t","department_id":"d","application_id":"a","aggregate_type":"agent_run","aggregate_id":"run"}],"total":1,"page":1}
            elif path.endswith("/events/e/permissions"): data={"event_id":"e","actions":{"audit.content.read":state["mode"] in ("content","export"),"audit.export":state["mode"]=="export"}}
            elif path.endswith("/events/e/content"):
                time.sleep(state.get("delay",0)); data={"id":"e","summary":"audit-private-browser-fixture"}
            else: self.send({"error":{"code":"UNEXPECTED_ROUTE"}},404); return
            self.send(data); return
        target=(ROOT/"frontend/dist"/path.lstrip("/")).resolve()
        dist=(ROOT/"frontend/dist").resolve()
        if not target.is_relative_to(dist) or not target.is_file(): target=dist/"index.html"
        self.send_response(200); self.send_header("Content-Type", "text/javascript" if target.suffix==".js" else "text/css" if target.suffix==".css" else "text/html"); self.end_headers(); self.wfile.write(target.read_bytes())
    def do_POST(self):
        payload=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
        state["requests"].append({"method":"POST","path":self.path,"body":payload})
        if self.path.endswith("/audit/exports") and state["mode"]=="export": self.send({"items":[{"id":"e","summary":"audit-private-browser-fixture"}],"total":1})
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
    chrome_log = (ROOT / "artifacts" / "user-permissions-audit-content-chrome-20261001.log").open("wb")
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

        downloads = PROFILE / "Downloads"
        downloads.mkdir()
        command("Browser.setDownloadBehavior", {"behavior": "allow", "downloadPath": str(downloads)})
        command("Runtime.enable", {})
        command("Page.navigate", {"url": f"http://127.0.0.1:{server.server_port}/audit"})
        expect("!!document.querySelector('#audit-filter')", "Built audit page loads with metadata authority")
        evaluate("document.querySelector('#audit-filter button').click()")
        expect("document.querySelectorAll('.audit-content-controls button:disabled').length===2", "Metadata authority does not enable content or export")
        state["mode"]="content"
        evaluate("window.dispatchEvent(new Event('focus'))")
        expect("document.querySelectorAll('.audit-content-controls button:disabled').length===1", "Content grant enables reading without export")
        evaluate("document.querySelector('.audit-content-controls button').click()")
        expect("document.body.innerText.includes('audit-private-browser-fixture')", "Explicit content action displays authorized summary")
        state["mode"]="export"
        evaluate("window.dispatchEvent(new Event('focus'))")
        expect("!document.body.innerText.includes('audit-private-browser-fixture') && document.querySelectorAll('.audit-content-controls button:disabled').length===0", "Focus clears old content and rechecks independent actions")
        evaluate("document.querySelectorAll('.audit-content-controls button')[1].click()")
        expect("document.querySelectorAll('.audit-content-controls button:disabled').length===0", "Explicit export finishes")
        assert any(r['method']=='POST' and r['path'].endswith('/audit/exports') and r['body']=={'event_ids':['e']} for r in state['requests'])
        result['checks'].append('Export calls the independently authorized endpoint with selected identifiers')
        download = downloads / 'audit-events.json'
        deadline = time.monotonic()+5
        while not download.exists():
            if time.monotonic()>deadline: raise AssertionError('Owned audit export was not downloaded')
            time.sleep(.1)
        assert json.loads(download.read_text(encoding='utf-8')) == {'items':[{'id':'e','summary':'audit-private-browser-fixture'}],'total':1}
        result['checks'].append('Downloaded export contains exactly the authorized fixture event')
        state["delay"]=.4
        evaluate("document.querySelector('.audit-content-controls button').click()")
        time.sleep(.1)
        state["mode"]="revoked"
        evaluate("window.dispatchEvent(new Event('focus'))")
        expect("document.querySelectorAll('.audit-content-controls button:disabled').length===2", "Revocation disables both independent actions")
        time.sleep(.6)
        expect("!document.body.innerText.includes('audit-private-browser-fixture')", "Late response cannot restore content after permission refresh")
        assert all(r['path'].endswith('/audit/exports') for r in state['requests'] if r['method']=='POST')
        result['checks'].append('Metadata selection and permission refresh produce no business mutation')
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
