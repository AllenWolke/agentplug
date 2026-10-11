// Common browser transport; business scenarios live in separate test suites.
export class CDP {
  constructor(url, timeout = 12000) {
    this.timeout = timeout;
    this.ws = new WebSocket(url);
    this.id = 0;
    this.pending = new Map();
    this.ready = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("DevTools connection timed out"));
        this.ws.close();
      }, timeout);
      this.ws.onopen = () => { clearTimeout(timer); resolve(); };
      this.ws.onerror = () => { clearTimeout(timer); reject(new Error("DevTools connection failed")); };
      this.ws.onclose = () => {
        clearTimeout(timer);
        reject(new Error("DevTools connection closed"));
        this.rejectPending();
      };
    });
    this.ws.onmessage = (event) => {
      let message;
      try { message = JSON.parse(event.data); }
      catch { this.close(); return; }
      const waiter = this.pending.get(message.id);
      if (!waiter) return;
      this.pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error("DevTools command failed"));
      else waiter.resolve(message.result);
    };
  }

  rejectPending() {
    for (const waiter of this.pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error("DevTools connection closed"));
    }
    this.pending.clear();
  }

  async call(method, params = {}) {
    await this.ready;
    if (this.ws.readyState !== WebSocket.OPEN) throw new Error("DevTools connection unavailable");
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("DevTools command timed out"));
      }, this.timeout);
      this.pending.set(id, { resolve, reject, timer });
      try { this.ws.send(JSON.stringify({ id, method, params })); }
      catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error("DevTools command could not be sent"));
      }
    });
  }

  async value(expression, awaitPromise = false) {
    const result = await this.call("Runtime.evaluate", { expression, awaitPromise, returnByValue: true });
    if (result.exceptionDetails) throw new Error("Browser evaluation failed");
    return result.result.value;
  }

  close() { this.rejectPending(); this.ws.close(); }
}

export async function waitValue(cdp, expression, timeout = 12000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await cdp.value(expression)) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return false;
}
