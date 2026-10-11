// A result belongs to one popup, one origin and one operation. Proofs remain
// in memory only and are consumed immediately by the submitting component.
export function authenticateOIDC({ browser = window, begin, input, signal, timeoutMs = 300000 }) {
  const popup = browser.open("about:blank", "_blank", "popup,width=560,height=720");
  if (!popup) return Promise.reject(new Error("请允许弹出认证窗口，然后重试"));
  return new Promise((resolve, reject) => {
    let state = "", settled = false;
    let deadline, closed;
    const finish = (error, proof) => {
      if (settled) return;
      settled = true;
      browser.removeEventListener("message", receive);
      signal?.removeEventListener("abort", abort);
      clearTimeout(deadline); clearInterval(closed);
      try { popup.close(); } catch { /* The provider may have closed it. */ }
      if (error) reject(error); else resolve(proof);
    };
    const abort = () => finish(new Error("认证操作已取消，请重新预览"));
    const receive = event => {
      if (settled || !state || event.origin !== browser.location.origin || event.source !== popup || event.data?.type !== "agentplug.oidc.step-up" || event.data.state !== state) return;
      const data = event.data;
      if (data.error) return finish(new Error("再次认证失败，请重新办理"));
      if (!/^[A-Za-z0-9_-]{43}$/.test(data.step_up_token || "") || !Number.isFinite(Date.parse(data.expires_at)) || Date.parse(data.expires_at) <= Date.now() || Date.parse(data.expires_at) > Date.now() + 300000) return finish(new Error("认证凭证无效或已过期，请重新办理"));
      finish(null, { step_up_token: data.step_up_token, expires_at: data.expires_at });
    };
    browser.addEventListener("message", receive);
    signal?.addEventListener("abort", abort, { once: true });
    deadline = setTimeout(() => finish(new Error("认证窗口已超时，请重新办理")), timeoutMs);
    closed = setInterval(() => { if (popup.closed) finish(new Error("认证窗口已关闭")); }, 500);
    if (signal?.aborted) { abort(); return; }
    Promise.resolve().then(() => begin(input)).then(flow => {
      if (settled) return;
      const target = new URL(flow.authorization_url);
      if (target.protocol !== "https:" || target.username || target.password || !/^[A-Za-z0-9_-]{43}$/.test(flow.state || "")) throw new Error("认证地址无效");
      state = flow.state;
      popup.location.href = target.href;
    }).catch(error => finish(error));
  });
}
