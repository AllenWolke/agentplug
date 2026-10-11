import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { authenticateOIDC } from "./oidc-step-up.js";

export function FreshAuthentication({ action, requestDigest, onProof, onBusy }) {
  useLanguage();
  const [method, setMethod] = useState(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const controller = useRef(null);
  useEffect(() => {
    let active = true;
    setMethod(null); setPassword(""); setError("");
    api.identityStepUpMethod().then(value => { if (active) setMethod(value); })
      .catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; controller.current?.abort(); };
  }, [action, requestDigest]);
  const submit = async event => {
    event.preventDefault();
    if (busy || !method?.available) return;
    const attempt = new AbortController(); controller.current = attempt;
    setBusy(true); onBusy?.(true); setError("");
    const currentPassword = password; setPassword("");
    try {
      const input = { action, request_digest: requestDigest };
      const proof = method.method === "oidc"
        ? await authenticateOIDC({ begin: api.beginOIDCStepUp, input, signal: attempt.signal })
        : await api.identityStepUp({ ...input, current_password: currentPassword });
      if (!attempt.signal.aborted) await onProof(proof);
    } catch (cause) { if (!attempt.signal.aborted) setError(cause.message); }
    finally { if (!attempt.signal.aborted) { setBusy(false); onBusy?.(false); } }
  };
  return <Localized><form onSubmit={submit} aria-label="再次认证与提交">
    {error && <p className="form-error" role="alert">{error}</p>}
    {!method ? <p>正在读取再次认证方式…</p> : !method.available ? <p role="alert">当前身份提供方尚未配置再次认证，请联系平台管理员。</p> : method.method === "oidc"
      ? <p>将在身份提供方窗口验证当前账号，成功后提交本次已预览的变更。</p>
      : <label>请再次输入当前账号密码<input type="password" autoComplete="current-password" value={password} required disabled={busy} onChange={event => setPassword(event.target.value)}/></label>}
    <button className="button primary" disabled={busy || !method?.available || (method.method !== "oidc" && !password)}>{busy ? "正在认证与办理…" : "验证身份并提交变更"}</button>
  </form></Localized>;
}
