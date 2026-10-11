import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api.js";
import { createToolApprovalFlow } from "./tool-approval.js";
import { authenticateOIDC } from "../identity/oidc-step-up.js";

// Host supplies a pending reference; callbacks receive non-secret receipts, never confirmation tokens.
export function ToolApproval({ operation, onApproved, onRevoked, onResumeRequested, onClose }) {
  useLanguage();
  const flow = useMemo(() => createToolApprovalFlow(api), []);
  const password = useRef(null);
  const mounted = useRef(false);
  const authentication = useRef(null);
  const methodGeneration = useRef(0);
  const [method, setMethod] = useState(null);
  const [preview, setPreview] = useState(null);
  const [approved, setApproved] = useState(false);
  const [resumeState, setResumeState] = useState("");
  const [resumeWarning, setResumeWarning] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function loadAuthenticationMethod() {
    const generation = ++methodGeneration.current;
    setMethod(null);
    try {
      const value = await api.identityStepUpMethod();
      if (mounted.current && methodGeneration.current === generation) setMethod(value);
    } catch (cause) {
      if (mounted.current && methodGeneration.current === generation) { setMethod({ available: false, failed: true }); setError(cause.message); }
    }
  }
  useEffect(() => {
    mounted.current = true; flow.invalidate(); setPreview(null); setApproved(false); setResumeState(""); setResumeWarning(""); setError("");
    loadAuthenticationMethod();
    if (password.current) password.current.value = "";
    return () => { ++methodGeneration.current; mounted.current = false; authentication.current?.abort(); flow.invalidate(); };
  }, [flow, operation]);
  async function load() {
    setBusy(true); setError("");
    try { const value = await flow.preview(operation); if (mounted.current) setPreview(value); }
    catch (cause) { if (mounted.current) setError(cause.message); }
    finally { if (mounted.current) setBusy(false); }
  }
  async function submit(event) {
    event.preventDefault();
    if (busy || !method?.available || !["local", "oidc"].includes(method.method)) return;
    const attempt = new AbortController(); authentication.current = attempt;
    setBusy(true); setError("");
    let secret = password.current?.value || "";
    let response = null;
    if (password.current) password.current.value = "";
    try {
      response = await flow.commit(approved ? "revoke" : "approve", secret,
        method.method === "oidc" ? input => authenticateOIDC({ begin: api.beginOIDCStepUp, input, signal: attempt.signal }) : undefined);
      const receipt = {
        ...(typeof response?.approval_id === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(response.approval_id)
          ? { approval_id: response.approval_id } : {}),
        ...(typeof response?.expires_at === "string" && response.expires_at.length <= 64
          ? { expires_at: response.expires_at }
          : Number.isFinite(response?.expires_at) ? { expires_at: response.expires_at } : {}),
        ...(approved ? { revoked: response?.revoked === true } : {})
      };
      response = null; // Do not pass or retain the plaintext confirmation token.
      if (!mounted.current) return;
      if (approved) {
        setApproved(false); setPreview(null); flow.invalidate();
        if (resumeState !== "unknown") { setResumeState(""); setResumeWarning(""); }
        await onRevoked?.(receipt);
      }
      else { setApproved(true); await onApproved(receipt); }
    } catch (cause) { if (mounted.current) setError(cause.message); }
    finally { secret = ""; response = null; if (mounted.current) setBusy(false); }
  }
  async function continueRun() {
    if (busy || !approved || resumeState) return;
    setBusy(true); setError("");
    try {
      const receipt = await flow.resumeApproved();
      if (!mounted.current) return;
      setResumeState("requested");
      await onResumeRequested?.(receipt);
    } catch (cause) {
      if (mounted.current) {
        setResumeState("unknown");
        setResumeWarning(`继续请求结果无法确认。请核查原运行 ${operation.run_id} 的状态；为避免重复执行，页面不会自动重发。`);
      }
    } finally { if (mounted.current) setBusy(false); }
  }
  return <Localized><section className="card" aria-label="工具操作批准">
    <div className="card-heading"><h3>工具操作批准</h3><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {resumeWarning && <p className="form-hint" role="status">{resumeWarning}</p>}
    {!preview ? (!resumeState && <button className="button primary" disabled={busy} onClick={load}>核对待执行操作</button>) : <>
      {!resumeState && <>
        <p>工具：{preview.claims.tool_name}；有效期至 {new Date(preview.claims.expires_at * 1000).toLocaleString()}。</p>
        <pre>{JSON.stringify(preview.display_payload, null, 2)}</pre>
        {(preview.display_filtered || preview.display_truncated) && <p>部分参数已隐藏或截断，请向业务负责人核实完整操作后办理。</p>}
      </>}
      {(approved || !resumeState) && <form onSubmit={submit} aria-label="验证身份并办理工具操作">
        {!method ? <p>正在读取再次认证方式…</p> : method.failed
          ? <button type="button" className="button secondary" disabled={busy} onClick={loadAuthenticationMethod}>重新读取认证方式</button>
          : !method.available || !["local", "oidc"].includes(method.method)
          ? <p role="alert">当前身份提供方尚未配置再次认证，请联系平台管理员。</p>
          : method.method === "oidc" ? <p>将在身份提供方窗口验证当前账号。验证成功后，仅办理本次已核对的工具操作。</p>
          : <label>当前登录密码<input ref={password} type="password" autoComplete="current-password" required disabled={busy}/></label>}
        <button className="button primary" disabled={busy || !method?.available || !["local", "oidc"].includes(method.method)}>{busy ? "正在办理…" : approved ? "再次认证并撤销批准" : "再次认证并批准此操作"}</button>
      </form>}
      {approved && !resumeState && <>
        <p>该具体操作已批准。你可以继续运行，也可以再次认证后撤销批准。</p>
        <button type="button" className="button primary" disabled={busy} onClick={continueRun}>{busy ? "正在提交…" : "继续运行"}</button>
      </>}
    </>}
  </section></Localized>;
}
