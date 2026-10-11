import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useState } from "react";
import { api } from "../../api.js";

export function WorkloadCreation({ user, onCreated }) {
  useLanguage();
  const [pending, setPending] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async event => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(true); setError("");
    let command = pending;
    try {
      if (!command) {
        const values = Object.fromEntries(new FormData(form));
        const cidrs = String(values.network_cidrs).split(/[\s,;]+/).filter(Boolean);
        if (!cidrs.length) throw new Error("至少填写一个调用来源 CIDR");
        const bytes = crypto.getRandomValues(new Uint8Array(48));
        command = { principal_id: values.principal_id.trim(),
          scope: { scope_type: "application", tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id },
          network_cidrs: cidrs, reason: values.reason.trim(), idempotency_key: crypto.randomUUID(),
          client_secret: Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("") };
        setPending(command);
      }
      await api.createPermissionWorkload(command);
      // The platform stores only the hash. Display the locally generated value once.
      const created = { client_id: command.principal_id, client_secret: command.client_secret };
      setPending(null); form.reset();
      await onCreated(created);
    } catch (cause) {
      setError(cause.message || "机器主体创建失败");
      // Preserve the exact command after an ambiguous failure; never retry with a new secret.
      if (cause.status >= 400 && cause.status < 500 && cause.status !== 409) setPending(null);
    } finally { setBusy(false); }
  };
  return <Localized><article className="card"><h3>新建机器主体并签发凭证</h3>
    <p>工作空间：{user.tenant_id} / {user.department_id} / {user.application_id}</p>
    <p>创建后没有人员角色、业务权限或 Agent 绑定。请分别办理资源授权和安装实例绑定，再接入业务 Agent。</p>
    {error && <p className="form-error" role="alert">{error}</p>}
    <form id="create-permission-workload-form" className="form" onSubmit={submit}>
      <label>机器主体 ID<input name="principal_id" required maxLength={128} pattern="[a-zA-Z0-9][a-zA-Z0-9._:\-]*" autoComplete="off" disabled={busy || !!pending}/></label>
      <label>调用来源 CIDR<textarea name="network_cidrs" rows="3" required disabled={busy || !!pending} placeholder="例如 10.20.0.0/16，每行一个"/></label>
      <label>办理原因<textarea name="reason" required maxLength={1000} disabled={busy || !!pending}/></label>
      <button className="button primary" disabled={busy} type="submit">{pending ? "重试同一创建请求" : "创建并生成一次性 Client Secret"}</button>
    </form>
    {pending && !busy && <p>待确认请求保留在当前页面内存中。重试使用相同主体、幂等键和 Secret；刷新页面会丢失尚未保存的 Secret。</p>}
  </article></Localized>;
}
