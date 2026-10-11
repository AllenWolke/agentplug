import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api.js";

export function CredentialSettings({ logout }) {
  useLanguage();
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    if (newPassword !== confirmPassword) {
      setError("两次输入的新密码不一致。");
      return;
    }
    if (newPassword === currentPassword) {
      setError("新密码必须与当前密码不同。");
      return;
    }
    setBusy(true);
    try {
      await api.changeOwnIdentityPassword(currentPassword, newPassword);
      // Password change increments auth_revision, so all browser sessions must
      // reauthenticate; the API response never returns either password.
      try { await logout(); } catch { /* A revoked session is already logged out. */ }
      navigate("/login", { replace: true });
    } catch (cause) {
      setError(cause.message || "密码修改失败；请确认当前密码后重试。");
    } finally {
      setBusy(false);
    }
  };

  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">账号安全</p><h2>安全设置</h2><p>修改本地登录密码后，旧会话将立即失效并要求重新登录。OIDC 账号请在企业身份提供方修改密码。</p></div></div>
    <section className="card registration-card">
      <h3>修改登录密码</h3>
      <form className="form" onSubmit={submit}>
        <label><span>当前密码</span><input name="current_password" type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required maxLength={128}/></label>
        <label><span>新密码（10–128 个字符）</span><input name="new_password" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required minLength={10} maxLength={128}/></label>
        <label><span>确认新密码</span><input name="confirm_password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required minLength={10} maxLength={128}/></label>
        {error && <div className="form-error" role="alert">{error}</div>}
        <button className="button primary" type="submit" disabled={busy}>{busy ? "正在修改…" : "修改密码并重新登录"}</button>
      </form>
    </section>
  </></Localized>;
}
