import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { formatTime } from "../../format.js";

export function PersonalInbox({ user }) {
  useLanguage();
  const [state, setState] = useState({ loading: true, items: [], error: "" });
  useEffect(() => {
    let active = true;
    const read = async () => {
      try {
        const result = await api.notificationInbox();
        if (active) setState({ loading: false, items: result.items || [], error: "" });
      } catch (error) {
        // Clear previous messages after revocation, logout or workspace switch.
        if (active) setState({ loading: false, items: [], error: error.message });
      }
    };
    setState({ loading: true, items: [], error: "" });
    read();
    const interval = setInterval(read, 10000);
    return () => { active = false; clearInterval(interval); };
  }, [user.username, user.tenant_id, user.department_id, user.application_id]);
  return <Localized><section className="card">
    <div className="card-heading"><h2>我的通知</h2><small>已撤回通知会从列表移除；更正通知会保留更正说明。</small></div>
    {state.loading && <p>正在读取通知…</p>}
    {state.error && <p role="alert">{state.error}</p>}
    {!state.loading && !state.error && !state.items.length && <div className="empty"><b>当前工作空间暂无通知</b><p>Agent 发送给你的通知会显示在这里。</p></div>}
    {state.items.map(message => <article key={message.event_id} className="card">
      <h3>{message.title ? <span data-i18n-preserve>{message.title}</span> : "Agent 通知"}</h3>
      <p data-i18n-preserve style={{ whiteSpace: "pre-wrap" }}>{message.text}</p>
      {message.state === "corrected" && <p role="note">更正：<span data-i18n-preserve>{message.correction}</span></p>}
      <small>{formatTime(message.created_at)}</small>
    </article>)}
  </section></Localized>;
}
