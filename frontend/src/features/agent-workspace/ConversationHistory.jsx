import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { formatTime } from "../../format.js";
import { AnswerText } from "../../renderers/AnswerText.js";
import { ArtifactRenderer } from "../../renderers/ArtifactRenderer.jsx";
import { agentPresentation, agentWorkspacePath } from "./catalog-presentation.js";
import { conversationActions } from "./conversation-actions.js";

function titleOf(session) {
  try { const input = JSON.parse(session.title); return input.question || input.symptom || input.summary || session.title; } catch { return session.title || "未命名会话"; }
}

export function ConversationHistory({ user }) {
  useLanguage();
  const [page, setPage] = useState(1), [query, setQuery] = useState(""), [filter, setFilter] = useState("");
  const [selected, setSelected] = useState(null);
  const [state, setState] = useState({ loading: true, items: [], total: 0, error: "" });
  const generation = useRef(0);
  const load = useCallback(async () => {
    const request = ++generation.current;
    setState({ loading: true, items: [], total: 0, error: "" });
    setSelected(null);
    try {
      const value = await api.conversations({ view: "mine", text: filter, page, page_size: 20 });
      if (request === generation.current) setState({ loading: false, items: asItems(value), total: value.total || 0, error: "" });
    } catch (cause) { if (request === generation.current) setState({ loading: false, items: [], total: 0, error: cause.message || "历史记录读取失败" }); }
  }, [page, filter, user.username, user.tenant_id, user.department_id, user.application_id]);
  useEffect(() => { load(); window.addEventListener("focus", load); return () => { generation.current++; window.removeEventListener("focus", load); }; }, [load]);
  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">本人任务记录</p><h2>我的运行历史</h2><p>查看当前工作空间内仍有权读取的个人会话。刷新页面后，已保存的输入与回答仍可从这里查看。</p></div></div>
    <section className="card"><form className="inline-form history-filter" onSubmit={event => { event.preventDefault(); setSelected(null); setPage(1); setFilter(query.trim()); }}><label><span>搜索历史</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="输入标题或关键词" maxLength={200}/></label><button className="button primary" disabled={state.loading}>搜索</button><button type="button" className="button secondary" disabled={state.loading} onClick={load}>刷新</button></form>
      {state.error && <p className="form-error" role="alert">{state.error}</p>}
      {state.loading ? <div className="empty">正在读取历史记录…</div> : !state.error && !state.items.length ? <div className="empty"><b>暂无匹配的历史记录</b><p>Agent 运行产生的会话会保存在这里；列表受当前读取权限约束。</p></div> : <div className="history-records">{state.items.map(session => <button className={selected?.id === session.id ? "selected" : ""} type="button" key={session.id} disabled={!conversationActions(user, session).read} onClick={() => setSelected(session)}><span><b data-i18n-preserve>{titleOf(session)}</b><small>{agentPresentation({ agent_id: session.agent_id }).name} · {formatTime(session.updated_at || session.started_at)} · {session.message_count || 0} 条消息</small></span><span aria-hidden="true">→</span></button>)}</div>}
      <div className="pagination-controls"><span>共 {state.total} 条 · 第 {page} 页</span><button className="button secondary" disabled={state.loading || page <= 1} onClick={() => setPage(value => value - 1)}>上一页</button><button className="button secondary" disabled={state.loading || page * 20 >= state.total} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    </section>
    {selected && <ConversationDetail key={selected.id} session={selected} user={user} onClose={() => setSelected(null)}/>}
  </></Localized>;
}

function ConversationDetail({ session, user, onClose }) {
  useLanguage();
  const [state, setState] = useState({ loading: true, items: [], total: 0, error: "" });
  const [page, setPage] = useState(1);
  useEffect(() => {
    let current = true;
    setState({ loading: true, items: [], total: 0, error: "" });
    (async () => {
      try {
        const target = await api.conversation(session.id);
        if (target.id !== session.id || !conversationActions(user, target).read) throw new Error("当前会话读取权限已变化，请刷新列表。");
        const value = await api.conversationMessages(session.id, { page, page_size: 20 });
        if (current) setState({ loading: false, items: asItems(value), total: value.total || 0, error: "" });
      } catch (cause) { if (current) setState({ loading: false, items: [], total: 0, error: cause.message || "会话内容读取失败" }); }
    })();
    return () => { current = false; };
  }, [session.id, page, user.username, user.tenant_id, user.department_id, user.application_id]);
  return <Localized><section className="card conversation-detail"><div className="card-heading"><div><h3 data-i18n-preserve>{titleOf(session)}</h3><p className="form-hint">会话编号：{session.id}</p></div><button type="button" className="button secondary" onClick={onClose}>关闭详情</button></div>
    {state.loading && <p>正在读取会话内容…</p>}{state.error && <p className="form-error" role="alert">{state.error}</p>}
    {state.items.map(message => { let value = message.content; try { value = JSON.parse(value); } catch {} const answer = typeof value === "string" ? value : value?.answer || value?.draft; return <article className={`history-message ${message.role === "user" ? "user" : "assistant"}`} key={message.id}><div className="card-heading"><b>{message.role === "user" ? "我的输入" : "Agent 回答"}</b><small>{formatTime(message.created_at)}</small></div>{message.role !== "user" && typeof answer === "string" ? <AnswerText text={answer}/> : <ArtifactRenderer artifact={value}/>}</article>; })}
    <div className="pagination-controls"><span>共 {state.total} 条消息 · 第 {page} 页</span><button className="button secondary" disabled={state.loading || page <= 1} onClick={() => setPage(value => value - 1)}>上一页</button><button className="button secondary" disabled={state.loading || page * 20 >= state.total} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    <Link className="text-button" to={agentWorkspacePath({ agent_id: session.agent_id })}>打开对应 Agent</Link>
  </section></Localized>;
}
