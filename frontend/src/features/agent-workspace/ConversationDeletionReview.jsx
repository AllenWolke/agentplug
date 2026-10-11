import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { canReviewConversationDeletion } from "../../config.js";

export function ConversationDeletionReview({ user, onProjection }) {
  useLanguage();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const generation = useRef(0);
  const operation = useRef(0);
  const refreshRef = useRef(() => {});
  const mounted = useRef(false);
  useEffect(() => { setPage(1); }, [user.username, user.tenant_id, user.department_id, user.application_id]);

  const project = async () => {
    const projection = await api.identityPermissions();
    if (user.policy_mode === "v2") {
      const scope = projection.scope;
      if (projection.policy_mode !== "v2" || scope?.scope_type !== "application" || scope.tenant_id !== user.tenant_id || scope.department_id !== user.department_id || scope.application_id !== user.application_id) throw new Error("审批权限响应范围不匹配");
    }
    return projection;
  };

  useEffect(() => {
    mounted.current = true;
    setBusy(false); setNotice("");
    const refresh = async () => {
      const current = ++generation.current;
      setItems([]); setTotal(0); setLoading(true); setError("");
      try {
        const projection = await project();
        if (!mounted.current || current !== generation.current) return;
        onProjection(projection, user);
        if (!canReviewConversationDeletion({ ...user, ...projection })) throw new Error("当前没有删除审批授权");
        const result = await api.conversationDeletionRequests({ page, page_size: 100 });
        if (!mounted.current || current !== generation.current) return;
        setItems((result.items || []).filter(item => item.status === "pending" && item.owner_id !== user.username));
        setTotal(Number(result.total || 0));
      } catch (reason) {
        if (mounted.current && current === generation.current) { setItems([]); setError(reason.message); }
      } finally {
        if (mounted.current && current === generation.current) setLoading(false);
      }
    };
    refreshRef.current = refresh;
    refresh();
    const timer = setInterval(refresh, 15000);
    window.addEventListener("focus", refresh);
    return () => { mounted.current = false; generation.current++; operation.current++; clearInterval(timer); window.removeEventListener("focus", refresh); };
  }, [user.username, user.tenant_id, user.department_id, user.application_id, user.policy_mode, onProjection, page]);

  const approve = async item => {
    const current = generation.current;
    const ticket = ++operation.current;
    setBusy(true); setError(""); setNotice("");
    try {
      const projection = await project();
      if (!mounted.current || current !== generation.current) return;
      onProjection(projection, user);
      if (!canReviewConversationDeletion({ ...user, ...projection })) throw new Error("当前没有删除审批授权");
      const result = await api.conversationDeletionRequests({ page, page_size: 100 });
      if (!mounted.current || current !== generation.current) return;
      if (!(result.items || []).some(value => value.id === item.id && value.status === "pending" && value.owner_id !== user.username)) throw new Error("该申请已不在当前可审批范围");
      await api.approveConversationDeletion(item.id);
      if (!mounted.current || current !== generation.current) return;
      setNotice("删除申请已批准，会话已从普通历史入口隐藏。");
      refreshRef.current();
    } catch (reason) {
      if (mounted.current && current === generation.current) { generation.current++; setItems([]); setTotal(0); setError(reason.message); }
    } finally {
      if (mounted.current && ticket === operation.current) setBusy(false);
    }
  };

  return <Localized><section className="card" data-testid="deletion-review">
    <h3>待审批会话删除</h3>
    <button className="button secondary" disabled={busy} onClick={() => refreshRef.current()}>刷新审批权限</button>
    <div className="inline-actions"><button disabled={busy || loading || page <= 1} onClick={() => setPage(value => value - 1)}>上一页</button><span>第 {page} 页 · {total} 条</span><button disabled={busy || loading || page * 100 >= total} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    {notice && <p className="notice">{notice}</p>}
    {error && <p className="form-error">{error}</p>}
    {loading ? <p>正在读取当前审批范围…</p> : items.length ? <div className="record-list">{items.map(item => <div key={item.id}>
      <span><b>{item.owner_id} · {item.session_id}</b><small>{item.reason}</small></span>
      <button className="button primary" disabled={busy} onClick={() => approve(item)}>批准删除申请</button>
    </div>)}</div> : <p>当前范围内没有待处理申请。</p>}
  </section></Localized>;
}
