import { Localized, useLanguage } from "../../components/Localization.jsx";
import { translateUI } from "../../localization.js";
import React, { useCallback, useEffect, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { PermissionEditor } from "./PermissionEditor.jsx";
import { AdministratorAppointment } from "./AdministratorAppointment.jsx";
import { MembershipEditor } from "./MembershipEditor.jsx";
import { PrincipalCreation } from "./PrincipalCreation.jsx";
import { TaskAssignmentEditor } from "./TaskAssignmentEditor.jsx";
import { DelegationEditor } from "./DelegationEditor.jsx";
import { BatchDepartmentAssignment } from "./BatchDepartmentAssignment.jsx";
import { PERMISSION_BATCH_LIMIT, selectBatchRecords } from "./permission-batch.js";
import { roleName } from "../../presentation.js";
import { administrationKind } from "./administration-state.js";
import { useSearchParams } from "react-router-dom";

export function PrincipalAdmin({ user }) {
  useLanguage();
  const [search] = useSearchParams();
  const [principals, setPrincipals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyID, setBusyID] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [editing, setEditing] = useState(null);
  const [appointing, setAppointing] = useState(null);
  const [memberEditing, setMemberEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [assigning, setAssigning] = useState(null);
  const [delegating, setDelegating] = useState(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [candidateID, setCandidateID] = useState("");
  const [candidates, setCandidates] = useState([]);
  const [batchSelected, setBatchSelected] = useState([]);
  const [batchLocked, setBatchLocked] = useState(false);
  const [batchOperation, setBatchOperation] = useState("department");
  const canBatch = user.policy_mode === "v2" && user.capabilities?.includes("authorization.change");
  const openBatch = operation => {
    setBatchOperation(operation);
    requestAnimationFrame(() => document.getElementById(operation === "agent" ? "batch-agent-use-assignment" : "batch-department-assignment")?.scrollIntoView({ block: "start", behavior: "smooth" }));
  };
  const hasAdditionalActions = user.policy_mode !== "v2" || ["authorization.change", "membership.manage", "administrator.appoint", "delegation.manage", "principal.disable"].some(action => user.capabilities?.includes(action));
  const selectable = principals.filter(item => item.is_active && item.id !== user.username);
  const selectBatch = (records, checked) => {
    if (batchLocked) return;
    try { setBatchSelected(selectBatchRecords(batchSelected, records, checked)); setError(""); }
    catch (cause) { setError(cause.message); }
  };
  const findCandidate = async event => {
    event.preventDefault(); setError(""); setCandidates([]);
    try { setCandidates(asItems(await api.identityMembershipCandidates({ principal_id: candidateID.trim(), page: 1, page_size: 20 }))); }
    catch (cause) { setError(cause.message); }
  };

  const reload = useCallback(async () => {
    const result = await api.identityPrincipals({ tenant_id: user.tenant_id, principal_type: "user", page, page_size: 20 });
    const items = asItems(result);
    setPrincipals(items);
    setTotal(result?.total ?? items.length);
    return items;
  }, [user.tenant_id, user.department_id, user.application_id, page]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    reload().catch((cause) => { if (active) setError(cause.message || "用户主体读取失败"); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [reload]);

  const disable = async (principal) => {
    if (!principal?.is_active || !principal.revision || principal.id === user.username) return;
    if (!window.confirm(translateUI(`确定停用用户「${principal.id}」？其本地凭据、已签发会话和 Agent 授权检查将立即失效。此操作不可从本页面撤销。`))) return;
    setError("");
    setNotice("");
    setBusyID(principal.id);
    try {
      await api.disableIdentityPrincipal(principal.id, principal.revision);
      setNotice(`用户 ${principal.id} 已停用；凭据和活动会话已撤销，操作已写入审计。`);
      await reload();
    } catch (cause) {
      setError(cause.message || "用户停用失败；若出现版本冲突，请刷新后重试。");
    } finally {
      setBusyID("");
    }
  };

  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">账号与身份</p><h2>用户主体管理</h2><p>查看管理范围内的用户，办理岗位、权限和管理员身份变更。</p></div></div>
    {notice && <div className="success-banner" role="status">{notice}</div>}
    {batchLocked && <div className="notice"><span>批量操作正在处理或等待核对。</span><button className="text-button" onClick={() => document.getElementById("permission-batch-authorization")?.scrollIntoView({ block: "start", behavior: "smooth" })}>查看批次结果</button></div>}
    {error && <div className="form-error page-error" role="alert">{error}</div>}
    {administrationKind(user) === "department" && user.capabilities?.includes("membership.manage") && <section className="card"><h3>添加部门成员</h3><p>输入同公司账号，先将其加入本部门，再分配公司允许本部门使用的 Agent。</p><form className="inline-form" onSubmit={findCandidate}><label>账号名<input required maxLength={128} value={candidateID} onChange={event => setCandidateID(event.target.value)}/></label><button className="button secondary" type="submit">查找账号</button></form>{candidates.map(item => <div className="permission-record" key={item.id}><span>{item.id}</span><button className="button secondary" disabled={item.id === user.username} onClick={() => setMemberEditing(item)}>分配部门</button></div>)}</section>}
    {user.policy_mode === "v2" && user.capabilities?.includes("authorization.change") && user.capabilities?.includes("membership.manage") && <button className="button primary" onClick={() => setCreating(true)}>新建用户</button>}
    <section className="card principal-directory">
      <div className="card-heading"><h3>公司用户</h3><button type="button" className="button secondary" disabled={loading || busyID !== "" || batchLocked} onClick={() => { setError(""); setLoading(true); reload().catch((cause) => setError(cause.message)).finally(() => setLoading(false)); }}>刷新</button></div>
      {canBatch && <div className="batch-selection-bar"><label className="checkbox-field"><input type="checkbox" disabled={loading || batchLocked || !selectable.length} checked={selectable.length > 0 && selectable.every(item => batchSelected.some(value => value.id === item.id))} onChange={event => selectBatch(selectable, event.target.checked)}/>选择本页有效用户</label><span>跨页已选 {batchSelected.length} / {PERMISSION_BATCH_LIMIT} 位</span><button className="button primary" disabled={batchLocked || !batchSelected.length} onClick={() => openBatch("agent")}>开通 Agent 使用</button>{user.capabilities?.includes("membership.manage") && <button className="button secondary" disabled={batchLocked || !batchSelected.length} onClick={() => openBatch("department")}>分配部门与身份</button>}<button className="text-button" disabled={batchLocked || !batchSelected.length} onClick={() => setBatchSelected([])}>清空选择</button></div>}
      {loading ? <div className="state-panel">正在读取用户…</div> : principals.length ? <div className="simple-table">{principals.map((principal) => <div key={`${principal.type}:${principal.id}`}>
        <span className="batch-person"><label className="checkbox-field">{canBatch && <input type="checkbox" aria-label={`选择用户 ${principal.display_name || principal.id}`} checked={batchSelected.some(item => item.id === principal.id)} disabled={batchLocked || !principal.is_active || principal.id === user.username} onChange={event => selectBatch([principal], event.target.checked)}/>}<b data-i18n-preserve>{principal.display_name || principal.id}</b>{principal.id === user.username && <span>（当前账号）</span>}</label><small data-i18n-preserve>{principal.id}{user.policy_mode !== "v2" && principal.roles?.map(code => roleName(code)).join(" · ")}</small></span>
        <span className={`badge ${principal.is_active ? "success" : "danger"}`}>{principal.is_active ? "已启用" : "已停用"}</span>
        <div className="principal-actions">
        <button type="button" className="button secondary" disabled={!principal.is_active || busyID !== "" || batchLocked} onClick={() => setEditing(principal)}>{principal.id === user.username ? "查看权限" : "身份与权限"}</button>
        {hasAdditionalActions && principal.id !== user.username && <details className="principal-more-actions"><summary>更多操作</summary><div>
        {user.policy_mode === "v2" && user.capabilities?.includes("authorization.change") && <button type="button" className="button secondary" disabled={!principal.is_active || busyID !== "" || batchLocked} onClick={() => setAssigning(principal)}>任务指派</button>}
        {user.policy_mode === "v2" && user.capabilities?.includes("membership.manage") && <button type="button" className="button secondary" disabled={!principal.is_active || busyID !== "" || batchLocked} onClick={() => setMemberEditing(principal)}>成员关系</button>}
        {user.capabilities?.includes("administrator.appoint") && <button type="button" className="button secondary" disabled={!principal.is_active || busyID !== "" || batchLocked} onClick={() => setAppointing(principal)}>管理员任命</button>}
        {user.capabilities?.includes("delegation.manage") && <button type="button" className="button secondary" disabled={!principal.is_active || busyID !== "" || batchLocked} onClick={() => setDelegating(principal)}>授权委托</button>}
        {(user.policy_mode !== "v2" || user.capabilities?.includes("principal.disable")) && <button type="button" className="button secondary danger" disabled={!principal.is_active || !principal.revision || principal.id === user.username || busyID !== "" || batchLocked} onClick={() => disable(principal)}>{busyID === principal.id ? "处理中…" : principal.id === user.username ? "不可自停用" : "停用"}</button>}
        </div></details>}
        </div>
      </div>)}</div> : <div className="empty"><b>当前公司暂无用户</b><p>已批准注册用户及管理员预置用户会显示在此处。</p></div>}
      <div className="pagination-controls"><span>共 {total} 位用户 · 第 {page} 页</span><button className="button secondary" disabled={loading || busyID !== "" || page === 1} onClick={() => setPage(value => value - 1)}>上一页</button><button className="button secondary" disabled={loading || busyID !== "" || page * 20 >= total} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    </section>
    {canBatch && <><div className="batch-selected-users" aria-label="已选用户">{batchSelected.map(item => <button key={item.id} className="batch-selection-chip" disabled={batchLocked} aria-label={`取消选择用户 ${item.display_name || item.id}`} onClick={() => selectBatch([item], false)}><span data-i18n-preserve>{item.display_name || item.id}</span><span aria-hidden="true">×</span></button>)}</div><BatchDepartmentAssignment user={user} principals={batchSelected} operation={batchOperation} onLockedChange={setBatchLocked} onClear={() => setBatchSelected([])} onSaved={async () => { setNotice("批次结果已保存，请按每人的结果核对。"); await reload(); }}/></>}
    {editing && !batchLocked && <PermissionEditor key={editing.id} user={user} principal={editing} onClose={() => setEditing(null)} onSaved={async receipt => { setNotice(`用户 ${receipt.subject_id} 的权限已更新。`); await reload(); }}/>}
    {assigning && !batchLocked && <TaskAssignmentEditor key={assigning.id} principal={assigning} onClose={() => setAssigning(null)} onSaved={async receipt => { setNotice(`用户 ${receipt.subject_id} 的任务指派已更新。`); await reload(); }}/>}
    {delegating && !batchLocked && <DelegationEditor key={delegating.id} principal={delegating} onClose={() => setDelegating(null)} onSaved={async receipt => { setNotice(`用户 ${receipt.subject_id} 的授权委托已更新。`); await reload(); }}/>}
    {memberEditing && !batchLocked && <MembershipEditor key={memberEditing.id} user={user} principal={memberEditing} preferredDepartmentID={search.get("department_id") || ""} onClose={() => setMemberEditing(null)} onSaved={async receipt => { setNotice(`用户 ${receipt.subject_id} 的成员关系已更新。`); await reload(); }}/>}
    {creating && !batchLocked && <PrincipalCreation user={user} onClose={() => setCreating(false)} onSaved={async receipt => { setNotice(`已创建用户 ${receipt.subject_id}。`); await reload(); }}/>}
    {appointing && !batchLocked && <AdministratorAppointment key={appointing.id} principal={appointing} onClose={() => setAppointing(null)} onSaved={async receipt => { setNotice(`用户 ${receipt.subject_id} 的管理员身份已更新。`); await reload(); }}/>}
  </></Localized>;
}
