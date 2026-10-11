import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { TechnicalDetails } from "../../components/DisplayNames.jsx";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { formatStatus } from "../../format.js";
import { DepartmentAgentAccess } from "./DepartmentAgentAccess.jsx";

export function DepartmentAdmin({ user }) {
  useLanguage();
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ items: [], total: 0 });
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [departmentID, setDepartmentID] = useState(() => crypto.randomUUID());
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState(null);
  const [generation, setGeneration] = useState(0);
  const [agentDepartment, setAgentDepartment] = useState(null);
  useEffect(() => {
    let active = true;
    setLoading(true);
    api.departmentPage({ tenant_id: user.tenant_id, page, page_size: 20 }).then(value => { if (active) setData(value); })
      .catch(cause => { if (active) setError(cause.message); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [user.tenant_id, page, generation]);
  const create = async event => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const value = { id: departmentID, tenant_id: user.tenant_id, name: name.trim(), code: code.trim() || `dept-${departmentID.slice(0, 8)}`, status: "active", revision: 1 };
      await api.createDepartment(value);
      setCreated(value); setName(""); setCode(""); setDepartmentID(crypto.randomUUID()); setPage(1); setGeneration(value => value + 1);
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const memberLink = department => `/platform/identity-principals?department_id=${encodeURIComponent(department.id)}`;
  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">公司组织</p><h2>部门管理</h2><p>创建部门，再添加成员并指定部门身份。没有 Agent 的部门也可先配置成员。</p></div></div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {created && <section className="success-banner" role="status"><b>部门已创建：{created.name}</b><p>下一步选择本公司用户，指定为部门管理员或部门用户。</p><Link className="button primary" to={memberLink(created)}>添加部门成员</Link></section>}
    <section className="card"><h3>创建部门</h3><form className="form" aria-label="创建公司部门" onSubmit={create}>
      <label>所属公司工作空间<input readOnly value={user.workspace_name || "当前公司"}/></label>
      <label>部门名称<input required maxLength={128} value={name} disabled={busy} onChange={event => setName(event.target.value)}/></label>
      <details className="technical-details"><summary>部门编码（可选）</summary><label>部门编码<input maxLength={64} value={code} disabled={busy} onChange={event => setCode(event.target.value)}/></label><p>留空将自动生成，不影响部门名称。</p></details>
      <p className="form-hint">创建部门不会自动添加用户或开通 Agent 权限。</p>
      <button className="button primary" type="submit" disabled={busy || !name.trim()}>创建部门</button>
    </form></section>
    <section className="card"><div className="card-heading"><h3>本公司部门</h3><button className="button secondary" disabled={loading || busy} onClick={() => { setError(""); setGeneration(value => value + 1); }}>刷新</button></div>
      {loading ? <p>正在读取部门…</p> : <div className="record-list">{asItems(data).map(item => <div key={item.id}><span><b>{item.name}</b><small>{formatStatus(item.status)}</small><TechnicalDetails values={{ "部门编号": item.id, "部门编码": item.code }}/></span><div className="button-row"><button className="button secondary" onClick={() => setAgentDepartment(item)}>可用 Agent</button><Link className="button secondary" to={memberLink(item)}>成员与身份</Link></div></div>)}</div>}
      <div className="pagination-controls"><span>共 {data.total || 0} 个部门</span><button className="button secondary" disabled={loading || page === 1} onClick={() => setPage(value => value - 1)}>上一页</button><button className="button secondary" disabled={loading || page * 20 >= (data.total || 0)} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    </section>
    {agentDepartment && <DepartmentAgentAccess key={agentDepartment.id} user={user} department={agentDepartment} onClose={() => setAgentDepartment(null)}/>}
  </></Localized>;
}
