import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api.js";
import { hasManagementAction } from "../../config.js";

export const canManageSkills = user => user?.policy_mode === "v2" &&
  (hasManagementAction(user, "policy.manage") || hasManagementAction(user, "release.approve"));

const initialBundle = () => JSON.stringify({ protocol: "skill-bundle/v1", skill_id: "example.skill", version_id: "v1",
  title: "示例业务指引", summary: "按业务步骤处理请求，所有能力调用仍通过平台。",
  sections: { workflow: "先核对输入，再按当前授权调用公共能力，并说明结果依据。" },
  required_tools: [], required_knowledge: [] }, null, 2);

export default function SkillAdmin({ user }) {
  useLanguage();
  const [department, setDepartment] = useState(user.department_id || "");
  const [application, setApplication] = useState(user.application_id || "");
  const [skill, setSkill] = useState("example.skill"), [version, setVersion] = useState("v1");
  const [bundleText, setBundleText] = useState(initialBundle);
  const [record, setRecord] = useState(null), [release, setRelease] = useState(null);
  const [releaseChecked, setReleaseChecked] = useState(false);
  const [stable, setStable] = useState(""), [candidate, setCandidate] = useState("");
  const [percentage, setPercentage] = useState("0"), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [notice, setNotice] = useState("");
  const generation = useRef(0);
  const canRegister = hasManagementAction(user, "policy.manage");
  const canApprove = hasManagementAction(user, "release.approve");
  const actor = user.principal_id || user.id || user.username;

  useEffect(() => {
    generation.current++;
    setDepartment(user.department_id || ""); setApplication(user.application_id || "");
    setRecord(null); setRelease(null); setReleaseChecked(false); setBundleText(initialBundle());
    setStable(""); setCandidate(""); setPercentage("0"); setError(""); setNotice(""); setBusy(false);
    return () => { generation.current++; };
  }, [user.principal_id, user.id, user.username, user.tenant_id, user.department_id, user.application_id]);

  function clearSelection() { generation.current++; setRecord(null); setRelease(null); setReleaseChecked(false); setError(""); setNotice(""); }
  function namespace() {
    if (!department.trim() || !application.trim()) throw new Error("请填写目标部门和应用。");
    return { tenant_id: user.tenant_id, department_id: department.trim(), application_id: application.trim() };
  }
  async function act(work) {
    const current = generation.current;
    setBusy(true); setError(""); setNotice("");
    try { await work(current); }
    catch (cause) { if (current === generation.current) setError(cause.message || "操作失败，请查询当前状态后再办理。"); }
    finally { if (current === generation.current) setBusy(false); }
  }
  async function inspectVersion() {
    await act(async current => {
      const result = await api.inspectSkill({ namespace: namespace(), skill_id: skill.trim(), version_id: version.trim() });
      if (current === generation.current) { setRecord(result.version); setNotice("已取得当前版本、内容摘要和修订号。"); }
    });
  }
  async function inspectRelease() {
    await act(async current => {
      const result = await api.inspectSkill({ namespace: namespace(), skill_id: skill.trim() });
      if (current === generation.current) {
        setRelease(result.release || null); setReleaseChecked(true);
        setStable(result.release?.stable_version || ""); setCandidate(result.release?.candidate_version || "");
        setPercentage(String((result.release?.candidate_basis_points || 0) / 100)); setNotice("已刷新发布状态。");
      }
    });
  }
  async function register() {
    await act(async current => {
      let bundle; try { bundle = JSON.parse(bundleText); } catch { throw new Error("Skill 内容必须为有效 JSON。"); }
      if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("Skill 内容必须为对象。");
      const result = await api.registerSkill(bundle, namespace());
      if (current === generation.current) { setSkill(bundle.skill_id); setVersion(bundle.version_id); setRecord(result); setRelease(null); setReleaseChecked(false); setNotice("版本已提交，请由另一位有权审核人办理审核。"); }
    });
  }
  async function review(decision) {
    await act(async current => {
      if (!record || record.bundle?.skill_id !== skill.trim() || record.bundle?.version_id !== version.trim()) throw new Error("请先查询对应版本。");
      await api.reviewSkill({ namespace: namespace(), skill_id: record.bundle.skill_id, version_id: record.bundle.version_id,
        digest: record.digest, expected_revision: record.revision, decision });
      if (current === generation.current) { setRecord(null); setReleaseChecked(false); setNotice("办理完成，请重新查询版本与发布状态。"); }
    });
  }
  async function publish() {
    await act(async current => {
      if (!releaseChecked) throw new Error("请先查询当前发布状态。");
      const percent = Number(percentage), basisPoints = Math.round(percent * 100);
      if (!Number.isFinite(percent) || percent < 0 || percent > 100 || Math.abs(percent * 100 - basisPoints) > 1e-7) throw new Error("灰度比例为0～100，最多两位小数。");
      if (!stable.trim() || (basisPoints > 0 && !candidate.trim()) || (basisPoints === 0 && candidate.trim())) throw new Error("请选择稳定版本；灰度比例与候选版本须匹配。");
      await api.publishSkill({ namespace: namespace(), skill_id: skill.trim(), expected_revision: release?.revision || 0,
        release: { stable_version: stable.trim(), candidate_version: candidate.trim(), candidate_basis_points: basisPoints } });
      if (current === generation.current) { setReleaseChecked(false); setNotice("发布已提交，请查询最新状态。已有运行保持固定版本。"); }
    });
  }
  return <Localized><section className="page-stack">
    <header><h1>Skill 管理</h1><p>注册业务指引，由另一位审核人审核，再发布给已授权的 Agent。回滚请选择仍已批准的旧版本；撤销后不能继续加载。</p></header>
    {error && <p role="alert">{error} 若提交结果不确定，请先查询状态。</p>}
    {notice && <p role="status">{notice}</p>}
    <fieldset disabled={busy}>
      <legend>目标应用与版本</legend>
      <p>租户：{user.tenant_id}</p>
      <label>部门 ID<input value={department} maxLength={128} onChange={event => { clearSelection(); setDepartment(event.target.value); }}/></label>
      <label>应用 ID<input value={application} maxLength={128} onChange={event => { clearSelection(); setApplication(event.target.value); }}/></label>
      <label>Skill ID<input value={skill} maxLength={128} onChange={event => { clearSelection(); setSkill(event.target.value); }}/></label>
      <label>版本 ID<input value={version} maxLength={128} onChange={event => { setRecord(null); setVersion(event.target.value); }}/></label>
      <button className="button" onClick={inspectVersion}>查询版本</button>
      <button className="button" onClick={inspectRelease}>查询发布状态</button>
    </fieldset>
    {canRegister && <fieldset disabled={busy}><legend>注册不可变版本</legend>
      <label>版本内容<textarea rows={14} value={bundleText} onChange={event => setBundleText(event.target.value)}/></label>
      <button className="button primary" onClick={register}>提交版本</button>
    </fieldset>}
    {record && <article><h2>当前版本</h2><p>状态：{record.status} · 修订：{record.revision} · 作者：{record.author_id}</p>
      <p>摘要：<code>{record.digest}</code></p><pre>{JSON.stringify(record.bundle, null, 2)}</pre>
      {canApprove && record.status === "submitted" && <><button disabled={busy || actor === record.author_id} onClick={() => review("approved")}>批准版本</button><button disabled={busy || actor === record.author_id} onClick={() => review("rejected")}>拒绝版本</button></>}
      {canRegister && ["submitted", "approved"].includes(record.status) && <button disabled={busy} onClick={() => review("revoked")}>撤销版本</button>}
    </article>}
    {canApprove && <fieldset disabled={busy}><legend>发布、灰度与回滚</legend>
      <p>当前发布修订：{releaseChecked ? release?.revision || "尚未发布" : "请先查询"}</p>
      <label>稳定版本<input value={stable} maxLength={128} onChange={event => setStable(event.target.value)}/></label>
      <label>候选版本<input value={candidate} maxLength={128} onChange={event => setCandidate(event.target.value)}/></label>
      <label>灰度比例（%）<input type="number" min="0" max="100" step="0.01" value={percentage} onChange={event => setPercentage(event.target.value)}/></label>
      <button className="button primary" disabled={!releaseChecked} onClick={publish}>提交发布或回滚</button>
    </fieldset>}
    <p>发布后需在 Agent 的 Runtime 策略中允许该 Skill，并为业务用户绑定 Skill 使用者角色，分别授予用户与 Agent 对应安装的 Skill 资源权限。<Link to="/admin/user-access">办理用户与 Agent 授权</Link></p>
  </section></Localized>;
}
