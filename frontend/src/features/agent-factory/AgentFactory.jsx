import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useMemo, useState } from "react";
import { api } from "../../api.js";
import { formatStatus, formatTime, shortId, statusTone } from "../../format.js";

const itemsOf = (value) => {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  if (Array.isArray(value?.data?.items)) return value.data.items;
  if (Array.isArray(value?.data)) return value.data;
  return [];
};

const initialInspect = { language: "", framework: "", adapter: "", level: "", findings: [], unknown: [] };
const initialMappingSpec = JSON.stringify({
  mapping_id: "legacy-qa",
  version: "1.0.0",
  kind: "legacy-http",
  request: {
    message: { source: "input.question", required: true, max_length: 2048 },
    trace_id: "context.trace_id"
  },
  response: { answer: "body.output" }
}, null, 2);
const initialFixture = JSON.stringify({
  input: { question: "示例问题" },
  context: { trace_id: "trace-demo" },
  body: { output: "示例回答" }
}, null, 2);

function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    if (!file) return reject(new Error("请选择模板制品文件"));
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = () => reject(new Error("模板制品读取失败"));
    reader.readAsDataURL(file);
  });
}

function inspectSummary(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : Array.isArray(report?.inspect_findings) ? report.inspect_findings : [];
  const unknown = findings.filter((item) => String(item?.status || item?.state || "").toLowerCase() === "unknown");
  return {
    language: report?.language || report?.detected?.language || "未知",
    framework: report?.framework || report?.detected?.framework || "未知",
    adapter: report?.suggested_adapter || report?.recommended_adapter || "待确认",
    level: report?.recommended_level || report?.highest_level || "待评估",
    findings,
    unknown
  };
}

export function AgentFactory() {
  useLanguage();
  const [templates, setTemplates] = useState([]);
  const [selectedID, setSelectedID] = useState("");
  const [versions, setVersions] = useState([]);
  const [mappings, setMappings] = useState([]);
  const [selectedMappingID, setSelectedMappingID] = useState("");
  const [mappingDetail, setMappingDetail] = useState(null);
  const [mappingEvidence, setMappingEvidence] = useState([]);
  const [mappingSpec, setMappingSpec] = useState(initialMappingSpec);
  const [fixture, setFixture] = useState(initialFixture);
  const [dryRun, setDryRun] = useState(null);
  const [inspect, setInspect] = useState(initialInspect);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [versionsLoading, setVersionsLoading] = useState(false);
  const [mappingsLoading, setMappingsLoading] = useState(true);
  const [mappingBusy, setMappingBusy] = useState(false);
  const [hasMoreMappings, setHasMoreMappings] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const selected = useMemo(() => templates.find((item) => item.id === selectedID) || templates[0] || null, [templates, selectedID]);
  const selectedMapping = useMemo(() => mappings.find((item) => item.id === selectedMappingID) || mappings[0] || null, [mappings, selectedMappingID]);

  const loadTemplates = async () => {
    setLoading(true);
    setError("");
    try {
      const next = itemsOf(await api.factoryTemplates({ limit: 50 }));
      setTemplates(next);
      setSelectedID((current) => next.some((item) => item.id === current) ? current : next[0]?.id || "");
    } catch (reason) {
      setError(reason.message || "模板目录读取失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadTemplates(); }, []);

  const loadMappings = async (after = "") => {
    setMappingsLoading(true);
    try {
      const next = itemsOf(await api.factoryMappings({ limit: 50, after }));
      setMappings((current) => {
        const combined = after ? [...current, ...next] : next;
        return [...new Map(combined.map((item) => [item.id, item])).values()];
      });
      setHasMoreMappings(next.length === 50);
      if (!after) setSelectedMappingID((current) => next.some((item) => item.id === current) ? current : next[0]?.id || "");
    } catch (reason) {
      setError(reason.message || "Adapter Mapping 目录读取失败");
    } finally {
      setMappingsLoading(false);
    }
  };

  useEffect(() => { loadMappings(); }, []);

  useEffect(() => {
    let active = true;
    if (!selectedMapping?.id) {
      setMappingDetail(null); setMappingEvidence([]); setDryRun(null);
      return () => { active = false; };
    }
    setMappingBusy(true);
    setDryRun(null);
    Promise.all([
      api.factoryMapping(selectedMapping.id),
      api.factoryMappingEvidence(selectedMapping.id, { limit: 20 })
    ]).then(([detail, evidence]) => {
      if (!active) return;
      setMappingDetail(detail);
      setMappingEvidence(itemsOf(evidence));
    }).catch((reason) => {
      if (active) setError(reason.message || "Mapping 详情或合规证据读取失败");
    }).finally(() => { if (active) setMappingBusy(false); });
    return () => { active = false; };
  }, [selectedMapping?.id]);

  useEffect(() => {
    let active = true;
    if (!selected?.id) { setVersions([]); return () => { active = false; }; }
    setVersionsLoading(true);
    api.factoryTemplateVersions(selected.id, { limit: 50 }).then((value) => {
      if (active) setVersions(itemsOf(value));
    }).catch((reason) => {
      if (active) setError(reason.message || "模板版本读取失败");
    }).finally(() => { if (active) setVersionsLoading(false); });
    return () => { active = false; };
  }, [selected?.id]);

  const createTemplate = async (event) => {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    try {
      const created = await api.createFactoryTemplate(values);
      await loadTemplates();
      if (created?.id) setSelectedID(created.id);
      form.reset();
      setNotice(`模板 ${created?.name || values.name} 已登记，可继续上传不可变版本。`);
    } catch (reason) {
      setError(reason.message || "模板登记失败");
    } finally { setBusy(false); }
  };

  const createVersion = async (event) => {
    event.preventDefault();
    if (!selected?.id) return setError("请先选择模板 Definition");
    setBusy(true); setError(""); setNotice("");
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    try {
      const file = form.elements.artifact.files?.[0];
      const artifactBase64 = await readAsBase64(file);
      await api.createFactoryTemplateVersion(selected.id, { version: values.version, artifact_uri: values.artifact_uri, artifact_base64: artifactBase64 });
      const next = await api.factoryTemplateVersions(selected.id, { limit: 50 });
      setVersions(itemsOf(next));
      form.reset();
      setNotice(`模板 ${selected.name} 的 ${values.version} 版本已登记，摘要由服务端固化。`);
    } catch (reason) {
      setError(reason.message || "模板版本登记失败");
    } finally { setBusy(false); }
  };

  const importInspect = (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const report = JSON.parse(String(reader.result));
        setInspect(inspectSummary(report));
        setError("");
        setNotice("Inspect 报告已导入。报告内容仅作为安全文本展示，未知项不会被当作通过。");
      } catch {
        setError("Inspect 报告必须是合法 JSON");
      }
    };
    reader.onerror = () => setError("Inspect 报告读取失败");
    reader.readAsText(file);
  };

  const createMapping = async (event) => {
    event.preventDefault();
    setMappingBusy(true); setError(""); setNotice("");
    try {
      const spec = JSON.parse(mappingSpec);
      if (!spec || typeof spec !== "object" || Array.isArray(spec)) throw new Error("Mapping Spec 必须是 JSON 对象");
      if (!spec.mapping_id || !spec.kind) throw new Error("Mapping Spec 必须包含 mapping_id 和 kind");
      const created = await api.createFactoryMapping({ mapping_id: spec.mapping_id, kind: spec.kind, spec });
      await loadMappings();
      if (created?.id) setSelectedMappingID(created.id);
      setNotice(`Mapping ${created?.mapping_id || spec.mapping_id} 已创建为 draft（revision ${created?.revision || 1}）。`);
    } catch (reason) {
      setError(reason instanceof SyntaxError ? "Mapping Spec 必须是合法 JSON" : reason.message || "Mapping 创建失败");
    } finally { setMappingBusy(false); }
  };

  const runMapping = async (event) => {
    event.preventDefault();
    if (!selectedMapping?.id) return setError("请先选择 Adapter Mapping");
    setMappingBusy(true); setError(""); setNotice(""); setDryRun(null);
    try {
      const input = JSON.parse(fixture);
      if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Conformance Fixture 必须是 JSON 对象");
      const result = await api.dryRunFactoryMapping(selectedMapping.id, input);
      setDryRun(result);
      setMappingDetail(await api.factoryMapping(selectedMapping.id));
      setMappingEvidence(itemsOf(await api.factoryMappingEvidence(selectedMapping.id, { limit: 20 })));
      setNotice(result?.evidence?.status === "passed" ? "Dry-run 通过；证据只保存摘要，可继续发布当前 revision。" : "Dry-run 完成，请检查失败信息后重试。");
    } catch (reason) {
      setError(reason instanceof SyntaxError ? "Conformance Fixture 必须是合法 JSON" : reason.message || "Mapping dry-run 失败");
    } finally { setMappingBusy(false); }
  };

  const publishMapping = async () => {
    if (!selectedMapping?.id || !mappingDetail?.revision) return;
    setMappingBusy(true); setError(""); setNotice("");
    try {
      const result = await api.publishFactoryMapping(selectedMapping.id, mappingDetail.revision);
      await loadMappings();
      setMappingDetail(await api.factoryMapping(selectedMapping.id));
      setNotice(`Mapping 已发布（revision ${result?.revision}）。`);
    } catch (reason) {
      setError(reason.message || "发布失败；revision 冲突时请刷新并重新 dry-run");
    } finally { setMappingBusy(false); }
  };

  if (loading) return <Localized><div className="state-panel"><span className="spinner"/><p>正在读取 Agent Factory 模板目录</p></div></Localized>;

  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">助手开发</p><h2>Agent 工厂</h2><p>从受信任的语言/框架模板登记不可变制品，或导入存量 Agent 的 Inspect 结果，再进入 Adapter 与评测流程。</p></div><button className="button secondary" onClick={loadTemplates}>刷新目录</button></div>
    {notice && <div className="success-banner">{notice}</div>}
    {error && <div className="form-error page-error">{error}</div>}

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>创建模板 Definition</h3><p className="form-hint">登记不等于发布；制品版本仍需安全扫描和审批。</p></div><span>{templates.length} 个模板</span></div>
        <form className="form" onSubmit={createTemplate}>
          <label><span>Template ID</span><input name="template_id" pattern="[A-Za-z0-9._-]+" placeholder="python-langgraph" required/></label>
          <label><span>模板名称</span><input name="name" placeholder="Python / LangGraph" required/></label>
          <div className="inline-form"><label><span>语言</span><select name="language" defaultValue="python"><option value="python">Python</option><option value="go">Go</option><option value="java">Java</option></select></label><label><span>框架</span><input name="framework" placeholder="LangGraph / Eino / Spring AI" required/></label></div>
          <button className="button primary" disabled={busy}>登记模板 Definition</button>
        </form>
      </article>
      <article className="card">
        <div className="card-heading"><div><h3>导入存量 Agent Inspect</h3><p className="form-hint">静态报告只读展示；unknown / failed 证据不会自动升级能力等级。</p></div><span>安全文本</span></div>
        <label className="form"><span>Inspect JSON 报告</span><input type="file" accept="application/json,.json" onChange={importInspect}/></label>
        {inspect.findings.length ? <div className="notice" style={{ marginTop: 14 }}><b>{inspect.language} · {inspect.framework}</b><p>推荐 Adapter：{inspect.adapter} · 建议等级：{inspect.level} · 未知项：{inspect.unknown.length}</p></div> : <div className="empty"><span>◇</span><b>尚未导入盘点报告</b><p>导入后可核对入口、依赖、Secret 风险和能力缺口。</p></div>}
        {!!inspect.findings.length && <div className="simple-table">{inspect.findings.slice(0, 20).map((item, index) => <div key={`${item?.id || item?.key || "finding"}-${index}`}><span><b>{item?.title || item?.key || item?.category || "Inspect Finding"}</b><small>{item?.status || item?.state || "unknown"} · {item?.risk || item?.recommendation || "请人工确认"}</small></span><span className={`badge ${statusTone(item?.status || item?.state || "unknown")}`}>{item?.status || item?.state || "unknown"}</span></div>)}</div>}
      </article>
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>模板目录</h3><p className="form-hint">选择模板查看版本、兼容性与摘要。</p></div></div>
        {templates.length ? <div className="record-list">{templates.map((item) => <button key={item.id} type="button" className="text-button" style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center", gap: 12, padding: "11px 3px", borderBottom: "1px solid #edf0f5", textAlign: "left" }} onClick={() => setSelectedID(item.id)}><span className="record-icon">T</span><span><b>{item.name || item.template_id}</b><small>{item.template_id} · {item.language} · {item.framework}</small></span><span className={`badge ${selected?.id === item.id ? "info" : ""}`}>{selected?.id === item.id ? "已选择" : formatStatus(item.status)}</span></button>)}</div> : <div className="empty"><span>◇</span><b>暂无模板</b><p>登记一个模板 Definition 后上传第一个版本。</p></div>}
      </article>
      <article className="card">
        <div className="card-heading"><div><h3>{selected ? `${selected.name || selected.template_id} · 版本` : "上传模板版本"}</h3><p className="form-hint">Artifact 通过 Base64 上传；浏览器不会展示制品内容。</p></div><span>{versions.length} 个版本</span></div>
        {selected && <form className="form" onSubmit={createVersion}><label><span>Semantic Version</span><input name="version" pattern="[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?" placeholder="1.0.0" required/></label><label><span>Artifact URI</span><input name="artifact_uri" placeholder="oci://registry/agent-template@sha256:…" required/></label><label><span>Artifact 文件</span><input name="artifact" type="file" required/></label><button className="button primary" disabled={busy}>{busy ? "正在提交…" : "登记不可变版本"}</button></form>}
        {versionsLoading ? <p className="form-hint">正在读取版本…</p> : versions.length ? <div className="simple-table" style={{ marginTop: 18 }}>{versions.map((version) => <div key={version.id}><span><b>{version.semantic_version || version.version}</b><small>创建于 {formatTime(version.created_at)} · ID {shortId(version.id)}</small></span><code>{shortId(version.content_hash, 12)}</code></div>)}</div> : <div className="empty"><span>◇</span><b>{selected ? "暂无版本" : "选择一个模板"}</b><p>{selected ? "上传制品后版本会出现在这里。" : "从左侧目录选择 Definition。"}</p></div>}
      </article>
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>创建 Adapter Mapping</h3><p className="form-hint">DSL 受限执行，不接受 caller scope；租户、部门和应用边界由可信 Gateway 身份确定。</p></div><span>声明式 Adapter</span></div>
        <form className="form" onSubmit={createMapping}>
          <label><span>Mapping Spec（JSON）</span><textarea rows="13" spellCheck="false" value={mappingSpec} onChange={(event) => setMappingSpec(event.target.value)} aria-label="Mapping Spec JSON" /></label>
          <button className="button primary" disabled={mappingBusy}>{mappingBusy ? "正在提交…" : "创建 Draft Mapping"}</button>
        </form>
      </article>
      <article className="card">
        <div className="card-heading"><div><h3>Mapping 目录</h3><p className="form-hint">列表仅返回当前可信身份作用域内的记录。</p></div><button type="button" className="button secondary" onClick={loadMappings} disabled={mappingsLoading}>刷新</button></div>
        {mappingsLoading && !mappings.length ? <p className="form-hint">正在读取 Mapping…</p> : mappings.length ? <><div className="record-list">{mappings.map((item) => <button key={item.id} type="button" className="text-button" style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center", gap: 12, padding: "11px 3px", borderBottom: "1px solid #edf0f5", textAlign: "left", width: "100%" }} onClick={() => setSelectedMappingID(item.id)}><span className="record-icon">M</span><span><b>{item.mapping_id}</b><small>{item.kind} · revision {item.revision} · {shortId(item.content_hash, 12)}</small></span><span className={`badge ${selectedMapping?.id === item.id ? "info" : ""}`}>{formatStatus(item.status)}</span></button>)}</div>{hasMoreMappings && <button type="button" className="button secondary" style={{ marginTop: 12 }} onClick={() => loadMappings(mappings[mappings.length - 1]?.id || "")} disabled={mappingsLoading}>{mappingsLoading ? "正在加载…" : "加载更多"}</button>}</> : <div className="empty"><span>◇</span><b>暂无 Adapter Mapping</b><p>创建一个 draft，再通过 dry-run 生成发布所需的 conformance evidence。</p></div>}
      </article>
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>{selectedMapping ? `${selectedMapping.mapping_id} · Conformance` : "Conformance dry-run"}</h3><p className="form-hint">只展示运行状态和证据摘要；不在页面回显 fixture、映射输入/输出或制品正文。</p></div><span>{mappingDetail ? `revision ${mappingDetail.revision}` : "未选择"}</span></div>
        {selectedMapping && <form className="form" onSubmit={runMapping}><label><span>Dry-run Fixture（JSON：input / context / body）</span><textarea rows="9" spellCheck="false" value={fixture} onChange={(event) => setFixture(event.target.value)} aria-label="Conformance Fixture JSON" /></label><button className="button secondary" disabled={mappingBusy}>{mappingBusy ? "正在执行…" : "运行 Dry-run"}</button></form>}
        {dryRun && <div className="notice" style={{ marginTop: 14 }}><b>{dryRun.evidence?.status === "passed" ? "Dry-run 通过" : "Dry-run 未通过"}</b><p>{dryRun.evidence?.check_count || 0} 项检查 · fixture hash {shortId(dryRun.evidence?.fixture_hash, 16)} · result hash {shortId(dryRun.evidence?.result_hash, 16)}</p></div>}
        {mappingEvidence.length ? <div className="simple-table" style={{ marginTop: 18 }}>{mappingEvidence.map((item) => <div key={item.id}><span><b>{formatStatus(item.status)} · {item.check_count} 项检查</b><small>{formatTime(item.created_at)} · revision {item.mapping_revision} · {shortId(item.id)}</small></span><code>{shortId(item.fixture_hash, 12)} / {shortId(item.result_hash, 12)}</code></div>)}</div> : <div className="empty"><span>◇</span><b>{mappingBusy ? "正在加载证据" : "暂无 Conformance Evidence"}</b><p>成功或失败的 dry-run 都会持久化摘要证据，不保存 fixture 和响应正文。</p></div>}
      </article>
      <article className="card">
        <div className="card-heading"><div><h3>发布 Mapping</h3><p className="form-hint">发布使用当前 revision CAS；必须先存在同 revision、同 hash 的通过证据。</p></div><span>{mappingDetail ? formatStatus(mappingDetail.status) : "—"}</span></div>
        {mappingDetail ? <><div className="simple-table"><div><span><b>Mapping</b><small>{mappingDetail.mapping_id} · {mappingDetail.kind}</small></span><code>{shortId(mappingDetail.id)}</code></div><div><span><b>Revision / hash</b><small>revision {mappingDetail.revision}</small></span><code>{shortId(mappingDetail.content_hash, 16)}</code></div><div><span><b>最近更新</b><small>{formatTime(mappingDetail.updated_at)}</small></span><span>{mappingDetail.created_by || "平台用户"}</span></div></div><button type="button" className="button primary" style={{ marginTop: 16 }} onClick={publishMapping} disabled={mappingBusy || mappingDetail.status === "published" || !mappingEvidence.some((item) => item.status === "passed" && item.mapping_revision === mappingDetail.revision && item.mapping_hash === mappingDetail.content_hash)}>{mappingBusy ? "正在发布…" : mappingDetail.status === "published" ? "已发布" : "发布当前 Revision"}</button></> : <div className="empty"><span>◇</span><b>选择一个 Mapping</b><p>发布按钮仅在当前 revision 有匹配的通过证据时启用。</p></div>}
      </article>
    </section>
  </></Localized>;
}
