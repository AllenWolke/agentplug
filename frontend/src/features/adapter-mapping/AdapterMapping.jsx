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

const defaultSpec = {
  mapping_id: "legacy-qa",
  version: "1.0.0",
  kind: "legacy-http",
  request: { message: "input.question", trace_id: "context.trace_id" },
  response: { output: "body.output" }
};

const stringify = (value) => JSON.stringify(value, null, 2);

export function AdapterMapping() {
  useLanguage();
  const [mappings, setMappings] = useState([]);
  const [selectedID, setSelectedID] = useState("");
  const [specText, setSpecText] = useState(stringify(defaultSpec));
  const [sampleText, setSampleText] = useState('{"input":{"question":"demo"},"context":{"trace_id":"trace-demo"},"body":{}}');
  const [detail, setDetail] = useState(null);
  const [dryResult, setDryResult] = useState(null);
  const [after, setAfter] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const selected = useMemo(() => mappings.find((item) => item.id === selectedID) || null, [mappings, selectedID]);

  const load = async (cursor = "", append = false) => {
    setLoading(true); setError("");
    try {
      const page = itemsOf(await api.factoryMappings({ limit: 50, after: cursor }));
      setMappings((current) => append ? [...current, ...page.filter((item) => !current.some((old) => old.id === item.id))] : page);
      setAfter(page.at(-1)?.id || cursor);
      setHasMore(page.length >= 50);
      setSelectedID((current) => current && (append ? true : page.some((item) => item.id === current)) ? current : page[0]?.id || "");
    } catch (reason) { setError(reason.message || "Mapping 目录读取失败"); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    let active = true;
    if (!selected?.id) { setDetail(null); return () => { active = false; }; }
    api.factoryMapping(selected.id).then((value) => {
      if (!active) return;
      setDetail(value);
      const source = value?.spec || value?.spec_json;
      if (source) {
        try { setSpecText(stringify(typeof source === "string" ? JSON.parse(source) : source)); } catch { /* keep the editor text */ }
      }
    }).catch((reason) => { if (active) setError(reason.message || "Mapping 详情读取失败"); });
    return () => { active = false; };
  }, [selected?.id]);

  const create = async (event) => {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    const form = event.currentTarget;
    try {
      const spec = JSON.parse(specText);
      if (!spec || typeof spec !== "object" || Array.isArray(spec)) throw new Error("Mapping 必须是 JSON 对象");
      if (/[\u0000-\u001f]/.test(specText)) throw new Error("Mapping 不允许控制字符");
      const created = await api.createFactoryMapping({ mapping_id: spec.mapping_id, kind: spec.kind, spec });
      await load();
      if (created?.id) setSelectedID(created.id);
      setNotice(`Mapping ${created?.mapping_id || spec.mapping_id} 已保存为 draft，内容摘要 ${shortId(created?.content_hash, 12)}。`);
    } catch (reason) { setError(reason.message || "Mapping 保存失败"); }
    finally { setBusy(false); }
  };

  const runDry = async () => {
    if (!selected?.id) return setError("请先选择一个 Mapping");
    setBusy(true); setError(""); setNotice(""); setDryResult(null);
    try {
      const sample = JSON.parse(sampleText);
      const result = await api.dryRunFactoryMapping(selected.id, sample);
      setDryResult(result);
      setNotice("Dry Run 完成：仅执行已保存的映射，不访问网络或执行脚本。");
    } catch (reason) { setError(reason.message || "Dry Run 失败"); }
    finally { setBusy(false); }
  };

  const publish = async () => {
    if (!selected?.id) return setError("请先选择一个 Mapping");
    setBusy(true); setError(""); setNotice("");
    try {
      await api.publishFactoryMapping(selected.id, selected.revision);
      setNotice(`Mapping ${selected.mapping_id} 已发布。并发修改时服务端会以 revision 拒绝旧页面提交。`);
      await load();
    } catch (reason) {
      // The mapping endpoints signal a lost CAS race with {"error":
      // "REVISION_CONFLICT"} (409), which the API client surfaces as message
      // (the numeric HTTP status lands in code). Match both shapes so the
      // conflict guidance is actually shown.
      // Mapping 端点以 {"error": "REVISION_CONFLICT"}（409）表示 CAS 竞争失败，
      // API 客户端把它呈现为 message（数字 HTTP 状态落在 code）。两种形态都
      // 匹配，确保冲突指引真的展示出来。
      setError(reason.code === "REVISION_CONFLICT" || reason.message === "REVISION_CONFLICT" ? "Mapping 已被其他管理员修改，请刷新后重试。" : reason.message || "Mapping 发布失败");
    }
    finally { setBusy(false); }
  };

  if (loading && !mappings.length) return <Localized><div className="state-panel"><span className="spinner"/><p>正在读取 Adapter Mapping 目录</p></div></Localized>;

  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">存量服务接入</p><h2>Adapter Mapping</h2><p>使用有限、确定性的字段映射接入存量 Agent。Endpoint 由服务端注册和授权，浏览器不提供脚本、URL 或凭证编辑能力。</p></div><button className="button secondary" onClick={() => load()}>刷新目录</button></div>
    {notice && <div className="success-banner">{notice}</div>}{error && <div className="form-error page-error">{error}</div>}

    <section className="two-column">
      <article className="card"><div className="card-heading"><div><h3>创建受控 Mapping</h3><p className="form-hint">保存前由服务端做 Schema、引用、污染分析和摘要校验。</p></div><span>JSON DSL</span></div><form className="form" onSubmit={create}><label><span>Mapping 文档</span><textarea value={specText} onChange={(event) => setSpecText(event.target.value)} rows={16} spellCheck="false" required/></label><button className="button primary" disabled={busy}>{busy ? "正在校验…" : "保存为 Draft"}</button></form></article>
      <article className="card"><div className="card-heading"><div><h3>Dry Run 与 Fixture</h3><p className="form-hint">输入仅作为 fixture；运行结果只展示映射后的键值。</p></div><span>{selected ? `r${selected.revision}` : "未选择"}</span></div><label className="form"><span>Fixture（JSON）</span><textarea value={sampleText} onChange={(event) => setSampleText(event.target.value)} rows={8} spellCheck="false"/></label><div className="inline-actions" style={{ marginTop: 14 }}><button className="button primary" type="button" disabled={busy || !selected} onClick={runDry}>运行 Dry Run</button><button className="button secondary" type="button" disabled={busy || !selected || selected.status === "published"} onClick={publish}>发布 Mapping</button></div>{dryResult && <div className="notice" style={{ marginTop: 16 }}><b>映射结果</b><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{stringify(dryResult)}</pre></div>}</article>
    </section>

    <section className="card"><div className="card-heading"><div><h3>Mapping Registry</h3><p className="form-hint">发布后不可原地修改；revision 冲突需要重新读取。</p></div><span>{mappings.length} 条</span></div>{mappings.length ? <div className="record-list">{mappings.map((mapping) => <button key={mapping.id} type="button" className="text-button" style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center", gap: 12, padding: "11px 3px", borderBottom: "1px solid #edf0f5", textAlign: "left" }} onClick={() => setSelectedID(mapping.id)}><span className="record-icon">D</span><span><b>{mapping.mapping_id} · {mapping.kind}</b><small>{formatStatus(mapping.status)} · r{mapping.revision} · {formatTime(mapping.updated_at || mapping.created_at)} · {shortId(mapping.content_hash, 12)}</small></span><span className={`badge ${selected?.id === mapping.id ? "info" : statusTone(mapping.status)}`}>{selected?.id === mapping.id ? "已选择" : formatStatus(mapping.status)}</span></button>)}</div> : <div className="empty"><span>◇</span><b>暂无 Mapping</b><p>输入受控 JSON DSL 保存第一个 Adapter Mapping。</p></div>}{hasMore && <div className="inline-actions" style={{ marginTop: 16 }}><span className="form-hint">列表使用游标分页，避免跨租户偏移量漂移。</span><button className="button secondary" onClick={() => load(after, true)}>加载更多</button></div>}</section>

    {detail && <section className="card"><div className="card-heading"><div><h3>Mapping 只读详情</h3><p className="form-hint">服务端返回的声明式文档以 JSON 文本展示，不执行其中任何内容。</p></div><code>{shortId(detail.content_hash, 16)}</code></div><pre style={{ margin: 0, maxHeight: 340, overflow: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{stringify(detail.spec || detail.spec_json || detail)}</pre></section>}
  </></Localized>;
}
