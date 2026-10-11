import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api.js";
import { formatStatus, formatTime, shortId, statusTone } from "../../format.js";

const PAGE_SIZE = 50;
const initialCases = '[{"case_id":"case-001","input":{"question":"demo"},"expected":{"answer":"demo"},"split":"dev"}]';
const metricFormulaExamples = {
  exact_match: '{"field":"expected.answer","output_field":"answer"}',
  contains: '{"field":"expected.answer","output_field":"answer"}',
  numeric_tolerance: '{"field":"expected.value","output_field":"value","tolerance":0.01}',
  recall_at_k: '{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":5}',
  mrr: '{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":10}',
  ndcg: '{"input_relevant_field":"expected.relevant_ids","output_ranked_field":"retrieved_ids","k":10}',
  citation_accuracy: '{"input_expected_field":"expected.citation_ids","output_actual_field":"citation_ids"}',
  grounding: '{"output_citations_field":"citations","output_claims_field":"claims","gate":{"min_entailment":0.8,"require_all_claims":true,"fail_on_unknown":true}}',
  custom_deterministic: '{"input_total_field":"expected.total","output_correct_field":"score.correct"}'
};

function itemsOf(value) {
  return Array.isArray(value?.items) ? value.items : [];
}

// The module returns Resource envelopes; keep its control fields separate from
// the domain payload so revision/status always come from the authoritative row.
// 模块返回 Resource 信封；领域载荷与控制字段分开，revision/status 始终来自权威记录。
function normalizeResource(resource) {
  const payload = resource?.data && typeof resource.data === "object" ? resource.data : {};
  return {
    ...payload,
    id: resource?.id,
    kind: resource?.kind,
    status: resource?.status,
    revision: resource?.revision,
    created_by: resource?.created_by || "",
    created_at: resource?.created_at,
    updated_at: resource?.updated_at,
    resource_data: payload
  };
}

function normalizedItems(value) {
  return itemsOf(value).map(normalizeResource);
}

function principalIDOf(identity) {
  return String(identity?.principal_id || identity?.user_id || identity?.id || identity?.username || "");
}

function stringify(value) {
  return JSON.stringify(value, null, 2);
}

export function EvaluationWorkspace() {
  useLanguage();
  const [datasets, setDatasets] = useState([]);
  const [suites, setSuites] = useState([]);
  const [metrics, setMetrics] = useState([]);
  const [metricKind, setMetricKind] = useState("exact_match");
  const [runs, setRuns] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [reviews, setReviews] = useState([]);
  const [baselines, setBaselines] = useState([]);
  const [currentIdentity, setCurrentIdentity] = useState(null);
  const [evaluatorAvailability, setEvaluatorAvailability] = useState({ configured: null, state: "unknown", reason_code: "EVALUATOR_UNAVAILABLE" });
  const [selectedRunID, setSelectedRunID] = useState("");
  const [runDetail, setRunDetail] = useState(null);
  const [selectedEvidenceRunDetail, setSelectedEvidenceRunDetail] = useState(null);
  const [runFilter, setRunFilter] = useState("");
  const [runQuery, setRunQuery] = useState("");
  const [selectedEvidenceID, setSelectedEvidenceID] = useState("");
  const [gateResult, setGateResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const runIdempotencyKey = useRef(crypto.randomUUID());

  const visibleRuns = useMemo(() => runs.filter((run) =>
    (!runFilter || run.status === runFilter) &&
    (!runQuery || `${run.id} ${run.suite_id} ${run.agent_version_id}`.toLowerCase().includes(runQuery.toLowerCase()))
  ), [runs, runFilter, runQuery]);
  const selectedRun = runs.find((run) => run.id === selectedRunID) || null;
  const selectedEvidence = evidence.find((item) => item.id === selectedEvidenceID) || null;
  const selectedEvidenceRun = selectedEvidence
    ? runs.find((run) => run.id === selectedEvidence.run_id) || selectedEvidenceRunDetail
    : null;
  const currentPrincipalID = principalIDOf(currentIdentity);
  const evaluatorCanRun = evaluatorAvailability.configured === true && evaluatorAvailability.state === "configured";

  const load = async (showLoading = true) => {
    if (showLoading) setLoading(true);
    setError("");
    // Availability is fail-closed while refreshing; stale success must not
    // leave Run creation enabled if the Dispatcher has become unavailable.
    // 刷新期间按失败关闭处理，不能让旧的可用状态继续开放 Run 提交。
    setEvaluatorAvailability({ configured: null, state: "checking", reason_code: "EVALUATOR_UNAVAILABLE" });
    const results = await Promise.allSettled([
      api.evaluationProductDatasets({ page: 1, page_size: PAGE_SIZE }),
      api.evaluationProductSuites({ page: 1, page_size: PAGE_SIZE }),
      api.evaluationProductMetrics({ page: 1, page_size: PAGE_SIZE }),
      api.evaluationProductRuns({ page: 1, page_size: PAGE_SIZE }),
      api.evaluationProductEvidence({ page: 1, page_size: PAGE_SIZE }),
      api.evaluationProductReviews({ page: 1, page_size: PAGE_SIZE }),
      api.evaluationProductBaselines({ page: 1, page_size: PAGE_SIZE }),
      api.me(),
      api.evaluationProductAvailability()
    ]);
    const setters = [setDatasets, setSuites, setMetrics, setRuns, setEvidence, setReviews, setBaselines];
    const labels = ["Dataset", "Suite", "Metric", "Run", "Evidence", "Review", "Baseline", "当前身份", "评测器可用性"];
    const failed = [];
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        failed.push(labels[index]);
        if (index < setters.length) setters[index]([]);
        else if (index === setters.length) setCurrentIdentity(null);
        else setEvaluatorAvailability({ configured: null, state: "unknown", reason_code: "EVALUATOR_UNAVAILABLE" });
      } else if (index < setters.length) {
        setters[index](normalizedItems(result.value));
      } else if (index === setters.length) {
        setCurrentIdentity(result.value);
      } else {
        const availability = result.value;
        if (!availability || typeof availability.configured !== "boolean" || typeof availability.state !== "string") {
          failed.push("评测器可用性");
          setEvaluatorAvailability({ configured: null, state: "unknown", reason_code: "EVALUATOR_UNAVAILABLE" });
        } else {
          setEvaluatorAvailability({
            configured: availability.configured,
            state: availability.state,
            reason_code: availability.reason_code || (availability.configured ? "" : "EVALUATOR_UNAVAILABLE")
          });
        }
      }
    });
    if (failed.length) setNotice(`${failed.join("、")} 查询失败；工作区不使用旧接口或本地伪数据，请检查权限/服务后重试。`);
    else setNotice("");
    if (showLoading) setLoading(false);
  };

  useEffect(() => { void load(); }, []);

  useEffect(() => {
    let active = true;
    if (!selectedRunID) { setRunDetail(null); return () => { active = false; }; }
    api.evaluationProductRun(selectedRunID)
      .then((value) => { if (active) setRunDetail(normalizeResource(value)); })
      .catch((reason) => { if (active) setError(reason.message || "Run 详情读取失败"); });
    return () => { active = false; };
  }, [selectedRunID]);

  useEffect(() => {
    const current = runDetail || selectedRun;
    if (!selectedRunID || !["queued", "running", "cancelling"].includes(current?.status)) return;
    let active = true;
    let timer;
    const refresh = async () => {
      try {
        const latest = normalizeResource(await api.evaluationProductRun(selectedRunID));
        if (!active) return;
        setRunDetail(latest);
        setRuns((items) => items.map((item) => item.id === latest.id ? latest : item));
        if (current.status === "cancelling" && latest.status === "cancelled") {
          setNotice(`Run ${shortId(latest.id)} 已取消，执行停止和必要补偿已确认。`);
        }
        if (["queued", "running", "cancelling"].includes(latest.status)) timer = setTimeout(refresh, 2000);
      } catch (reason) {
        if (active) {
          setRunDetail(null);
          setError(reason.message || "Run 状态暂时无法确认，请刷新核对。");
        }
      }
    };
    timer = setTimeout(refresh, 2000);
    return () => { active = false; clearTimeout(timer); };
  }, [selectedRunID, runDetail?.status, selectedRun?.status]);

  useEffect(() => {
    let active = true;
    setSelectedEvidenceRunDetail(null);
    if (!selectedEvidence) return () => { active = false; };
    const listed = runs.find((run) => run.id === selectedEvidence.run_id);
    if (listed) {
      setSelectedEvidenceRunDetail(listed);
      return () => { active = false; };
    }
    api.evaluationProductRun(selectedEvidence.run_id)
      .then((value) => { if (active) setSelectedEvidenceRunDetail(normalizeResource(value)); })
      .catch(() => { if (active) setSelectedEvidenceRunDetail(null); });
    return () => { active = false; };
  }, [selectedEvidenceID, runs, evidence]);

  const submit = async (event, work, successMessage) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await work(new FormData(form), form);
      form.reset();
      await load(false);
      setNotice(successMessage);
      return result;
    } catch (reason) {
      setError(reason.message || "操作失败");
      return null;
    } finally {
      setBusy(false);
    }
  };

  const createDataset = (event) => submit(event, (form) => {
    let cases;
    try { cases = JSON.parse(String(form.get("cases"))); } catch { throw new Error("Cases 必须是合法 JSON 数组"); }
    if (!Array.isArray(cases) || !cases.length) throw new Error("Dataset 至少需要一个 Case");
    return api.createEvaluationProductDataset({
      name: String(form.get("name")).trim(),
      version: String(form.get("version")).trim(),
      source_type: form.get("source_type"),
      cases
    });
  }, "Dataset 已创建为 draft；需要另一位身份审核后方可发布。");

  const reviewDataset = (event, dataset) => submit(event, async (form) => {
    if (!currentPrincipalID) throw new Error("无法读取当前登录身份，不能发起 Dataset 审核。");
    if (dataset.created_by === currentPrincipalID) throw new Error("Dataset 创建人与审核人必须分离。");
    const result = await api.reviewEvaluationProductDataset(dataset.id, {
      expected_revision: dataset.revision,
      decision: form.get("decision"),
      reason: String(form.get("reason")).trim()
    });
    return normalizeResource(result);
  }, `Dataset ${shortId(dataset.id)} 的审核决定已记录；批准后可单独发布。`);

  const publishDataset = async (dataset) => {
    setBusy(true); setError(""); setNotice("");
    try {
      await api.publishEvaluationProductDataset(dataset.id, { expected_revision: dataset.revision });
      await load(false);
      setNotice(`Dataset ${shortId(dataset.id)} 已发布，可用于创建 Suite。`);
    } catch (reason) { setError(reason.message || "Dataset 发布失败"); }
    finally { setBusy(false); }
  };

  const createMetric = (event) => submit(event, (form) => {
    let formula;
    try { formula = JSON.parse(String(form.get("formula"))); } catch { throw new Error("Metric Formula 必须是合法 JSON"); }
    const metric = {
      metric_id: String(form.get("metric_id")).trim(),
      version: String(form.get("version")).trim(),
      name: String(form.get("name")).trim(),
      kind: form.get("kind"),
      formula
    };
    if (metric.kind === "custom_deterministic") {
      metric.plugin_id = String(form.get("plugin_id")).trim();
      metric.plugin_version = String(form.get("plugin_version")).trim();
      metric.plugin_digest = String(form.get("plugin_digest")).trim();
    }
    return api.createEvaluationProductMetric(metric);
  }, "Metric Version 已登记为 draft。");

  const publishMetric = async (metric) => {
    setBusy(true); setError(""); setNotice("");
    try {
      await api.publishEvaluationProductMetric(metric.id, { expected_revision: metric.revision });
      await load(false);
      setNotice(`Metric ${metric.metric_id} · ${metric.version} 已发布。`);
    } catch (reason) { setError(reason.message || "Metric 发布失败"); }
    finally { setBusy(false); }
  };

  const createSuite = (event) => submit(event, (form) => {
    const metricIDs = form.getAll("metric_ids").map((value) => String(value).trim()).filter(Boolean);
    if (!metricIDs.length) throw new Error("至少选择一个已发布 Metric");
    return api.createEvaluationProductSuite({
      name: String(form.get("name")).trim(),
      version: String(form.get("version")).trim(),
      dataset_id: form.get("dataset_id"),
      agent_id: String(form.get("agent_id")).trim(),
      agent_version_id: String(form.get("agent_version_id")).trim(),
      metric_ids: metricIDs
    });
  }, "Suite 已固化已发布 Dataset、Agent Version 与 Metric 引用。");

  const createRun = (event) => submit(event, async (form) => {
    if (!evaluatorCanRun) throw new Error("EVALUATOR_UNAVAILABLE: 评测 Dispatcher 未配置或可用性未知，不能创建评测 Run。");
    const created = await api.createEvaluationProductRun({
      suite_id: form.get("suite_id"),
      idempotency_key: runIdempotencyKey.current
    });
    runIdempotencyKey.current = crypto.randomUUID();
    const normalized = normalizeResource(created);
    if (normalized.id) setSelectedRunID(normalized.id);
    return normalized;
  }, "Run 已提交给评测执行端；只有真实 Runner 完成并发布 Evidence 后才形成评测结论。");

  const cancelRun = async () => {
    const target = runDetail || selectedRun;
    if (!target) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const accepted = normalizeResource(await api.cancelEvaluationProductRun(target.id, { expected_revision: target.revision }));
      setRunDetail(accepted);
      await load(false);
      setSelectedRunID(target.id);
      setNotice(`Run ${shortId(target.id)} 取消请求已受理，正在确认子 Run 停止及必要补偿。`);
    } catch (reason) {
      setError(reason.code === "REVISION_OR_IDEMPOTENCY_CONFLICT" ? "Run 已发生状态变化，请刷新后重试。" : reason.message || "取消 Run 失败");
    } finally { setBusy(false); }
  };

  const createReview = (event) => submit(event, (form) => {
    if (!currentPrincipalID) throw new Error("无法读取当前登录身份，不能提交 Evidence 审核。");
    if (!selectedEvidence || !selectedEvidenceRun) throw new Error("请先选择可审核的 Evidence。");
    if (selectedEvidenceRun.created_by === currentPrincipalID) throw new Error("Run 发起人与 Evidence 审核人必须分离。");
    return api.createEvaluationProductReview({
      evidence_id: selectedEvidence.id,
      decision: form.get("decision"),
      reason: String(form.get("reason")).trim()
    });
  }, "Evidence 审核已提交；审核人由当前已认证身份确定。");

  const createBaseline = (event) => submit(event, (form) => {
    const suiteID = String(form.get("suite_id"));
    const existing = baselines.find((baseline) => baseline.id === `baseline.${suiteID}`);
    return api.createEvaluationProductBaseline({
      suite_id: suiteID,
      evidence_id: form.get("evidence_id"),
      expected_revision: existing?.revision || 0
    });
  }, "Baseline 已创建或按 revision CAS 更新。");

  const evaluateGate = (event) => submit(event, async (form) => {
    const result = await api.evaluateEvaluationProductGate({
      evidence_id: form.get("evidence_id"),
      minimum_score: Number(form.get("minimum_score"))
    });
    setGateResult(result);
    return result;
  }, "Gate 判定已返回；UNKNOWN/BLOCKED 均不会被视为通过。");

  if (loading) return <Localized><div className="state-panel"><span className="spinner"/><p>正在读取 Evaluation Product 工作区</p></div></Localized>;

  return <Localized><>
    <div className="page-title">
      <div><p className="eyebrow">版本评测</p><h2>评测工作台</h2><p>Dataset、Suite、Metric、Run、Review、Evidence、Baseline 与 Gate 均通过 evaluation-product 模块管理；身份、作用域与审核人由已认证会话和服务端裁决。</p></div>
      <button className="button secondary" type="button" disabled={busy} onClick={() => load()}>刷新工作区</button>
    </div>
    {notice && <div className="success-banner">{notice}</div>}
    {error && <div className="form-error page-error">{error}</div>}
    <section className="metric-grid">
      <article className="metric violet"><span>Datasets</span><strong>{datasets.length}</strong><small>草稿 / 审核 / 发布</small></article>
      <article className="metric"><span>Suites / Metrics</span><strong>{suites.length} / {metrics.length}</strong><small>只引用已发布版本</small></article>
      <article className="metric cyan"><span>Runs</span><strong>{runs.length}</strong><small>执行状态由 Runner 更新</small></article>
      <article className="metric green"><span>Evidence</span><strong>{evidence.length}</strong><small>真实执行端发布</small></article>
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>Dataset Registry</h3><p className="form-hint">创建者不能审核自己的数据集；审核身份来自当前登录会话。审核与发布是两个 CAS 步骤。</p></div></div>
        <form className="form" onSubmit={createDataset}>
          <div className="inline-form"><label><span>名称</span><input name="name" placeholder="example-regression" maxLength="128" required/></label><label><span>版本</span><input name="version" placeholder="1.0.0" maxLength="64" required/></label></div>
          <label><span>来源类型</span><select name="source_type" defaultValue="manual_gold"><option value="manual_gold">manual_gold · 人工黄金集</option><option value="synthetic_generated">synthetic_generated · 合成生成</option><option value="imported_redacted">imported_redacted · 脱敏导入</option><option value="public_reference">public_reference · 公开参考</option></select></label>
          <label><span>Cases JSON</span><textarea name="cases" defaultValue={initialCases} rows={8} maxLength={1048576} spellCheck="false" required/></label>
          <button className="button primary" disabled={busy}>创建 Dataset draft</button>
        </form>
        {datasets.length > 0 && <div className="simple-table" style={{ marginTop: 18 }}>{datasets.map((dataset) => <div key={dataset.id}>
          <span><b>{dataset.name} · {dataset.version}</b><small>{formatStatus(dataset.status)} · {dataset.source_type} · {dataset.sample_count} cases · r{dataset.revision}</small></span>
          {dataset.status === "draft" && <form className="inline-form" onSubmit={(event) => reviewDataset(event, dataset)}>
            <select name="decision" aria-label={`审核决定 ${dataset.name}`} defaultValue="approved"><option value="approved">批准</option><option value="rejected">拒绝</option></select>
            <input name="reason" aria-label={`审核说明 ${dataset.name}`} placeholder="审核说明" minLength="2" maxLength="1000" required/>
            <button className="button secondary" disabled={busy || !currentPrincipalID || dataset.created_by === currentPrincipalID}>提交审核</button>
          </form>}
          {dataset.status === "approved" && <button className="button secondary" type="button" disabled={busy} onClick={() => publishDataset(dataset)}>发布</button>}
          {dataset.status === "published" && <span className="badge active">已发布</span>}
          {dataset.status === "rejected" && <span className="badge danger">已拒绝</span>}
          {dataset.status === "draft" && dataset.created_by === currentPrincipalID && <small>创建者本人不可审核</small>}
        </div>)}</div>}
      </article>

      <article className="card">
        <div className="card-heading"><div><h3>Metric Registry</h3><p className="form-hint">公式以 JSON 保存；支持类型由服务端白名单校验，发布版本不可变。</p></div><span>{metrics.length} 个</span></div>
        <form className="form" onSubmit={createMetric}>
          <div className="inline-form"><label><span>Metric ID</span><input name="metric_id" placeholder="citation-accuracy" maxLength="128" required/></label><label><span>版本</span><input name="version" placeholder="1.0.0" maxLength="64" required/></label></div>
          <label><span>名称</span><input name="name" placeholder="Citation Accuracy" maxLength="128" required/></label>
          <label><span>类型</span><select name="kind" value={metricKind} onChange={(event) => setMetricKind(event.target.value)}><option value="exact_match">exact_match</option><option value="contains">contains</option><option value="numeric_tolerance">numeric_tolerance</option><option value="recall_at_k">recall_at_k</option><option value="mrr">mrr</option><option value="ndcg">ndcg</option><option value="citation_accuracy">citation_accuracy</option><option value="grounding">grounding</option><option value="custom_deterministic">custom_deterministic</option></select></label>
          {metricKind === "custom_deterministic" && <div className="inline-form"><label><span>签名插件 ID</span><input name="plugin_id" placeholder="risk_score_metric" maxLength="128" required/></label><label><span>插件版本</span><input name="plugin_version" placeholder="1.0.0" maxLength="64" required/></label><label><span>插件 SHA-256</span><input name="plugin_digest" placeholder="64 位十六进制摘要" pattern="[A-Fa-f0-9]{64}" maxLength="64" required/></label></div>}
          <label><span>Formula JSON</span><textarea key={metricKind} name="formula" defaultValue={metricFormulaExamples[metricKind]} rows={5} maxLength={65536} spellCheck="false" required/></label>
          <p className="form-hint">{metricKind === "custom_deterministic" ? "自定义指标仅向隔离 Runner 插件传递 Formula 选出的计数；插件 ID、版本和 SHA-256 必须与已签名注册表完全一致，未匹配会失败关闭。" : metricKind === "grounding" ? "Grounding 输入需在 Agent 输出中包含 citations 与 claims；任何 UNKNOWN/BLOCKED 均不会作为 PASS。" : metricKind === "recall_at_k" || metricKind === "mrr" || metricKind === "ndcg" ? "检索指标从 expected.relevant_ids 与 Agent 输出 retrieved_ids 提取数据，k 必须在 1–1000。" : metricKind === "citation_accuracy" ? "引用指标比较金标 expected.citation_ids 与 Agent 输出 citation_ids 的命中率。" : "公式字段路径必须存在于 Dataset expected 或 Agent 输出中；数值容差须为有限非负数。"}</p>
          <button className="button primary" disabled={busy}>创建 Metric draft</button>
        </form>
        {metrics.length ? <div className="simple-table" style={{ marginTop: 18 }}>{metrics.map((metric) => <div key={metric.id}>
          <span><b>{metric.name} · {metric.version}</b><small>{metric.metric_id} · {metric.kind} · {formatStatus(metric.status || metric.resource_data?.status)}</small></span>
          {(metric.status === "draft") && <button className="button secondary" type="button" disabled={busy} onClick={() => publishMetric(metric)}>发布 Metric</button>}
          {metric.status === "published" && <span className="badge active">已发布</span>}
        </div>)}</div> : <div className="empty"><span>◇</span><b>暂无 Metric</b><p>先创建并发布一个 Metric Version。</p></div>}
      </article>
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>创建 Evaluation Suite</h3><p className="form-hint">Suite 固化已发布 Dataset、Agent ID/Version ID 与 Metric Version IDs 的快照。</p></div></div>
        <form className="form" onSubmit={createSuite}>
          <div className="inline-form"><label><span>名称</span><input name="name" placeholder="example-regression" maxLength="128" required/></label><label><span>版本</span><input name="version" placeholder="1.0.0" maxLength="64" required/></label></div>
          <label><span>Dataset</span><select name="dataset_id" required defaultValue=""><option value="" disabled>选择已发布 Dataset</option>{datasets.filter((item) => item.status === "published").map((item) => <option key={item.id} value={item.id}>{item.name} · {item.version}</option>)}</select></label>
          <div className="inline-form"><label><span>Agent ID</span><input name="agent_id" placeholder="document-assistant" maxLength="128" required/></label><label><span>Agent Version ID</span><input name="agent_version_id" placeholder="published-version-id" maxLength="128" required/></label></div>
          <label><span>已发布 Metrics（可多选）</span><select name="metric_ids" multiple size="4" required>{metrics.filter((item) => item.status === "published").map((item) => <option key={item.id} value={item.id}>{item.metric_id} · {item.version}</option>)}</select></label>
          <button className="button primary" disabled={busy || !datasets.some((item) => item.status === "published") || !metrics.some((item) => item.status === "published")}>冻结 Suite</button>
        </form>
        {suites.length ? <div className="simple-table" style={{ marginTop: 18 }}>{suites.map((suite) => <div key={suite.id}><span><b>{suite.name} · {suite.version}</b><small>Dataset {shortId(suite.dataset_id)} · Agent {suite.agent_id} / {shortId(suite.agent_version_id)} · {suite.metric_ids?.length || 0} Metrics</small></span><code>{shortId(suite.id)}</code></div>)}</div> : <p className="form-hint" style={{ marginTop: 14 }}>需要先发布 Dataset 和至少一个 Metric。</p>}
      </article>

      <article className="card">
        <div className="card-heading"><div><h3>运行评测</h3><p className="form-hint">样本总数由已冻结 Dataset 决定，不接受浏览器提交；请求带幂等键。</p></div></div>
        <form className="form" onSubmit={createRun}>
          <label><span>Suite</span><select name="suite_id" required defaultValue=""><option value="" disabled>选择 Suite</option>{suites.map((suite) => <option key={suite.id} value={suite.id}>{suite.name} · {suite.version}</option>)}</select></label>
          <button className="button primary" disabled={busy || !evaluatorCanRun || !suites.length}>提交给评测 Runner</button>
        </form>
        <div className={`notice ${evaluatorCanRun ? "" : "warning"}`} style={{ marginTop: 16 }}>
          <b>{evaluatorCanRun ? "评测 Dispatcher 已配置" : evaluatorAvailability.configured === false ? "EVALUATOR_UNAVAILABLE" : "评测器可用性未知"}</b>
          <p>{evaluatorCanRun
            ? "Dispatcher 已配置；此状态只表示可接收执行请求，不代表评测已运行或通过。"
            : evaluatorAvailability.configured === false
              ? "当前未配置兼容 Evaluation Product 契约的真实 Dispatcher/Runner，已禁用 Run 提交。"
              : evaluatorAvailability.state === "checking"
                ? "正在检查 Dispatcher 状态；检查完成前按失败关闭，Run 提交保持禁用。"
                : "无法读取或验证 Dispatcher 可用性；状态按未知处理，Run 提交保持禁用。"}
          </p>
          {!evaluatorCanRun && <code>{evaluatorAvailability.reason_code || "EVALUATOR_UNAVAILABLE"}</code>}
          <p>只有执行端完成并发布可信 Evidence 后才能形成评测结论；此界面不会伪造样本评分或 Gate 通过状态。</p>
        </div>
      </article>
    </section>

    <section className="card">
      <div className="card-heading"><div><h3>Run 控制台</h3><p className="form-hint">状态来自执行端持久化记录；取消动作通过 revision CAS 进入 Runner。</p></div><span>{visibleRuns.length}/{runs.length}</span></div>
      <form className="inline-form" onSubmit={(event) => event.preventDefault()}>
        <label><span>状态</span><select value={runFilter} onChange={(event) => setRunFilter(event.target.value)}><option value="">全部</option><option value="queued">queued</option><option value="running">running</option><option value="cancelling">取消确认中</option><option value="succeeded">succeeded</option><option value="failed">failed</option><option value="cancelled">cancelled</option></select></label>
        <label><span>搜索</span><input value={runQuery} onChange={(event) => setRunQuery(event.target.value)} placeholder="Run ID / Suite ID / Agent Version"/></label><span/>
      </form>
      {visibleRuns.length ? <div className="record-list">{visibleRuns.map((run) => <button key={run.id} type="button" className="text-button" style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center", gap: 12, padding: "11px 3px", borderBottom: "1px solid #edf0f5", textAlign: "left" }} onClick={() => setSelectedRunID(run.id)}><span className="record-icon">R</span><span><b>{shortId(run.id, 12)} · Suite {shortId(run.suite_id, 12)}</b><small>{run.completed || 0}/{run.total || 0} completed · failed {run.failed || 0} · r{run.revision || 1} · {formatTime(run.updated_at || run.created_at)}</small></span><span className={`badge ${selectedRunID === run.id ? "info" : statusTone(run.status)}`}>{selectedRunID === run.id ? "已选择" : formatStatus(run.status)}</span></button>)}</div> : <div className="empty"><span>◇</span><b>暂无匹配 Run</b><p>创建 Suite 后可将运行请求交给已配置的真实 Runner。</p></div>}
      {(runDetail || selectedRun) && <div className="version-detail"><div className="version-detail-heading"><span><b>{shortId((runDetail || selectedRun).id, 16)}</b><small>{formatStatus((runDetail || selectedRun).status)} · revision {(runDetail || selectedRun).revision}</small></span><button className="button secondary" type="button" disabled={busy || !["queued", "running"].includes((runDetail || selectedRun).status)} onClick={cancelRun}>取消 Run</button></div><div className="version-detail-grid"><div><b>进度</b><small>{(runDetail || selectedRun).completed || 0} / {(runDetail || selectedRun).total || 0}</small></div><div><b>失败样本</b><small>{(runDetail || selectedRun).failed || 0}</small></div><div><b>执行状态</b><code>{(runDetail || selectedRun).execution_state || "—"}</code></div></div><pre style={{ marginTop: 14, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{stringify(runDetail || selectedRun)}</pre></div>}
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>Evidence / Gate</h3><p className="form-hint">浏览器不能创建 Evidence；UNKNOWN、BLOCKED 或证据不足都不是 PASS。</p></div><span>{evidence.length} 条</span></div>
        {evidence.length ? <div className="record-list">{evidence.map((item) => <div key={item.id}><span className="record-icon">E</span><span><b>{shortId(item.id, 14)} · Run {shortId(item.run_id, 12)}</b><small>{formatStatus(item.status)} · {item.provider_mode || "provider unknown"} · {formatTime(item.created_at)}</small></span><button className="button secondary" type="button" onClick={() => { setSelectedEvidenceID(item.id); setGateResult(null); }}>选择</button></div>)}</div> : <div className="empty"><span>◇</span><b>暂无 Evidence</b><p>评测执行端完成 Run 并以服务身份发布证据后，会显示在这里。</p></div>}
        <form className="inline-form" style={{ marginTop: 16 }} onSubmit={evaluateGate}>
          <label><span>Evidence</span><select name="evidence_id" value={selectedEvidenceID} onChange={(event) => setSelectedEvidenceID(event.target.value)} required><option value="">选择 Evidence</option>{evidence.map((item) => <option key={item.id} value={item.id}>{shortId(item.id)} · {formatStatus(item.status)}</option>)}</select></label>
          <label><span>最低分</span><input name="minimum_score" type="number" min="0" max="1" step="0.01" defaultValue="0.8" required/></label>
          <button className="button primary" disabled={busy || !evidence.length}>评估 Gate</button>
        </form>
        {gateResult && <div className={`notice ${gateResult.state === "PASS" ? "" : "warning"}`}><b>Gate：{gateResult.state}</b><p>{gateResult.reason || "没有可显示的原因"}</p>{gateResult.failures?.length > 0 && <small>{gateResult.failures.join("、")}</small>}</div>}
      </article>

      <article className="card">
        <div className="card-heading"><div><h3>Evidence 人工审核</h3><p className="form-hint">审核人从当前认证身份取得；服务端校验与 Run 发起人的岗位分离。当前身份：{currentPrincipalID || "不可用"}</p></div><span>{reviews.length} 条</span></div>
        <form className="form" onSubmit={createReview}>
          <label><span>Evidence</span><select value={selectedEvidenceID} onChange={(event) => setSelectedEvidenceID(event.target.value)} required><option value="">选择 Evidence</option>{evidence.map((item) => <option key={item.id} value={item.id}>{shortId(item.id)} · Run {shortId(item.run_id)}</option>)}</select></label>
          <div className="inline-form"><label><span>决定</span><select name="decision" defaultValue="approved"><option value="approved">批准</option><option value="needs_changes">需修改</option><option value="rejected">拒绝</option></select></label><label><span>审核意见</span><input name="reason" placeholder="审核意见" minLength="2" maxLength="1000" required/></label></div>
          {selectedEvidenceRun?.created_by === currentPrincipalID && currentPrincipalID && <p className="form-error">当前身份发起了该 Run，不能审核其 Evidence。</p>}
          <button className="button primary" disabled={busy || !currentPrincipalID || !selectedEvidence || !selectedEvidenceRun || selectedEvidenceRun.created_by === currentPrincipalID}>提交审核</button>
        </form>
        {reviews.length > 0 && <div className="simple-table" style={{ marginTop: 16 }}>{reviews.map((review) => <div key={review.id}><span><b>{shortId(review.evidence_id)} · {formatStatus(review.decision)}</b><small>审核人 {review.reviewer_id || "由服务端身份写入"} · {review.reason}</small></span><small>{formatTime(review.created_at)}</small></div>)}</div>}
      </article>
    </section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>Baseline</h3><p className="form-hint">Baseline 只能引用 Gate PASS 且已有批准 Review 的 Evidence；同一 Suite 更新需要显式 revision CAS。</p></div><span>{baselines.length} 条</span></div>
        <form className="form" onSubmit={createBaseline}>
          <label><span>Suite</span><select name="suite_id" required defaultValue=""><option value="" disabled>选择 Suite</option>{suites.map((suite) => <option key={suite.id} value={suite.id}>{suite.name} · {suite.version}</option>)}</select></label>
          <label><span>Evidence</span><select name="evidence_id" required defaultValue=""><option value="" disabled>选择已审核 Evidence</option>{evidence.map((item) => <option key={item.id} value={item.id}>{shortId(item.id)} · {formatStatus(item.status)}</option>)}</select></label>
          <button className="button secondary" disabled={busy || !suites.length || !evidence.length}>创建 / CAS 更新 Baseline</button>
        </form>
        {baselines.length > 0 && <div className="simple-table" style={{ marginTop: 16 }}>{baselines.map((baseline) => <div key={baseline.id}><span><b>{shortId(baseline.suite_id)} · revision {baseline.revision}</b><small>Evidence {shortId(baseline.evidence_id)} · hash {shortId(baseline.evidence_hash || "", 16)}</small></span><span className="badge active">{formatStatus(baseline.status)}</span></div>)}</div>}
      </article>

      <article className="card">
        <div className="card-heading"><div><h3>产品边界 / Evidence 明细</h3><p className="form-hint">这里展示模块保存的快照和证据，不对缺失的评测执行服务做假成功处理。</p></div></div>
        {selectedEvidence ? <><div className="version-detail-grid"><div><b>Run</b><small>{shortId(selectedEvidence.run_id)}</small></div><div><b>样本数</b><small>{selectedEvidence.sample_count || 0}</small></div><div><b>来源</b><small>{selectedEvidence.source_type || "unknown"} / {selectedEvidence.provider_mode || "unknown"}</small></div></div><pre style={{ marginTop: 14, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{stringify(selectedEvidence.resource_data)}</pre></> : <div className="empty"><span>◇</span><b>选择 Evidence 查看明细</b><p>包括指标结果、Grounding、报告 Hash 与 Gate 预判。</p></div>}
      </article>
    </section>
  </></Localized>;
}
