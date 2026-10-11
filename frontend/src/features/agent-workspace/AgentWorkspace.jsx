import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { ArtifactRenderer } from "../../renderers/ArtifactRenderer.jsx";
import { parseBusinessInput } from "./business-input.js";
import { ToolApproval } from "./ToolApproval.jsx";
import { checkedCancellation, formatCancellationStatus } from "./cancellation-state.js";
import { agentPresentation } from "./catalog-presentation.js";
import { formatStatus, statusTone } from "../../format.js";
import { AnswerText } from "../../renderers/AnswerText.js";
import { BusinessInput } from "./BusinessInput.jsx";
import { exampleInputReady } from "./example-form.js";
import { TechnicalDetails } from "../../components/DisplayNames.jsx";

const METADATA_KEYS = ["operation", "reason", "harness_key", "tool_name", "call_id", "code"];
const SAFE_METADATA_VALUE = /^[A-Za-z0-9_.:-]{1,128}$/;
const MAX_AGENT_EVENT_CURSOR = "9007199254740991";
const RUN_STATUSES = new Set(["accepted", "running", "waiting", "cancelling", "recovering", "succeeded", "failed", "cancelled"]);

function isDecimalCursor(value) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
  const normalized = value.replace(/^0+(?=\d)/, "");
  return normalized.length < MAX_AGENT_EVENT_CURSOR.length ||
    (normalized.length === MAX_AGENT_EVENT_CURSOR.length && normalized <= MAX_AGENT_EVENT_CURSOR);
}

function compareDecimalCursors(left, right) {
  const a = left.replace(/^0+(?=\d)/, "");
  const b = right.replace(/^0+(?=\d)/, "");
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

function safeAgentMetadata(frame, runID) {
  if (!isDecimalCursor(frame?.id) || compareDecimalCursors(frame.id, "0") <= 0 || !frame.data || typeof frame.data !== "object" ||
      Array.isArray(frame.data) || frame.data.run_id !== runID ||
      !Number.isSafeInteger(frame.data.seq) || frame.data.seq < 1 || String(frame.data.seq) !== frame.id.replace(/^0+(?=\d)/, "") ||
      typeof frame.data.event_type !== "string" || !SAFE_METADATA_VALUE.test(frame.data.event_type) ||
      (frame.type !== "message" && frame.type !== frame.data.event_type)) return null;
  const payload = {};
  const source = frame.data.payload;
  if (source && typeof source === "object" && !Array.isArray(source)) {
    for (const key of METADATA_KEYS) {
      const value = source[key];
      if (typeof value === "string" && SAFE_METADATA_VALUE.test(value)) payload[key] = value;
    }
  }
  return { id: frame.id, event_type: frame.data.event_type, payload };
}

export function AgentWorkspace({ agentId }) {
  useLanguage();
  const [catalog, setCatalog] = useState([]);
  const [error, setError] = useState("");
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [activeRunID, setActiveRunID] = useState("");
  const [agentEventLoading, setAgentEventLoading] = useState(false);
  const [agentEventCursor, setAgentEventCursor] = useState("0");
  const [latestAgentMetadata, setLatestAgentMetadata] = useState(null);
  const [agentEventError, setAgentEventError] = useState("");
  const [pendingApproval, setPendingApproval] = useState(null);
  const [approvalReceipt, setApprovalReceipt] = useState(null);
  const [runStatus, setRunStatus] = useState(null);
  const [runStatusLoading, setRunStatusLoading] = useState(false);
  const [runStatusError, setRunStatusError] = useState("");
  const [connectionNotice, setConnectionNotice] = useState("");
  const [cancelling, setCancelling] = useState(false);
  const generationRef = useRef(0);
  const activeRunRef = useRef("");
  const agentIDRef = useRef(agentId);
  agentIDRef.current = agentId;
  const pendingApprovalRef = useRef(null);
  const cancellingRef = useRef(false);
  const submittingRef = useRef(false);
  const agentEventBusyRef = useRef(false);
  const runStatusBusyRef = useRef(false);
  const agentEventCursorRef = useRef("0");
  const activeSessionRef = useRef(null);
  const controllersRef = useRef({ platform: null, agent: null, status: null });

  function clearApprovalState() {
    pendingApprovalRef.current = null;
    setPendingApproval(null);
    setApprovalReceipt(null);
  }

  function clearApprovalForRun(runID) {
    if (pendingApprovalRef.current?.runID === runID) clearApprovalState();
  }

  function ownsApproval(target) {
    return pendingApprovalRef.current === target && generationRef.current === target.generation &&
      activeRunRef.current === target.runID && agentIDRef.current === target.agentID;
  }

  function recordApprovalPause(runID, metadata) {
    const harnessKey = metadata?.payload?.harness_key;
    if (runID !== activeRunRef.current || metadata?.event_type !== "waiting" ||
        metadata?.payload?.reason !== "approval_required" ||
        typeof harnessKey !== "string" || !SAFE_METADATA_VALUE.test(harnessKey)) {
      return false;
    }
    const current = pendingApprovalRef.current;
    if (current?.runID === runID && current.harnessKey === harnessKey &&
        current.eventID === metadata.id && current.generation === generationRef.current) return true;
    const target = {
      runID,
      harnessKey,
      eventID: metadata.id,
      generation: generationRef.current,
      agentID: agentIDRef.current,
      operation: Object.freeze({ run_id: runID, pending_key: harnessKey })
    };
    pendingApprovalRef.current = target;
    setPendingApproval(target);
    setApprovalReceipt(null);
    return true;
  }

  function abortEventReads() {
    controllersRef.current.platform?.abort();
    controllersRef.current.agent?.abort();
    controllersRef.current.status?.abort();
    controllersRef.current = { platform: null, agent: null, status: null };
    agentEventBusyRef.current = false;
    runStatusBusyRef.current = false;
  }

  function resetAgentEvents() {
    agentEventCursorRef.current = "0";
    setAgentEventCursor("0");
    setLatestAgentMetadata(null);
    setAgentEventError("");
    setAgentEventLoading(false);
  }

  function resetRunStatus() {
    setRunStatus(null);
    setRunStatusLoading(false);
    setRunStatusError("");
  }

  useEffect(() => {
    generationRef.current += 1;
    clearApprovalState();
    cancellingRef.current = false;
    setCancelling(false);
    abortEventReads();
    activeRunRef.current = "";
    activeSessionRef.current = null;
    submittingRef.current = false;
    setSubmitting(false);
    setActiveRunID("");
    setResult(null);
    setError("");
    setConnectionNotice("");
    resetRunStatus();
    resetAgentEvents();
    return () => {
      generationRef.current += 1;
      abortEventReads();
      activeRunRef.current = "";
      activeSessionRef.current = null;
      pendingApprovalRef.current = null;
      cancellingRef.current = false;
    };
  }, [agentId]);

  useEffect(() => {
    let active = true;
    api.myAgentCatalog().then((value) => { if (active) setCatalog(asItems(value)); }).catch((reason) => { if (active) setError(reason.message); });
    return () => { active = false; };
  }, []);

  const agent = catalog.find((item) => item.agent_id === agentId);
  const presentation = agentPresentation(agent || { agent_id: agentId });
  const selectedAgentRef = useRef(agent);
  selectedAgentRef.current = agent;
  const cancellationPending = ["cancelling", "cancellation_requested"].includes(result?.status);

  async function readRunStatus() {
    const runID = activeRunRef.current;
    const agentAtStart = agent;
    const sessionAtStart = activeSessionRef.current;
    const generation = generationRef.current;
    const agentID = agentIDRef.current;
    if (!runID || !agentAtStart?.agent_id || !agentAtStart?.version_id || !agentAtStart?.installation_id || runStatusBusyRef.current) return;
    runStatusBusyRef.current = true;
    const controller = new AbortController();
    controllersRef.current.status = controller;
    const isCurrent = () => generationRef.current === generation && activeRunRef.current === runID &&
      agentIDRef.current === agentID && agentID === agentAtStart.agent_id &&
      selectedAgentRef.current?.version_id === agentAtStart.version_id &&
      selectedAgentRef.current?.installation_id === agentAtStart.installation_id;
    setRunStatusLoading(true);
    setRunStatusError("");
    try {
      const snapshot = await api.executionRunStatus(runID, controller.signal);
      if (!isCurrent()) return;
      const scope = snapshot?.scope;
      if (snapshot?.run_id !== runID || !RUN_STATUSES.has(snapshot?.status) ||
          !Number.isSafeInteger(snapshot?.revision) || snapshot.revision < 1 ||
          snapshot.agent_version_id !== agentAtStart.version_id || !scope || typeof scope !== "object" || Array.isArray(scope) ||
          scope.run_id !== runID || scope.agent_id !== agentAtStart.agent_id ||
          scope.agent_version_id !== agentAtStart.version_id || scope.installation_id !== agentAtStart.installation_id ||
          (sessionAtStart && (activeSessionRef.current !== sessionAtStart || sessionAtStart.runID !== runID ||
            sessionAtStart.generation !== generation || sessionAtStart.agentID !== agentID ||
            sessionAtStart.agentVersionID !== agentAtStart.version_id || sessionAtStart.installationID !== agentAtStart.installation_id ||
            scope.session_id !== sessionAtStart.sessionID))) {
        throw new Error("运行状态响应与当前 Run 不匹配，请重新核查");
      }
      const cancellation = checkedCancellation(snapshot.status, snapshot.cancellation);
      setRunStatus({ runID, status: snapshot.status, revision: snapshot.revision, cancellation });
      setRunStatusError("");
      setResult((current) => current?.run_id === runID
        ? { ...current, status: snapshot.status, revision: snapshot.revision, agent_version_id: snapshot.agent_version_id, cancellation,
            ...(snapshot.status === "succeeded" ? {} : { answer: undefined, metadata: undefined }) }
        : current);

      if (snapshot.status === "succeeded" && sessionAtStart && scope.session_id === sessionAtStart.sessionID) {
        const messages = asItems(await api.conversationMessages(sessionAtStart.sessionID, { page: 1, page_size: 100 }));
        if (!isCurrent() || activeSessionRef.current !== sessionAtStart) return;
        const answer = [...messages].reverse().find((item) => item.role === "assistant");
        if (answer) {
          setResult((current) => current?.run_id === runID && isCurrent() && activeSessionRef.current === sessionAtStart
            ? { ...current, status: snapshot.status, revision: snapshot.revision, answer: answer.content, metadata: answer.metadata || {} }
            : current);
        }
      }
      if (["succeeded", "failed", "cancelled"].includes(snapshot.status) && isCurrent()) {
        setConnectionNotice("");
        clearApprovalForRun(runID);
        controllersRef.current.platform?.abort();
        submittingRef.current = false;
        setSubmitting(false);
      }
    } catch (reason) {
      if (isCurrent() && reason?.name !== "AbortError") setRunStatusError(reason.message || "运行状态读取失败，请重试");
    } finally {
      if (controllersRef.current.status === controller) {
        controllersRef.current.status = null;
        runStatusBusyRef.current = false;
        if (isCurrent()) setRunStatusLoading(false);
      }
    }
  }

  async function submit() {
    if (submittingRef.current || cancellingRef.current || cancellationPending || !input.trim() || !agent?.installation_id || !agent?.version_id) return;
    const selectedAgent = agent;
    submittingRef.current = true;
    setSubmitting(true);
    const generation = ++generationRef.current;
    const isCurrent = () => generationRef.current === generation;
    clearApprovalState();
    cancellingRef.current = false;
    setCancelling(false);
    abortEventReads();
    activeRunRef.current = "";
    activeSessionRef.current = null;
    setActiveRunID("");
    setResult(null);
    setError("");
    setConnectionNotice("");
    resetRunStatus();
    resetAgentEvents();
    let platformController = null;
    try {
      const request = parseBusinessInput(input);
      const sessionId = crypto.randomUUID();
      const messageId = crypto.randomUUID();
      const runId = crypto.randomUUID();
      const kind = "qa";
      await api.createConversationSession({ id: sessionId, kind, agent_id: selectedAgent.agent_id, agent_version_id: selectedAgent.version_id, title: input.slice(0, 512), status: "active", can_continue: true });
      if (!isCurrent()) return;
      await api.appendConversationMessage(sessionId, { id: messageId, role: "user", content: input });
      if (!isCurrent()) return;
      const accepted = await api.startConversationRun(sessionId, { run_id: runId, idempotency_key: `workspace:${runId}`, message_id: messageId, request });
      if (!isCurrent()) return;
      const currentRunID = accepted.run_id || runId;
      activeRunRef.current = currentRunID;
      activeSessionRef.current = {
        sessionID: sessionId,
        runID: currentRunID,
        generation,
        agentID: selectedAgent.agent_id,
        agentVersionID: selectedAgent.version_id,
        installationID: selectedAgent.installation_id
      };
      setActiveRunID(currentRunID);
      setResult({ status: "accepted", ...accepted });
      platformController = new AbortController();
      controllersRef.current.platform = platformController;
      try { await api.taskEvents(currentRunID, (event) => {
        if (isCurrent() && activeRunRef.current === currentRunID) {
          setResult((current) => generationRef.current === generation && activeRunRef.current === currentRunID && current
            ? { ...current, latest_event: event } : current);
        }
      }, platformController.signal); } catch (reason) {
        if (reason?.name === "AbortError") throw reason;
        if (isCurrent()) setConnectionNotice("实时事件连接中断，正在核对后台运行状态。无需重复提交。");
      }
      if (!isCurrent() || activeRunRef.current !== currentRunID) return;
      await readAgentEvents();
      if (!isCurrent() || activeRunRef.current !== currentRunID) return;
      if (pendingApprovalRef.current?.runID === currentRunID) {
        setResult({ ...accepted, run_id: currentRunID, status: "waiting" });
        return;
      }
      const messages = asItems(await api.conversationMessages(sessionId, { page: 1, page_size: 100 }));
      if (!isCurrent() || activeRunRef.current !== currentRunID) return;
      const answer = [...messages].reverse().find((item) => item.role === "assistant");
      if (answer) setResult({ ...accepted, status: "completed", answer: answer.content, metadata: answer.metadata || {} });
      await readRunStatus();
    } catch (reason) {
      if (isCurrent() && reason?.name !== "AbortError") setError(reason.message || "Agent 执行失败");
    } finally {
      if (controllersRef.current.platform === platformController) controllersRef.current.platform = null;
      if (isCurrent()) {
        submittingRef.current = false;
        setSubmitting(false);
      }
    }
  }

  async function cancelActiveRun() {
    const runID = activeRunRef.current;
    const runAgentID = agentIDRef.current;
    if (!runID || cancellingRef.current) return;

    // Invalidate pending callbacks and event reads before sending cancellation.
    const generation = ++generationRef.current;
    clearApprovalState();
    if (activeSessionRef.current?.runID === runID) {
      activeSessionRef.current = { ...activeSessionRef.current, generation };
    }
    cancellingRef.current = true;
    setCancelling(true);
    submittingRef.current = false;
    setSubmitting(false);
    abortEventReads();
    resetRunStatus();
    setResult((current) => ({ ...current, run_id: runID, status: "cancellation_requested", answer: undefined, metadata: undefined, cancellation: undefined }));
    try {
      await api.cancelTask(runID);
      if (generationRef.current !== generation || activeRunRef.current !== runID || agentIDRef.current !== runAgentID) return;
      // Retain the exact Run/session/version binding and query authoritative
      // state. Request acceptance never clears a pending business rollback.
      await readRunStatus();
    } catch (reason) {
      if (generationRef.current === generation && activeRunRef.current === runID && agentIDRef.current === runAgentID) {
        setError(reason.message || "取消请求未确认");
      }
    } finally {
      if (generationRef.current === generation && agentIDRef.current === runAgentID) {
        cancellingRef.current = false;
        setCancelling(false);
      }
    }
  }

  useEffect(() => {
    if (!activeRunID || !(["accepted", "running", "waiting", "cancellation_requested", "cancelling", "recovering"].includes(result?.status) || result?.status === "succeeded" && !result?.answer)) return;
    const timer = setInterval(() => { void readRunStatus(); }, 2000);
    return () => clearInterval(timer);
  }, [activeRunID, result?.status, !!result?.answer, agent?.version_id, agent?.installation_id]);

  async function readAgentEvents() {
    const runID = activeRunRef.current;
    if (!runID || agentEventBusyRef.current) return;
    agentEventBusyRef.current = true;
    const generation = generationRef.current;
    const cursorAtStart = agentEventCursorRef.current;
    const controller = new AbortController();
    controllersRef.current.agent = controller;
    const isCurrent = () => generationRef.current === generation && activeRunRef.current === runID;
    let nextCursor = cursorAtStart;
    setAgentEventLoading(true);
    setAgentEventError("");
    try {
      await api.agentTaskEvents(runID, (frame) => {
        if (!isCurrent()) return;
        if (frame.type === "stream_error") {
          setAgentEventError("Agent 事件流暂时无法确认，请稍后重新读取。");
          return;
        }
        const metadata = safeAgentMetadata(frame, runID);
        if (!metadata || compareDecimalCursors(metadata.id, nextCursor) <= 0) {
          setAgentEventError("Agent 事件响应无法确认，请重新读取。");
          controller.abort();
          return;
        }
        nextCursor = metadata.id;
        agentEventCursorRef.current = nextCursor;
        setAgentEventCursor(nextCursor);
        setLatestAgentMetadata(metadata);
        if (metadata.event_type === "waiting") {
          if (!recordApprovalPause(runID, metadata)) clearApprovalForRun(runID);
        } else if (["started", "cancelled", "completed", "failed"].includes(metadata.event_type)) {
          clearApprovalForRun(runID);
        }
      }, controller.signal, cursorAtStart);
    } catch (reason) {
      if (isCurrent() && reason?.name !== "AbortError") {
        setAgentEventError("Agent 事件读取失败，请稍后重试。");
      }
    } finally {
      if (controllersRef.current.agent === controller) {
        controllersRef.current.agent = null;
        agentEventBusyRef.current = false;
        if (isCurrent()) setAgentEventLoading(false);
      }
    }
  }

  return <Localized><section className="card agent-workspace" data-agent-id={agentId}>
    <div className="card-heading"><div><h2>{presentation.name}</h2><p className="form-hint">{presentation.description}</p></div><span>版本 {agent?.semantic_version || "—"}</span></div>
    {error && <div className="form-error" role="alert">{error}</div>}
    {connectionNotice && <div className="notice" role="status">{connectionNotice}</div>}
    <BusinessInput agentId={agentId} presentation={presentation} input={input} onChange={setInput} busy={submitting || cancelling || cancellationPending}/>
    {!agent && <p className="form-hint">该 Agent 未安装到当前应用，或当前用户没有 discover/run 授权。</p>}
    <button className="button primary" disabled={submitting || cancelling || cancellationPending || !exampleInputReady(agentId, input) || !agent?.installation_id || !agent?.version_id} onClick={submit}>{submitting ? "运行中…" : "开始处理任务"}</button>
    {activeRunID && <section className="agent-event-metadata" aria-label="Agent 元数据事件">
      <div className="inline-actions">
        <button type="button" className="button secondary" disabled={agentEventLoading || cancelling} onClick={readAgentEvents}>{agentEventLoading ? "读取中…" : "读取 Agent 事件"}</button>
        <button type="button" className="button secondary" disabled={runStatusLoading || cancelling} onClick={readRunStatus}>{runStatusLoading ? "读取中…" : "查看运行状态"}</button>
        <button type="button" className="button secondary" disabled={cancelling || cancellationPending || ["succeeded", "completed", "failed", "cancelled"].includes(runStatus?.status || result?.status) || agent?.permissions?.cancel === false} onClick={cancelActiveRun}>{cancelling ? "正在取消…" : "取消当前运行"}</button>
        <TechnicalDetails values={{ "运行编号": activeRunID, "事件游标": agentEventCursor }}/>
      </div>
      {runStatus && runStatus.runID === activeRunID && <p className="form-hint" role="status">运行状态：{formatCancellationStatus(runStatus.status, runStatus.cancellation)} · 状态版本 {runStatus.revision}</p>}
      {runStatusError && <p className="form-error" role="status">{runStatusError}</p>}
      {agentEventError && <p className="form-error" role="status">{agentEventError}</p>}
      {latestAgentMetadata && <details><summary>查看最近一条 Agent 事件</summary><pre className="artifact-preview" aria-label="最近一条 Agent 元数据事件" translate="no">{JSON.stringify(latestAgentMetadata, null, 2)}</pre></details>}
      {pendingApproval && pendingApprovalRef.current === pendingApproval && pendingApproval.runID === activeRunID &&
        pendingApproval.generation === generationRef.current && pendingApproval.agentID === agentId && <>
          <ToolApproval
            key={`${pendingApproval.agentID}:${pendingApproval.runID}:${pendingApproval.harnessKey}:${pendingApproval.eventID}`}
            operation={pendingApproval.operation}
            onApproved={(receipt) => {
              if (ownsApproval(pendingApproval)) {
                // Keep only non-secret receipt fields in memory; the component drops confirmation tokens.
                setApprovalReceipt({
                  runID: pendingApproval.runID,
                  harnessKey: pendingApproval.harnessKey,
                  status: "approved",
                  ...(typeof receipt?.approval_id === "string" ? { approvalID: receipt.approval_id } : {}),
                  ...(receipt?.expires_at !== undefined ? { expiresAt: receipt.expires_at } : {})
                });
              }
            }}
            onRevoked={() => {
              if (ownsApproval(pendingApproval)) setApprovalReceipt(null);
            }}
            onResumeRequested={(receipt) => {
              if (ownsApproval(pendingApproval) && receipt?.resume_requested === true &&
                  receipt.run_id === pendingApproval.runID && Number.isSafeInteger(receipt.revision) && receipt.revision > 0) {
                setApprovalReceipt({
                  runID: pendingApproval.runID,
                  status: "resume_requested",
                  revision: receipt.revision
                });
              }
            }}
            onClose={() => {
              if (ownsApproval(pendingApproval)) clearApprovalState();
            }}
          />
          {approvalReceipt?.runID === pendingApproval.runID && (approvalReceipt.status === "resume_requested"
            ? <p className="form-hint" role="status">已提交继续请求，可查看运行状态了解进展 · Run ID：{approvalReceipt.runID} · revision：{approvalReceipt.revision}</p>
            : approvalReceipt.harnessKey === pendingApproval.harnessKey && <p className="form-hint" role="status">操作已批准。{approvalReceipt.approvalID ? `批准编号：${approvalReceipt.approvalID}。` : ""}{approvalReceipt.expiresAt ? ` 有效期至 ${approvalReceipt.expiresAt}。` : ""}</p>)}
        </>}
    </section>}
    {result && <RunResult result={result}/>}
  </section></Localized>;
}

function RunResult({ result }) {
  useLanguage();
  let output = result.answer;
  if (typeof output === "string") { try { output = JSON.parse(output); } catch {} }
  const answer = typeof output === "string" ? output : typeof output?.answer === "string" ? output.answer : typeof output?.draft === "string" ? output.draft : "";
  return <Localized><section className="run-result" aria-label="运行结果" aria-live="polite"><div className="card-heading"><h3>运行结果</h3><span className={`badge ${statusTone(result.status)}`}>{formatStatus(result.status)}</span></div>
    {answer ? <div className="run-answer"><AnswerText text={answer}/></div> : <p className="form-hint">{result.status === "failed" ? "本次运行失败，可查看运行状态与详细记录了解原因。" : ["accepted", "running"].includes(result.status) ? "请求已受理，正在等待 Agent 返回结果。" : "本次运行尚无可展示的回答，可查看运行状态了解进展。"}</p>}
    <details><summary>查看完整返回数据与运行编号</summary><ArtifactRenderer artifact={result}/></details>
  </section></Localized>;
}
