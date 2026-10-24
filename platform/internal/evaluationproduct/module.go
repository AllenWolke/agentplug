package evaluationproduct

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
)

const bodyLimit = MaxBodySize

type Module struct {
	store            Store
	secret           string
	authorizer       Authorizer
	dispatcher       Dispatcher
	inspection       Inspection
	modeAdmission    ModeAdmission
	sourceAuthorizer SourceAuthorizer
	cancellation     CancellationCoordinator
	routingModels    RoutingCaseModelVerifier
	cancelWorker     context.CancelFunc
	cancelWG         sync.WaitGroup
}

func (m *Module) SetModeAdmission(port ModeAdmission)                       { m.modeAdmission = port }
func (m *Module) SetSourceAuthorizer(port SourceAuthorizer)                 { m.sourceAuthorizer = port }
func (m *Module) SetRoutingCaseModelVerifier(port RoutingCaseModelVerifier) { m.routingModels = port }

func NewModule(store Store, internalToken string, authorizer Authorizer, dispatcher Dispatcher) *Module {
	return &Module{store: store, secret: strings.TrimSpace(internalToken), authorizer: authorizer, dispatcher: dispatcher}
}

func (m *Module) Name() string { return "evaluation-product" }

func (m *Module) Start(ctx context.Context) error {
	if m == nil || m.store == nil || m.secret == "" {
		return errors.New("evaluation product store and internal token are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if lifecycle, ok := m.dispatcher.(DispatcherLifecycle); ok {
		if err := lifecycle.Start(ctx); err != nil {
			return fmt.Errorf("start evaluation dispatcher: %w", err)
		}
	}
	if m.cancellation != nil {
		workerCtx, cancel := context.WithCancel(ctx)
		m.cancelWorker = cancel
		m.cancelWG.Add(1)
		go m.reconcileCancellations(workerCtx)
	}
	return nil
}

func (m *Module) Ready() error {
	if m == nil || m.store == nil || m.secret == "" {
		return errors.New("evaluation product dependencies are required")
	}
	if probe, ok := m.dispatcher.(interface{ Ready() error }); ok {
		if err := probe.Ready(); err != nil {
			return errors.New("evaluation worker unavailable")
		}
	}
	return nil
}

func (m *Module) Close(ctx context.Context) error {
	if m.cancelWorker != nil {
		m.cancelWorker()
		done := make(chan struct{})
		go func() { m.cancelWG.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if lifecycle, ok := m.dispatcher.(DispatcherLifecycle); ok {
		return lifecycle.Close(ctx)
	}
	return nil
}

// Handler is mounted below /api/modules/evaluation-product by the Platform
// module gateway. Browser authentication and role checks are revalidated
// against Identity for every request.
// Handler 挂载在 /api/modules/evaluation-product 下；每个浏览器请求都会经 Identity 重验权限。
func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{"/availability", "/agents", "/trajectories/", "/datasets", "/datasets/", "/suites", "/suites/", "/metrics", "/metrics/", "/runs", "/runs/", "/evidence", "/evidence/", "/reviews", "/feedback", "/feedback/", "/baselines", "/gates/evaluate"} {
		mux.HandleFunc(path, m.serve)
	}
	mux.HandleFunc("/model-routing/qualifications:verify", m.serve)
	return mux
}

func (m *Module) serve(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.actor(w, r)
	if !ok {
		return
	}
	path := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	parts := strings.Split(path, "/")
	if path == "model-routing/qualifications:verify" {
		m.verifyRoutingQualification(w, r, actor)
		return
	}
	if parts[0] == "feedback" {
		m.feedback(w, r, actor, parts[1:])
		return
	}
	if len(parts) == 2 && parts[0] == "gates" && parts[1] == "evaluate" {
		m.evaluateGate(w, r, actor)
		return
	}
	if len(parts) == 1 && parts[0] == "availability" {
		m.availability(w, r, actor)
		return
	}
	switch parts[0] {
	case "agents", "trajectories":
		m.inspect(w, r, actor, parts)
	case "datasets":
		m.datasets(w, r, actor, parts[1:])
	case "suites":
		m.suites(w, r, actor, parts[1:])
	case "metrics":
		m.metrics(w, r, actor, parts[1:])
	case "runs":
		m.runs(w, r, actor, parts[1:])
	case "evidence":
		m.evidence(w, r, actor, parts[1:])
	case "reviews":
		m.reviews(w, r, actor)
	case "baselines":
		m.baselines(w, r, actor)
	default:
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
	}
}

// availability reports whether a product-compatible Dispatcher was injected.
// It deliberately does not infer readiness from the legacy scalar evaluation
// Runner: that protocol cannot consume frozen product snapshots or emit the
// product Evidence contract.
// availability 只报告是否注入产品契约兼容的 Dispatcher；不能从旧标量 Runner 推断可用。
func (m *Module) availability(w http.ResponseWriter, r *http.Request, actor Actor) {
	if r.Method != http.MethodGet {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if !m.permit(w, r, actor, ActionRead) {
		return
	}
	status := struct {
		Configured bool         `json:"configured"`
		State      string       `json:"state"`
		ReasonCode string       `json:"reason_code"`
		Worker     *WorkerStats `json:"worker,omitempty"`
	}{Configured: m.dispatcher != nil, State: "configured"}
	if !status.Configured {
		status.State = "unavailable"
		status.ReasonCode = "EVALUATOR_UNAVAILABLE"
	} else if observer, ok := m.dispatcher.(interface{ Stats() WorkerStats }); ok {
		// Expose only aggregate error counters, never case data or tenant identifiers.
		// 只暴露聚合故障计数，不输出评测样本或租户标识。
		stats := observer.Stats()
		status.Worker = &stats
	}
	m.writeJSON(w, http.StatusOK, status)
}

func (m *Module) datasets(w http.ResponseWriter, r *http.Request, actor Actor, parts []string) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		m.list(w, r, actor, KindDataset)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionCreate) {
			return
		}
		var data DatasetData
		if !m.decode(w, r, &data) {
			return
		}
		if err := validateDataset(data); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_DATASET")
			return
		}
		data.SampleCount = len(data.Cases)
		if err := m.authorizeDatasetSources(r.Context(), actor, data); err != nil {
			m.inspectionError(w, err)
			return
		}
		data.ReviewStatus = "pending_human_review"
		data.ContentHash, _ = contentHash(data.Cases)
		m.create(w, r, actor, KindDataset, "draft", data, "")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.get(w, r, actor, KindDataset, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "review" && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionReview) {
			return
		}
		var cmd struct {
			ExpectedRevision uint64 `json:"expected_revision"`
			Decision         string `json:"decision"`
			Reason           string `json:"reason"`
		}
		if !m.decode(w, r, &cmd) {
			return
		}
		row, err := m.store.Get(r.Context(), actor.Scope, KindDataset, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		if !m.protectSources(w, r, actor, row) {
			return
		}
		var data DatasetData
		if json.Unmarshal(row.Data, &data) != nil || cmd.ExpectedRevision != row.Revision || row.Status != "draft" || (cmd.Decision != "approved" && cmd.Decision != "rejected") || len(strings.TrimSpace(cmd.Reason)) < 2 || len(cmd.Reason) > 1000 || actor.PrincipalID == "" || actor.PrincipalID == row.CreatedBy {
			m.writeError(w, http.StatusConflict, "REVIEW_INVALID_OR_SEPARATION_OF_DUTIES")
			return
		}
		if cmd.Decision == "approved" {
			data.ReviewStatus = "approved"
		} else {
			data.ReviewStatus = "rejected"
		}
		reviewedAt := time.Now().UTC()
		data.ReviewerID, data.ReviewReason, data.ReviewedAt = actor.PrincipalID, strings.TrimSpace(cmd.Reason), &reviewedAt
		encoded, _ := json.Marshal(data)
		row.Data, row.Revision, row.UpdatedAt = encoded, row.Revision+1, time.Now().UTC()
		if cmd.Decision == "approved" {
			row.Status = "approved"
		} else {
			row.Status = "rejected"
		}
		if err := m.store.UpdateCAS(r.Context(), actor.Scope, KindDataset, row.ID, cmd.ExpectedRevision, row); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, row)
		return
	}
	if len(parts) == 2 && parts[1] == "publish" && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionPublish) {
			return
		}
		var cmd struct {
			ExpectedRevision uint64 `json:"expected_revision"`
		}
		if !m.decode(w, r, &cmd) {
			return
		}
		row, err := m.store.Get(r.Context(), actor.Scope, KindDataset, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		if !m.protectSources(w, r, actor, row) {
			return
		}
		var data DatasetData
		if json.Unmarshal(row.Data, &data) != nil || row.Revision != cmd.ExpectedRevision || row.Status != "approved" || data.ReviewStatus != "approved" {
			m.writeError(w, http.StatusConflict, "DATASET_NOT_APPROVED_OR_REVISION_CONFLICT")
			return
		}
		row.Status, row.Revision, row.UpdatedAt = "published", row.Revision+1, time.Now().UTC()
		if err := m.store.UpdateCAS(r.Context(), actor.Scope, KindDataset, row.ID, cmd.ExpectedRevision, row); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, row)
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) metrics(w http.ResponseWriter, r *http.Request, actor Actor, parts []string) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		m.list(w, r, actor, KindMetric)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionCreate) {
			return
		}
		var data MetricData
		if !m.decode(w, r, &data) {
			return
		}
		if err := validateMetric(data); err != nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_METRIC")
			return
		}
		data.FormulaHash, _ = contentHash(data.Formula)
		data.Status = "draft"
		id := data.MetricID + "." + data.Version
		m.create(w, r, actor, KindMetric, "draft", data, id)
		return
	}
	if len(parts) == 2 && parts[1] == "publish" && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionPublish) {
			return
		}
		var cmd struct {
			ExpectedRevision uint64 `json:"expected_revision"`
		}
		if !m.decode(w, r, &cmd) {
			return
		}
		row, err := m.store.Get(r.Context(), actor.Scope, KindMetric, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		if row.Revision != cmd.ExpectedRevision || row.Status != "draft" {
			m.writeError(w, http.StatusConflict, "REVISION_CONFLICT")
			return
		}
		var data MetricData
		if json.Unmarshal(row.Data, &data) != nil {
			m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
			return
		}
		data.Status, row.Status = "published", "published"
		row.Revision++
		row.UpdatedAt = time.Now().UTC()
		row.Data, _ = json.Marshal(data)
		if err := m.store.UpdateCAS(r.Context(), actor.Scope, KindMetric, row.ID, cmd.ExpectedRevision, row); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, row)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.get(w, r, actor, KindMetric, parts[0])
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) suites(w http.ResponseWriter, r *http.Request, actor Actor, parts []string) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		m.list(w, r, actor, KindSuite)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionCreate) {
			return
		}
		var data SuiteData
		if !m.decode(w, r, &data) {
			return
		}
		if (data.InstallationID == "") != (data.InstallationRevision == 0) || (data.InstallationID != "" && !validID(data.InstallationID)) || strings.TrimSpace(data.Name) == "" || len(data.Name) > 128 || strings.TrimSpace(data.Version) == "" || !validID(data.DatasetID) || !validID(data.AgentID) || !validID(data.AgentVersionID) || len(data.MetricIDs) == 0 || len(data.MetricIDs) > 100 {
			m.writeError(w, http.StatusBadRequest, "INVALID_SUITE")
			return
		}
		dataset, err := m.store.Get(r.Context(), actor.Scope, KindDataset, data.DatasetID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if dataset.Status != "published" {
			m.writeError(w, http.StatusConflict, "DATASET_NOT_PUBLISHED")
			return
		}
		if !m.protectSources(w, r, actor, dataset) {
			return
		}
		seen := map[string]bool{}
		metricSnapshots := make([]map[string]any, 0, len(data.MetricIDs))
		for _, id := range data.MetricIDs {
			if !validID(id) || seen[id] {
				m.writeError(w, http.StatusBadRequest, "INVALID_SUITE_METRIC")
				return
			}
			seen[id] = true
			metric, e := m.store.Get(r.Context(), actor.Scope, KindMetric, id)
			if e != nil || metric.Status != "published" {
				m.writeError(w, http.StatusConflict, "METRIC_NOT_PUBLISHED")
				return
			}
			var metricData MetricData
			if json.Unmarshal(metric.Data, &metricData) != nil || metricData.FormulaHash == "" {
				m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
				return
			}
			metricSnapshots = append(metricSnapshots, map[string]any{"id": metric.ID, "revision": metric.Revision, "formula_hash": metricData.FormulaHash, "plugin_id": metricData.PluginID, "plugin_version": metricData.PluginVersion, "plugin_digest": metricData.PluginDigest})
		}
		var datasetData DatasetData
		if json.Unmarshal(dataset.Data, &datasetData) != nil {
			m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
			return
		}
		snapshot := map[string]any{"dataset_id": data.DatasetID, "dataset_revision": dataset.Revision, "dataset_hash": datasetData.ContentHash, "agent_id": data.AgentID, "agent_version_id": data.AgentVersionID, "metrics": metricSnapshots}
		if data.InstallationID != "" {
			snapshot["installation_id"] = data.InstallationID
			snapshot["installation_revision"] = data.InstallationRevision
		}
		data.Snapshot, _ = json.Marshal(snapshot)
		data.SnapshotHash, _ = contentHash(snapshot)
		m.create(w, r, actor, KindSuite, "published", data, "")
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.get(w, r, actor, KindSuite, parts[0])
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) runs(w http.ResponseWriter, r *http.Request, actor Actor, parts []string) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		m.list(w, r, actor, KindRun)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionExecute) {
			return
		}
		if m.dispatcher == nil {
			m.writeError(w, http.StatusServiceUnavailable, "EVALUATOR_UNAVAILABLE")
			return
		}
		var data RunData
		if !m.decode(w, r, &data) {
			return
		}
		if !validID(data.SuiteID) || !validID(data.IdempotencyKey) {
			m.writeError(w, http.StatusBadRequest, "INVALID_RUN")
			return
		}
		if data.Mode == "" {
			data.Mode = "offline"
		}
		if (data.Mode != "offline" && data.Mode != "simulation") || (data.Mode == "offline" && data.SimulationProfile != "") || (data.Mode == "simulation" && !validID(data.SimulationProfile)) {
			m.writeError(w, 400, "INVALID_EVALUATION_MODE")
			return
		}
		if data.Limits != nil && (data.Limits.LimitTokens < 0 || data.Limits.LimitMicros < 0) {
			m.writeError(w, 400, "INVALID_EVALUATION_LIMITS")
			return
		}
		if idem, ok := m.store.(IdempotencyStore); ok {
			if existing, lookupErr := idem.FindByIdempotency(r.Context(), actor.Scope, KindRun, data.IdempotencyKey); lookupErr == nil {
				var existingData RunData
				if json.Unmarshal(existing.Data, &existingData) != nil {
					m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
					return
				}
				existingMode := existingData.Mode
				if existingMode == "" {
					existingMode = "offline"
				}
				if existingData.SuiteID != data.SuiteID || !evaluationLimitsEqual(existingData.Limits, data.Limits) || existingMode != data.Mode || existingData.SimulationProfile != data.SimulationProfile {
					m.writeError(w, 409, "IDEMPOTENCY_CONFLICT")
					return
				}
				if existingData.ExecutionState == "dispatch_pending" {
					persisted := existing
					if enqueueErr := m.dispatcher.Enqueue(r.Context(), actor.Scope, existing); enqueueErr == nil {
						existingData.ExecutionState = "queued"
						existing.Data, _ = json.Marshal(existingData)
						expected := existing.Revision
						existing.Revision++
						existing.UpdatedAt = time.Now().UTC()
						if updateErr := m.store.UpdateCAS(r.Context(), actor.Scope, KindRun, existing.ID, expected, existing); updateErr != nil {
							m.writeAcceptedRun(w, r, actor.Scope, persisted)
							return
						}
					} else {
						m.writeJSON(w, http.StatusAccepted, existing)
						return
					}
					m.writeJSON(w, http.StatusAccepted, existing)
				} else {
					m.writeJSON(w, http.StatusOK, existing)
				}
				return
			} else if !errors.Is(lookupErr, ErrNotFound) {
				m.storeError(w, lookupErr)
				return
			}
		}
		suite, err := m.store.Get(r.Context(), actor.Scope, KindSuite, data.SuiteID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if suite.Status != "published" {
			m.writeError(w, http.StatusConflict, "SUITE_NOT_PUBLISHED")
			return
		}
		if !m.protectSources(w, r, actor, suite) {
			return
		}
		var suiteData SuiteData
		if json.Unmarshal(suite.Data, &suiteData) != nil {
			m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
			return
		}
		if data.Mode == "simulation" {
			if m.modeAdmission == nil {
				m.writeError(w, 503, "SIMULATION_PROFILE_UNAVAILABLE")
				return
			}
			if err = m.modeAdmission.AuthorizeEvaluationMode(r.Context(), actor, data, suiteData); err != nil {
				m.inspectionError(w, err)
				return
			}
		}
		data.AgentID, data.AgentVersionID = suiteData.AgentID, suiteData.AgentVersionID
		data.InstallationID, data.InstallationRevision = suiteData.InstallationID, suiteData.InstallationRevision
		data.ExecutionState = "dispatch_pending"
		id, err := newID()
		if err != nil {
			m.writeError(w, http.StatusInternalServerError, "ID_GENERATION_FAILED")
			return
		}
		row := newResource(actor, KindRun, id, "queued", data)
		if err := m.store.Create(r.Context(), row); err != nil {
			m.storeError(w, err)
			return
		}
		persisted := row
		// Enqueue is keyed by the persisted Run ID. A dispatch failure leaves a
		// visible queued record so a retry/reconciler can safely resubmit it.
		// Enqueue 使用已持久化 Run ID 作为幂等键；失败时保留可见队列记录供安全重试。
		if err := m.dispatcher.Enqueue(r.Context(), actor.Scope, row); err == nil {
			data.ExecutionState = "queued"
			row.Revision++
			row.Data, _ = json.Marshal(data)
			row.UpdatedAt = time.Now().UTC()
			if updateErr := m.store.UpdateCAS(r.Context(), actor.Scope, KindRun, row.ID, 1, row); updateErr != nil {
				m.writeAcceptedRun(w, r, actor.Scope, persisted)
				return
			}
		}
		m.writeJSON(w, http.StatusAccepted, row)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.get(w, r, actor, KindRun, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "cases" && r.Method == http.MethodGet {
		m.runCases(w, r, actor, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "status" && r.Method == http.MethodPost {
		if actor.Browser || actor.PrincipalType != "service" {
			m.writeError(w, http.StatusForbidden, "SERVICE_IDENTITY_REQUIRED")
			return
		}
		var cmd struct {
			ExpectedRevision uint64 `json:"expected_revision"`
			Status           string `json:"status"`
			Total            int    `json:"total"`
			Completed        int    `json:"completed"`
			Failed           int    `json:"failed"`
			ErrorCode        string `json:"error_code"`
		}
		if !m.decode(w, r, &cmd) {
			return
		}
		row, err := m.store.Get(r.Context(), actor.Scope, KindRun, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		if row.Revision != cmd.ExpectedRevision || cmd.ExpectedRevision == 0 || cmd.Total < 0 || cmd.Completed < 0 || cmd.Failed < 0 || cmd.Completed+cmd.Failed > cmd.Total || len(cmd.ErrorCode) > 64 {
			m.writeError(w, http.StatusConflict, "REVISION_OR_PROGRESS_CONFLICT")
			return
		}
		allowed := (row.Status == "queued" && cmd.Status == "running") || (row.Status == "running" && (cmd.Status == "succeeded" || cmd.Status == "failed"))
		if !allowed || (cmd.Status == "succeeded" && (cmd.Total == 0 || cmd.Completed != cmd.Total || cmd.Failed != 0)) || (cmd.Status == "failed" && cmd.ErrorCode == "") {
			m.writeError(w, http.StatusConflict, "INVALID_RUN_TRANSITION")
			return
		}
		var data RunData
		if json.Unmarshal(row.Data, &data) != nil {
			m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
			return
		}
		data.ExecutionState, data.Total, data.Completed, data.Failed, data.ErrorCode = cmd.Status, cmd.Total, cmd.Completed, cmd.Failed, cmd.ErrorCode
		row.Data, _ = json.Marshal(data)
		row.Status, row.Revision, row.UpdatedAt = cmd.Status, row.Revision+1, time.Now().UTC()
		if err := m.store.UpdateCAS(r.Context(), actor.Scope, KindRun, row.ID, cmd.ExpectedRevision, row); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusOK, row)
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		if !m.permit(w, r, actor, ActionExecute) {
			return
		}
		var cmd struct {
			ExpectedRevision uint64 `json:"expected_revision"`
		}
		if !m.decode(w, r, &cmd) {
			return
		}
		row, err := m.store.Get(r.Context(), actor.Scope, KindRun, parts[0])
		if err != nil {
			m.storeError(w, err)
			return
		}
		if row.Revision != cmd.ExpectedRevision || (row.Status != "queued" && row.Status != "running") {
			m.writeError(w, http.StatusConflict, "REVISION_CONFLICT")
			return
		}
		row.Status = "cancelling"
		row.Revision++
		row.UpdatedAt = time.Now().UTC()
		var data RunData
		_ = json.Unmarshal(row.Data, &data)
		data.ExecutionState = "cancelling"
		row.Data, _ = json.Marshal(data)
		if err := m.store.UpdateCAS(r.Context(), actor.Scope, KindRun, parts[0], cmd.ExpectedRevision, row); err != nil {
			m.storeError(w, err)
			return
		}
		// Persist the stop intent before interrupting the worker: a synchronous
		// child must distinguish explicit cancellation from process shutdown.
		// 先持久化取消意图，再通知 Worker；子 Run 需据此区分主动取消和进程退出。
		notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
		err = m.dispatcher.Cancel(notifyCtx, actor.Scope, row.ID, row.Revision)
		cancel()
		if err != nil {
			// The durable fence already won. Return its identity for reconciliation
			// rather than pretending to roll back or prompting another mutation.
			// CAS 已生效；返回已接受的状态供查询核对，不伪造回滚或要求重复提交。
			log.Print("evaluation_cancel_signal_pending")
			m.writeJSON(w, http.StatusAccepted, row)
			return
		}
		m.writeJSON(w, http.StatusAccepted, row)
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

// Enqueue may let a worker advance the Run before this handler records queued.
// The Run was already persisted: always acknowledge that identity so clients
// can poll it, even if the current-status read is temporarily unavailable.
func (m *Module) writeAcceptedRun(w http.ResponseWriter, r *http.Request, scope Scope, persisted Resource) {
	if latest, err := m.store.Get(r.Context(), scope, KindRun, persisted.ID); err == nil {
		m.writeJSON(w, http.StatusAccepted, latest)
		return
	}
	m.writeJSON(w, http.StatusAccepted, persisted)
}

func (m *Module) runCases(w http.ResponseWriter, r *http.Request, actor Actor, runID string) {
	if !m.permit(w, r, actor, ActionRead) {
		return
	}
	if !validID(runID) {
		m.writeError(w, http.StatusBadRequest, "INVALID_ID")
		return
	}
	run, err := m.store.Get(r.Context(), actor.Scope, KindRun, runID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if run.Scope != actor.Scope || run.Kind != KindRun || run.ID != runID {
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	caseStore, ok := m.store.(interface {
		ListRunCases(context.Context, Scope, string, int, int) ([]Resource, int64, error)
	})
	if !ok {
		m.writeError(w, http.StatusServiceUnavailable, "EVALUATION_RESULTS_UNAVAILABLE")
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if (key != "page" && key != "page_size") || len(values) != 1 {
			m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
	}
	page, pageSize := 1, 50
	if raw := q.Get("page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100000 {
			m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
		page = n
	}
	if raw := q.Get("page_size"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxPageSize {
			m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
		pageSize = n
	}
	rows, total, err := caseStore.ListRunCases(r.Context(), actor.Scope, runID, page, pageSize)
	if err != nil {
		m.storeError(w, err)
		return
	}
	for _, row := range rows {
		if row.Scope != actor.Scope || row.Kind != KindCaseResult {
			m.writeError(w, http.StatusNotFound, "NOT_FOUND")
			return
		}
		var data CaseResultData
		if json.Unmarshal(row.Data, &data) != nil || data.RunID != runID {
			m.writeError(w, http.StatusInternalServerError, "EVALUATION_RESULT_CORRUPT")
			return
		}
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": total, "page": page, "page_size": pageSize})
}

func (m *Module) evidence(w http.ResponseWriter, r *http.Request, actor Actor, parts []string) {
	if len(parts) == 0 && r.Method == http.MethodGet {
		m.list(w, r, actor, KindEvidence)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		m.get(w, r, actor, KindEvidence, parts[0])
		return
	}
	// Only an authenticated service may publish evidence generated by an actual
	// evaluator. Browser payloads cannot manufacture release evidence.
	if len(parts) == 2 && parts[1] == "publish" && r.Method == http.MethodPost {
		if actor.Browser {
			m.writeError(w, http.StatusForbidden, "SERVICE_IDENTITY_REQUIRED")
			return
		}
		if !m.permit(w, r, actor, ActionCreate) {
			return
		}
		var data EvidenceData
		if !m.decode(w, r, &data) {
			return
		}
		if !validID(data.RunID) || parts[0] != data.RunID || !validID(data.SuiteID) || !validSHA256(data.SuiteSnapshotHash) || !validSHA256(data.DatasetContentHash) || !validID(data.AgentVersionID) || data.SampleCount <= 0 || data.SampleCount > 10000 || !validSHA256(data.ReportHash) || data.ProducedAt.IsZero() || len(data.Metrics) == 0 || len(data.Metrics) > 100 || !data.MetricsPresent || !data.ArtifactsPresent {
			m.writeError(w, http.StatusBadRequest, "INVALID_EVIDENCE")
			return
		}
		run, err := m.store.Get(r.Context(), actor.Scope, KindRun, data.RunID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if run.Status != "succeeded" {
			m.writeError(w, http.StatusConflict, "RUN_NOT_EVIDENCE_ELIGIBLE")
			return
		}
		var runData RunData
		if json.Unmarshal(run.Data, &runData) != nil || runData.SuiteID != data.SuiteID || runData.AgentVersionID != data.AgentVersionID {
			m.writeError(w, http.StatusConflict, "EVIDENCE_RUN_BINDING_MISMATCH")
			return
		}
		datasetSnapshot, verifyErr := verifyEvidenceSnapshot(r.Context(), m.store, actor.Scope, run, data)
		if verifyErr != nil {
			m.writeError(w, http.StatusConflict, "EVIDENCE_SNAPSHOT_INVALID")
			return
		}
		if err := verifyEvidenceCases(r.Context(), m.store, actor.Scope, data, datasetSnapshot.Cases); err != nil {
			m.writeError(w, http.StatusConflict, "EVIDENCE_CASES_INVALID")
			return
		}
		for _, metric := range data.Metrics {
			if !validID(metric.MetricID) || !validMetricStatus(metric.Status) || (metric.Value != nil && (math.IsNaN(*metric.Value) || math.IsInf(*metric.Value, 0))) || (metric.Direction != "higher_is_better" && metric.Direction != "lower_is_better") || math.IsNaN(metric.AllowedRegression) || math.IsInf(metric.AllowedRegression, 0) || metric.AllowedRegression < 0 || metric.AllowedRegression > 1 {
				m.writeError(w, http.StatusBadRequest, "INVALID_METRIC_OUTCOME")
				return
			}
		}
		decision := evaluateEvidence(data, nil, time.Now().UTC())
		data.Gate = decision
		data.Status = "completed"
		id, err := newID()
		if err != nil {
			m.writeError(w, http.StatusInternalServerError, "ID_GENERATION_FAILED")
			return
		}
		row := newResource(actor, KindEvidence, id, "completed", data)
		if err := m.store.Create(r.Context(), row); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, row)
		return
	}
	m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func (m *Module) reviews(w http.ResponseWriter, r *http.Request, actor Actor) {
	if r.Method == http.MethodGet {
		m.list(w, r, actor, KindReview)
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if !m.permit(w, r, actor, ActionReview) {
		return
	}
	var cmd struct {
		EvidenceID string `json:"evidence_id"`
		Decision   string `json:"decision"`
		Reason     string `json:"reason"`
	}
	if !m.decode(w, r, &cmd) {
		return
	}
	if !validID(cmd.EvidenceID) || (cmd.Decision != "approved" && cmd.Decision != "rejected" && cmd.Decision != "needs_changes") || len(strings.TrimSpace(cmd.Reason)) < 2 || len(cmd.Reason) > 1000 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REVIEW")
		return
	}
	evidence, err := m.store.Get(r.Context(), actor.Scope, KindEvidence, cmd.EvidenceID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	var evidenceData EvidenceData
	if json.Unmarshal(evidence.Data, &evidenceData) != nil {
		m.writeError(w, http.StatusInternalServerError, "DATA_CORRUPT")
		return
	}
	run, err := m.store.Get(r.Context(), actor.Scope, KindRun, evidenceData.RunID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if actor.PrincipalID == "" || actor.PrincipalID == run.CreatedBy {
		m.writeError(w, http.StatusForbidden, "SEPARATION_OF_DUTIES_REQUIRED")
		return
	}
	data := ReviewData{EvidenceID: evidence.ID, RunID: run.ID, ReviewerID: actor.PrincipalID, Decision: cmd.Decision, Reason: strings.TrimSpace(cmd.Reason)}
	id, err := newID()
	if err != nil {
		m.writeError(w, http.StatusInternalServerError, "ID_GENERATION_FAILED")
		return
	}
	row := newResource(actor, KindReview, id, cmd.Decision, data)
	if err := m.store.Create(r.Context(), row); err != nil {
		m.storeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusCreated, row)
}

func (m *Module) baselines(w http.ResponseWriter, r *http.Request, actor Actor) {
	if r.Method == http.MethodGet {
		m.list(w, r, actor, KindBaseline)
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if !m.permit(w, r, actor, ActionPublish) {
		return
	}
	var cmd struct {
		SuiteID          string `json:"suite_id"`
		EvidenceID       string `json:"evidence_id"`
		ExpectedRevision uint64 `json:"expected_revision"`
	}
	if !m.decode(w, r, &cmd) {
		return
	}
	if !validID(cmd.SuiteID) || !validID(cmd.EvidenceID) {
		m.writeError(w, http.StatusBadRequest, "INVALID_BASELINE")
		return
	}
	suite, err := m.store.Get(r.Context(), actor.Scope, KindSuite, cmd.SuiteID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	evidence, err := m.store.Get(r.Context(), actor.Scope, KindEvidence, cmd.EvidenceID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	var evidenceData EvidenceData
	if json.Unmarshal(evidence.Data, &evidenceData) != nil || evidenceData.SuiteID != suite.ID || evidenceData.Gate.State != GatePass {
		m.writeError(w, http.StatusConflict, "EVIDENCE_NOT_RELEASEABLE")
		return
	}
	approved, err := m.hasApprovedReview(r.Context(), actor.Scope, evidence.ID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if !approved {
		m.writeError(w, http.StatusConflict, "HUMAN_REVIEW_REQUIRED")
		return
	}
	metricBytes, _ := json.Marshal(evidenceData.Metrics)
	hash := evidenceData.ReportHash
	data := BaselineData{SuiteID: suite.ID, EvidenceID: evidence.ID, EvidenceHash: hash, MetricResults: metricBytes}
	rowID := "baseline." + suite.ID
	current, getErr := m.store.Get(r.Context(), actor.Scope, KindBaseline, rowID)
	if errors.Is(getErr, ErrNotFound) {
		if cmd.ExpectedRevision != 0 {
			m.writeError(w, http.StatusConflict, "REVISION_CONFLICT")
			return
		}
		row := newResource(actor, KindBaseline, rowID, "published", data)
		if err := m.store.Create(r.Context(), row); err != nil {
			m.storeError(w, err)
			return
		}
		m.writeJSON(w, http.StatusCreated, row)
		return
	}
	if getErr != nil {
		m.storeError(w, getErr)
		return
	}
	if current.Revision != cmd.ExpectedRevision || cmd.ExpectedRevision == 0 {
		m.writeError(w, http.StatusConflict, "REVISION_CONFLICT")
		return
	}
	current.Data, _ = json.Marshal(data)
	current.Revision++
	current.UpdatedAt = time.Now().UTC()
	if err := m.store.UpdateCAS(r.Context(), actor.Scope, KindBaseline, rowID, cmd.ExpectedRevision, current); err != nil {
		m.storeError(w, err)
		return
	}
	m.writeJSON(w, http.StatusOK, current)
}

func (m *Module) evaluateGate(w http.ResponseWriter, r *http.Request, actor Actor) {
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	if !m.permit(w, r, actor, ActionGate) {
		return
	}
	var cmd struct {
		EvidenceID   string  `json:"evidence_id"`
		MinimumScore float64 `json:"minimum_score"`
	}
	if !m.decode(w, r, &cmd) {
		return
	}
	if !validID(cmd.EvidenceID) || math.IsNaN(cmd.MinimumScore) || math.IsInf(cmd.MinimumScore, 0) || cmd.MinimumScore < 0 || cmd.MinimumScore > 1 {
		m.writeError(w, http.StatusBadRequest, "INVALID_GATE_REQUEST")
		return
	}
	evidence, err := m.store.Get(r.Context(), actor.Scope, KindEvidence, cmd.EvidenceID)
	if errors.Is(err, ErrNotFound) {
		m.writeJSON(w, http.StatusOK, GateDecision{State: GateUnknown, Reason: "evidence_missing", EvidenceID: cmd.EvidenceID})
		return
	}
	if err != nil {
		m.storeError(w, err)
		return
	}
	var data EvidenceData
	if json.Unmarshal(evidence.Data, &data) != nil {
		m.writeJSON(w, http.StatusOK, GateDecision{State: GateUnknown, Reason: "evidence_corrupt", EvidenceID: evidence.ID})
		return
	}
	run, runErr := m.store.Get(r.Context(), actor.Scope, KindRun, data.RunID)
	if runErr != nil || run.Status != "succeeded" {
		m.writeJSON(w, http.StatusOK, GateDecision{State: GateBlocked, Reason: "run_not_succeeded", EvidenceID: evidence.ID})
		return
	}
	datasetSnapshot, verifyErr := verifyEvidenceSnapshot(r.Context(), m.store, actor.Scope, run, data)
	if verifyErr != nil {
		m.writeJSON(w, http.StatusOK, GateDecision{State: GateBlocked, Reason: "evidence_snapshot_mismatch", EvidenceID: evidence.ID})
		return
	}
	if err := verifyEvidenceCases(r.Context(), m.store, actor.Scope, data, datasetSnapshot.Cases); err != nil {
		m.writeJSON(w, http.StatusOK, GateDecision{State: GateBlocked, Reason: "case_evidence_incomplete_or_invalid", EvidenceID: evidence.ID})
		return
	}
	decision := evaluateEvidence(data, &cmd.MinimumScore, time.Now().UTC())
	if decision.State == GatePass {
		baseline, err := m.store.Get(r.Context(), actor.Scope, KindBaseline, "baseline."+data.SuiteID)
		if errors.Is(err, ErrNotFound) {
			decision = GateDecision{State: GateUnknown, Reason: "baseline_missing", EvidenceID: evidence.ID}
		} else if err != nil {
			m.storeError(w, err)
			return
		} else {
			var baselineData BaselineData
			if json.Unmarshal(baseline.Data, &baselineData) != nil {
				decision = GateDecision{State: GateUnknown, Reason: "baseline_corrupt", EvidenceID: evidence.ID}
			} else if baselineData.EvidenceID == evidence.ID {
				decision = GateDecision{State: GateBlocked, Reason: "candidate_is_baseline", EvidenceID: evidence.ID}
			} else if comparison := compareBaseline(data.Metrics, baselineData.MetricResults, evidence.ID); comparison.State != GatePass {
				decision = comparison
			}
		}
	}
	if decision.State == GatePass {
		approved, err := m.hasApprovedReview(r.Context(), actor.Scope, evidence.ID)
		if err != nil {
			m.storeError(w, err)
			return
		}
		if !approved {
			decision = GateDecision{State: GateBlocked, Reason: "human_review_required", EvidenceID: evidence.ID}
		}
	}
	m.writeJSON(w, http.StatusOK, decision)
}

func evaluateEvidence(data EvidenceData, minimum *float64, now time.Time) GateDecision {
	return evaluateEvidenceMaxAge(data, minimum, now, 24*time.Hour)
}

func evaluateEvidenceMaxAge(data EvidenceData, minimum *float64, now time.Time, maxAge time.Duration) GateDecision {
	failures := []string{}
	if data.Status != "succeeded" && data.Status != "completed" {
		failures = append(failures, "run_not_succeeded")
	}
	if data.SampleCount <= 0 || !data.MetricsPresent || len(data.Metrics) == 0 {
		failures = append(failures, "metrics_or_samples_missing")
	}
	if !data.ArtifactsPresent {
		failures = append(failures, "artifact_missing")
	}
	if data.ProviderMode != "real" || data.SourceType == "mock" || data.SourceType == "replay" || data.SourceType == "synthetic_only" || data.SourceType == "synthetic_generated" {
		failures = append(failures, "untrusted_provenance")
	}
	if len(data.CaseResultIDs) != data.SampleCount {
		failures = append(failures, "case_evidence_incomplete")
	}
	if data.MeasurementProtocol != "" && data.MeasurementProtocol != IndependentVerdictProtocol {
		failures = append(failures, "unknown_measurement_protocol")
	}
	if data.MeasurementProtocol == IndependentVerdictProtocol && data.SourceType != "imported_redacted" {
		failures = append(failures, "untrusted_independent_review_source")
	}
	// Source-bound independent review measures business grounding as ratios.
	// Its own judgement document is not a business answer to ground. Preserve
	// those legacy fields as unknown rather than falsely marking them passed.
	if data.MeasurementProtocol != IndependentVerdictProtocol && (data.CitationGrounding != "passed" || data.DomainGrounding != "passed") {
		failures = append(failures, "grounding_unverified")
	}
	if maxAge < 24*time.Hour || maxAge > 7*24*time.Hour || !validSHA256(data.ReportHash) || !validSHA256(data.SuiteSnapshotHash) || !validSHA256(data.DatasetContentHash) || data.ProducedAt.IsZero() || data.ProducedAt.After(now) || now.Sub(data.ProducedAt) > maxAge {
		failures = append(failures, "evidence_missing_stale_or_future")
	}
	if len(data.Metrics) > 100 {
		failures = append(failures, "metric_limit_exceeded")
	}
	scoreSum := 0.0
	scoreCount := 0
	for _, metric := range data.Metrics {
		if metric.Status != "passed" || metric.Value == nil || math.IsNaN(*metric.Value) || math.IsInf(*metric.Value, 0) {
			failures = append(failures, "metric_unknown_or_blocked:"+metric.MetricID)
			continue
		}
		scoreSum += *metric.Value
		scoreCount++
	}
	if minimum != nil {
		if scoreCount == 0 || scoreSum/float64(scoreCount) < *minimum {
			failures = append(failures, "minimum_score_not_met")
		}
	}
	if len(failures) > 0 {
		return GateDecision{State: GateBlocked, Reason: "release_evidence_incomplete", EvidenceID: data.RunID, Failures: failures}
	}
	return GateDecision{State: GatePass, Reason: "evidence_checks_passed", EvidenceID: data.RunID}
}

func compareBaseline(candidate []MetricOutcome, rawBaseline json.RawMessage, evidenceID string) GateDecision {
	var baseline []MetricOutcome
	if len(rawBaseline) == 0 || json.Unmarshal(rawBaseline, &baseline) != nil || len(baseline) == 0 {
		return GateDecision{State: GateUnknown, Reason: "baseline_metrics_missing_or_invalid", EvidenceID: evidenceID}
	}
	byMetric := make(map[string]MetricOutcome, len(baseline))
	for _, metric := range baseline {
		if metric.MetricID == "" || metric.Value == nil || math.IsNaN(*metric.Value) || math.IsInf(*metric.Value, 0) {
			return GateDecision{State: GateUnknown, Reason: "baseline_metric_value_unknown", EvidenceID: evidenceID}
		}
		byMetric[metric.MetricID] = metric
	}
	failures := make([]string, 0)
	for _, metric := range candidate {
		base, ok := byMetric[metric.MetricID]
		if !ok || base.Direction != metric.Direction || metric.Value == nil {
			return GateDecision{State: GateUnknown, Reason: "baseline_metric_binding_unknown", EvidenceID: evidenceID, Failures: []string{metric.MetricID}}
		}
		tolerance := metric.AllowedRegression
		if metric.Direction == "higher_is_better" && *metric.Value < *base.Value-tolerance {
			failures = append(failures, "regressed:"+metric.MetricID)
		}
		if metric.Direction == "lower_is_better" && *metric.Value > *base.Value+tolerance {
			failures = append(failures, "regressed:"+metric.MetricID)
		}
	}
	if len(failures) > 0 {
		return GateDecision{State: GateBlocked, Reason: "baseline_regression", EvidenceID: evidenceID, Failures: failures}
	}
	return GateDecision{State: GatePass, Reason: "baseline_comparison_passed", EvidenceID: evidenceID}
}

func (m *Module) hasApprovedReview(ctx context.Context, scope Scope, evidenceID string) (bool, error) {
	rows, _, err := m.store.List(ctx, scope, KindReview, 1, MaxPageSize)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		var review ReviewData
		if json.Unmarshal(row.Data, &review) == nil && review.EvidenceID == evidenceID && review.Decision == "approved" {
			return true, nil
		}
	}
	return false, nil
}

func (m *Module) list(w http.ResponseWriter, r *http.Request, actor Actor, kind Kind) {
	if !m.permit(w, r, actor, ActionRead) {
		return
	}
	q := r.URL.Query()
	for key, values := range q {
		if (key != "page" && key != "page_size") || len(values) != 1 {
			m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
	}
	page, pageSize := 1, 50
	if raw := q.Get("page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100000 {
			m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
		page = n
	}
	if raw := q.Get("page_size"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxPageSize {
			m.writeError(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
		pageSize = n
	}
	rows, total, err := m.store.List(r.Context(), actor.Scope, kind, page, pageSize)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if kind == KindDataset {
		for i := range rows {
			var data DatasetData
			if json.Unmarshal(rows[i].Data, &data) == nil {
				data.Cases = nil
				rows[i].Data, _ = json.Marshal(data)
			}
		}
	}
	if kind == KindRun {
		for i := range rows {
			rows[i] = m.projectCancellation(r.Context(), rows[i])
		}
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": total, "page": page, "page_size": pageSize})
}

func (m *Module) get(w http.ResponseWriter, r *http.Request, actor Actor, kind Kind, id string) {
	if !m.permit(w, r, actor, ActionRead) {
		return
	}
	if !validID(id) {
		m.writeError(w, http.StatusBadRequest, "INVALID_ID")
		return
	}
	row, err := m.store.Get(r.Context(), actor.Scope, kind, id)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if kind == KindDataset && !m.protectSources(w, r, actor, row) {
		return
	}
	if kind == KindRun {
		row = m.projectCancellation(r.Context(), row)
	}
	m.writeJSON(w, http.StatusOK, row)
}

func (m *Module) create(w http.ResponseWriter, r *http.Request, actor Actor, kind Kind, status string, data any, id string) {
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			m.writeError(w, http.StatusInternalServerError, "ID_GENERATION_FAILED")
			return
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	row := newResource(actor, kind, id, status, json.RawMessage(encoded))
	if err := validateResource(row); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if err := m.store.Create(r.Context(), row); err != nil {
		m.storeError(w, err)
		return
	}
	response := row
	if kind == KindDataset {
		var stored DatasetData
		if json.Unmarshal(row.Data, &stored) == nil {
			stored.Cases = nil
			response.Data, _ = json.Marshal(stored)
		}
	}
	m.writeJSON(w, http.StatusCreated, response)
}

func newResource(actor Actor, kind Kind, id, status string, data any) Resource {
	encoded, _ := json.Marshal(data)
	now := time.Now().UTC()
	return Resource{ID: id, Kind: kind, Scope: actor.Scope, Status: status, Revision: 1, CreatedBy: actor.PrincipalID, CreatedAt: now, UpdatedAt: now, Data: encoded}
}

func (m *Module) actor(w http.ResponseWriter, r *http.Request) (Actor, bool) {
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if value == "" {
		value = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	if m.secret == "" || len(value) != len(m.secret) || subtle.ConstantTimeCompare([]byte(value), []byte(m.secret)) != 1 {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return Actor{}, false
	}
	scope := Scope{TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")), ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID"))}
	if !scope.valid() {
		m.writeError(w, http.StatusForbidden, "SCOPE_REQUIRED")
		return Actor{}, false
	}
	actor := Actor{Scope: scope, PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")), PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")), Browser: r.Header.Get("X-Browser-Module") == "1"}
	if actor.Browser && (actor.PrincipalType != "user" || actor.PrincipalID == "") {
		m.writeError(w, http.StatusForbidden, "USER_IDENTITY_REQUIRED")
		return Actor{}, false
	}
	return actor, true
}

func (m *Module) permit(w http.ResponseWriter, r *http.Request, actor Actor, action Action) bool {
	if !actor.Browser {
		return true
	}
	if m.authorizer == nil {
		m.writeError(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE")
		return false
	}
	if err := m.authorizer.AuthorizeEvaluation(r.Context(), actor, action, actor.Scope); err != nil {
		if errors.Is(err, ErrForbidden) {
			m.writeError(w, http.StatusForbidden, "FORBIDDEN")
		} else {
			m.writeError(w, http.StatusServiceUnavailable, "IDENTITY_UNAVAILABLE")
		}
		return false
	}
	return true
}

func (m *Module) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return false
	}
	return true
}

func (m *Module) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		m.writeError(w, http.StatusNotFound, "NOT_FOUND")
	case errors.Is(err, ErrConflict):
		m.writeError(w, http.StatusConflict, "REVISION_OR_IDEMPOTENCY_CONFLICT")
	case errors.Is(err, ErrInvalid):
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
	default:
		m.writeError(w, http.StatusInternalServerError, "EVALUATION_STORE_FAILED")
	}
}
func (m *Module) writeError(w http.ResponseWriter, status int, code string) {
	m.writeJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func (m *Module) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(publicEvaluationValue(value))
}

// Coordination leases are worker credentials, never browser response data.
// Preserve stored state and CAS revision; only project a copy for the gateway.
func publicEvaluationValue(value any) any {
	switch v := value.(type) {
	case Resource:
		if v.Kind != KindRun {
			return v
		}
		var data RunData
		if json.Unmarshal(v.Data, &data) != nil {
			v.Data = json.RawMessage(`{}`)
			return v
		}
		data.LeaseOwner, data.LeaseToken = "", ""
		data.LeaseUntil = time.Time{}
		v.Data, _ = json.Marshal(data)
		return v
	case []Resource:
		out := make([]Resource, len(v))
		for i, row := range v {
			out[i] = publicEvaluationValue(row).(Resource)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = publicEvaluationValue(item)
		}
		return out
	default:
		return value
	}
}

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate evaluation resource id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}
func validMetricStatus(value string) bool {
	return value == "passed" || value == "blocked" || value == "unknown"
}

// Checksum is exported for evaluator adapters that need to verify an immutable
// report before publishing it through the service identity route.
func Checksum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

var _ bootstrap.Module = (*Module)(nil)
var _ bootstrap.ReadyModule = (*Module)(nil)
