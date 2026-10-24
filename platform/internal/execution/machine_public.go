package execution

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type machineStartRunRequest struct {
	ModelSelection policyasset.ModelSelection `json:"model_selection,omitempty"`
	SessionID      string                     `json:"session_id"`
	IdempotencyKey string                     `json:"idempotency_key"`
	Input          map[string]any             `json:"input"`
}

type machineCancelRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type machineResumeRequest struct {
	Input map[string]any `json:"input"`
}

type machineRunResponse struct {
	RunID          string `json:"run_id"`
	Status         string `json:"status"`
	Revision       uint64 `json:"revision"`
	AgentVersionID string `json:"agent_version_id"`
	Replayed       bool   `json:"replayed,omitempty"`
}

type machineRunRoute struct {
	Action string
	RunID  string
	Op     string
}

func parseMachineRunRoute(r *http.Request) (machineRunRoute, int) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if path == "agent-runs" {
		if r.Method == http.MethodPost {
			return machineRunRoute{Action: "run"}, http.StatusOK
		}
		return machineRunRoute{}, http.StatusMethodNotAllowed
	}
	if len(parts) < 2 || parts[0] != "agent-runs" || strings.TrimSpace(parts[1]) == "" {
		return machineRunRoute{}, http.StatusNotFound
	}
	if len(parts) == 2 && r.Method == http.MethodGet {
		return machineRunRoute{Action: "read", RunID: parts[1]}, http.StatusOK
	}
	if len(parts) != 3 {
		return machineRunRoute{}, http.StatusNotFound
	}
	switch parts[2] {
	case "events":
		if r.Method == http.MethodGet {
			return machineRunRoute{Action: "events", RunID: parts[1], Op: "events"}, http.StatusOK
		}
	case "cancel":
		if r.Method == http.MethodPost {
			return machineRunRoute{Action: "cancel", RunID: parts[1], Op: "cancel"}, http.StatusOK
		}
	case "resume":
		if r.Method == http.MethodPost {
			return machineRunRoute{Action: "resume", RunID: parts[1], Op: "resume"}, http.StatusOK
		}
	}
	return machineRunRoute{}, http.StatusMethodNotAllowed
}

func machineBearer(r *http.Request) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(r.Header.Get("Authorization")))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func (m *Module) machineRuns(w http.ResponseWriter, r *http.Request) { m.machineRun(w, r) }

// machineRun is the only public machine-to-Agent execution surface. It derives
// every trusted field from Identity and Catalog; callers can submit only a
// session, idempotency key and business payload.
// machineRun 是机器身份调用 Agent 的唯一公开执行面；可信字段来自 Identity/Catalog，调用方只能提交会话、幂等键和业务输入。
func (m *Module) machineRun(w http.ResponseWriter, r *http.Request) {
	route, routeStatus := parseMachineRunRoute(r)
	if routeStatus != http.StatusOK {
		m.writeError(w, routeStatus, "INVALID_REQUEST")
		return
	}
	if m.machineAuth == nil {
		m.writeError(w, http.StatusServiceUnavailable, "MACHINE_IDENTITY_UNAVAILABLE")
		return
	}
	rawToken, ok := machineBearer(r)
	if !ok {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	access, err := m.machineAuth.AuthenticateMachine(r.Context(), rawToken, r.RemoteAddr, route.Action)
	if err != nil || access.Scope.Validate() != nil || access.Scope.PrincipalType != "service_principal" || access.Scope.AgentInstanceID == "" || access.AuthorizationEpoch == 0 {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if route.RunID == "" {
		m.startMachineRun(w, r, access)
		return
	}
	run, err := m.store.Get(route.RunID)
	if err != nil || !machineScopeOwnsRun(access.Scope, run.Scope) {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if route.Action == "resume" && run.Status == platformruntime.StatusWaiting {
		outcome, outcomeErr := m.store.GetOutcome(run.ID)
		if outcomeErr != nil || outcome.Revision != run.Revision {
			m.writeError(w, http.StatusServiceUnavailable, "REVIEW_STATE_UNAVAILABLE")
			return
		}
		var waiting struct {
			Stage string `json:"stage"`
		}
		if json.Unmarshal(outcome.OutputJSON, &waiting) != nil {
			m.writeError(w, http.StatusServiceUnavailable, "REVIEW_STATE_UNAVAILABLE")
			return
		}
		if waiting.Stage == "waiting_review" {
			m.writeError(w, http.StatusForbidden, "HUMAN_REVIEW_REQUIRED")
			return
		}
	}
	if err := m.machineAuth.AuthorizeMachineRun(r.Context(), rawToken, r.RemoteAddr, route.Action, run.Scope, run.ID); err != nil {
		m.writeError(w, http.StatusForbidden, "MACHINE_ACCESS_DENIED")
		return
	}
	switch route.Op {
	case "":
		m.writeJSON(w, http.StatusOK, machineRunResponseFrom(run, false))
	case "events":
		// Keep the verified bearer private in a callback, not client-controlled
		// headers. Recheck token, credential, principal and Grant for each event.
		check := func(ctx context.Context) error {
			current, err := m.machineAuth.AuthenticateMachine(ctx, rawToken, r.RemoteAddr, route.Action)
			if err != nil || current.AuthorizationEpoch == 0 || current.Scope.Validate() != nil || current.Scope.PrincipalType != "service_principal" || !machineScopeOwnsRun(current.Scope, run.Scope) {
				return errMachineStreamDenied
			}
			return m.machineAuth.AuthorizeMachineRun(ctx, rawToken, r.RemoteAddr, route.Action, run.Scope, run.ID)
		}
		streamRequest := r.WithContext(context.WithValue(r.Context(), machineStreamCheckKey{}, check))
		m.eventsSSE(w, withMachineRunScope(streamRequest, run.Scope), route.RunID)
	case "cancel":
		var request machineCancelRequest
		if err := decodeJSON(r, &request); err != nil || request.ExpectedRevision == 0 {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		body, _ := json.Marshal(cancelRequest{Scope: scopeFromDomain(run.Scope), ExpectedRevision: request.ExpectedRevision})
		m.cancel(w, withInternalRequest(r, m.internalToken, body), route.RunID)
	case "resume":
		var request machineResumeRequest
		if err := decodeJSON(r, &request); err != nil || request.Input == nil {
			m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		body, _ := json.Marshal(resumeRequest{Scope: scopeFromDomain(run.Scope), Input: request.Input})
		m.resume(w, withInternalRequest(r, m.internalToken, body), route.RunID)
	default:
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	}
}

type machineStreamCheckKey struct{}

var errMachineStreamDenied = errors.New("machine stream access denied")

func checkMachineStreamAccess(ctx context.Context) error {
	if check, ok := ctx.Value(machineStreamCheckKey{}).(func(context.Context) error); ok {
		return check(ctx)
	}
	return nil
}

func (m *Module) startMachineRun(w http.ResponseWriter, r *http.Request, access MachineAccess) {
	if m.machineTarget == nil {
		m.writeError(w, http.StatusServiceUnavailable, "AGENT_TARGET_UNAVAILABLE")
		return
	}
	var request machineStartRunRequest
	if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.SessionID) == "" || len(request.SessionID) > 128 ||
		strings.TrimSpace(request.IdempotencyKey) == "" || len(request.IdempotencyKey) > 200 || request.Input == nil || request.ModelSelection.Validate() != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if _, reserved := request.Input["policy_snapshot"]; reserved {
		m.writeError(w, http.StatusBadRequest, "PLATFORM_MANAGED_INPUT")
		return
	}
	inputBytes, err := json.Marshal(request.Input)
	if err != nil || len(inputBytes) == 0 || len(inputBytes) > 1<<20 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	base := access.Scope
	target, err := m.machineTarget.ResolveMachineTarget(r.Context(), base)
	if err != nil || target.InstallationID != base.AgentInstanceID || target.AgentID == "" || target.VersionID == "" ||
		strings.TrimSpace(target.InputSchemaURI) == "" || strings.TrimSpace(target.Endpoint) == "" || target.Revision == 0 {
		m.writeError(w, http.StatusForbidden, "AGENT_TARGET_UNAVAILABLE")
		return
	}
	if m.machinePolicy == nil || m.machineSigner == nil {
		m.writeError(w, http.StatusServiceUnavailable, "RUN_PREPARATION_UNAVAILABLE")
		return
	}
	runID, err := randomHexID("run_", 16)
	if err != nil {
		m.writeError(w, http.StatusInternalServerError, "EXECUTION_UNAVAILABLE")
		return
	}
	traceID, err := randomHexID("", 16)
	if err != nil {
		m.writeError(w, http.StatusInternalServerError, "EXECUTION_UNAVAILABLE")
		return
	}
	scope := base
	scope.AgentID = target.AgentID
	scope.InstallationID = target.InstallationID
	scope.AgentVersionID = target.VersionID
	scope.SessionID = strings.TrimSpace(request.SessionID)
	scope.RunID = runID
	scope.AuthorizationEpoch = access.AuthorizationEpoch
	scope.TraceID = traceID
	if m.authorizationEpoch != nil {
		epoch, err := m.authorizationEpoch(r.Context(), scope, "run")
		if err != nil || epoch == 0 {
			m.writeError(w, http.StatusForbidden, "PERMISSION_DENIED")
			return
		}
		scope.AuthorizationEpoch = epoch
	}
	if err := scope.ValidateTrusted(); err != nil {
		m.writeError(w, http.StatusBadRequest, "SCHEMA_VALIDATION_FAILED")
		return
	}
	policy, err := m.machinePolicy.ResolveAgentPolicy(r.Context(), scope, target.VersionID)
	if err != nil || policy == nil {
		m.writeError(w, http.StatusServiceUnavailable, "POLICY_SNAPSHOT_UNAVAILABLE")
		return
	}
	if request.ModelSelection.EffectiveMode() == "automatic" {
		var model policyasset.ModelPolicy
		raw, err := json.Marshal(policy["model"])
		if m.modelSelections == nil || err != nil || json.Unmarshal(raw, &model) != nil || model.Routing == nil || model.ValidateRouting() != nil {
			m.writeError(w, http.StatusConflict, "MODEL_ROUTING_UNAVAILABLE")
			return
		}
	}
	// The platform replaces no client policy fields because the public contract
	// rejects policy_snapshot above. This makes the published policy resolver
	// the sole policy authority for machine identities as well as browser Runs.
	// 公共合同已拒绝调用方传入策略快照；机器身份和浏览器 Run 共用平台已发布策略解析器。
	input := make(map[string]any, len(request.Input)+1)
	for key, value := range request.Input {
		input[key] = value
	}
	input["policy_snapshot"] = policy
	executeRequest := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Scope: contract.ScopeKey{
			TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID,
			RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID,
			InstallationID: scope.InstallationID,
		},
		Operation: "run", IdempotencyKey: strings.TrimSpace(request.IdempotencyKey),
		InputSchema: target.InputSchemaURI, Input: input,
	}
	token, err := m.machineSigner.Sign(r.Context(), scope, executeRequest)
	if err != nil || strings.TrimSpace(token) == "" {
		m.writeError(w, http.StatusServiceUnavailable, "CONTEXT_SIGNING_UNAVAILABLE")
		return
	}
	executeRequest.ContextToken = token
	requestBytes, err := json.Marshal(executeRequest)
	if err != nil || len(requestBytes) > 1<<20 {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	fingerprintScope := scope
	fingerprintScope.RunID = ""
	fingerprintScope.TraceID = ""
	fingerprintPayload, err := json.Marshal(struct {
		Scope       sharedkernel.Scope `json:"scope"`
		InputSchema string             `json:"input_schema"`
		Input       map[string]any     `json:"input"`
	}{Scope: fingerprintScope, InputSchema: target.InputSchemaURI, Input: input})
	if err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	fingerprint := sha256.Sum256(fingerprintPayload)
	if request.ModelSelection.EffectiveMode() == "automatic" {
		fingerprint = sha256.Sum256([]byte("run-model-selection/v1:automatic:" + hex.EncodeToString(fingerprint[:])))
	}
	if m.modelSelections != nil {
		policyHash, _ := policy["content_hash"].(string)
		binding := policyasset.ModelSelectionBinding{Selection: request.ModelSelection, PolicySHA256: policyHash, CommandFingerprint: hex.EncodeToString(fingerprint[:])}
		if binding.Selection.EffectiveMode() == "automatic" {
			var model policyasset.ModelPolicy
			raw, marshalErr := json.Marshal(policy["model"])
			task, taskErr := json.Marshal(request.Input)
			if marshalErr != nil || taskErr != nil || json.Unmarshal(raw, &model) != nil || model.Routing == nil {
				m.writeError(w, http.StatusBadRequest, "INVALID_ROUTING_TASK")
				return
			}
			binding, taskErr = policyasset.BindRoutingTask(binding, task, *model.Routing)
			if taskErr != nil {
				m.writeError(w, http.StatusBadRequest, "INVALID_ROUTING_TASK")
				return
			}
		}
		if err := m.modelSelections.BindModelSelection(r.Context(), scope, binding); err != nil {
			m.writeError(w, http.StatusConflict, "MODEL_SELECTION_BINDING_FAILED")
			return
		}
	}
	createdID, err := m.startRun(r.Context(), scope, runID, strings.TrimSpace(request.IdempotencyKey), hex.EncodeToString(fingerprint[:]), target.Endpoint, requestBytes, "")
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	created, err := m.store.Get(createdID)
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	response := machineRunResponseFrom(created, createdID != runID)
	status := http.StatusAccepted
	if response.Replayed {
		status = http.StatusOK
	}
	m.writeJSON(w, status, response)
}

func machineRunResponseFrom(run platformruntime.Run, replayed bool) machineRunResponse {
	return machineRunResponse{RunID: run.ID, Status: string(run.Status), Revision: run.Revision, AgentVersionID: run.AgentVersionID, Replayed: replayed}
}

func machineScopeOwnsRun(caller, run sharedkernel.Scope) bool {
	return caller.TenantID == run.TenantID && caller.DepartmentID == run.DepartmentID && caller.ApplicationID == run.ApplicationID &&
		caller.AgentInstanceID == run.AgentInstanceID && caller.PrincipalID == run.PrincipalID && caller.PrincipalType == run.PrincipalType
}

func withMachineRunScope(r *http.Request, scope sharedkernel.Scope) *http.Request {
	return withScopeHeaders(r, scope)
}

func withInternalRequest(r *http.Request, internalToken string, body []byte) *http.Request {
	cloned := r.Clone(r.Context())
	cloned.Header = r.Header.Clone()
	cloned.Header.Set("Authorization", "Bearer "+internalToken)
	cloned.Body = http.NoBody
	if len(body) > 0 {
		cloned.Body = io.NopCloser(bytes.NewReader(body))
	}
	return cloned
}

func withScopeHeaders(r *http.Request, scope sharedkernel.Scope) *http.Request {
	cloned := r.Clone(r.Context())
	cloned.Header = r.Header.Clone()
	cloned.Header.Set("X-Tenant-ID", scope.TenantID)
	cloned.Header.Set("X-Department-ID", scope.DepartmentID)
	cloned.Header.Set("X-Application-ID", scope.ApplicationID)
	cloned.Header.Set("X-Agent-Instance-ID", scope.AgentInstanceID)
	cloned.Header.Set("X-Agent-ID", scope.AgentID)
	cloned.Header.Set("X-Principal-ID", scope.PrincipalID)
	cloned.Header.Set("X-Principal-Type", scope.PrincipalType)
	cloned.Header.Set("X-Installation-ID", scope.InstallationID)
	cloned.Header.Set("X-Agent-Version-ID", scope.AgentVersionID)
	cloned.Header.Set("X-Session-ID", scope.SessionID)
	cloned.Header.Set("X-Authorization-Epoch", fmt.Sprintf("%d", scope.AuthorizationEpoch))
	cloned.Header.Set("X-Trace-ID", scope.TraceID)
	return cloned
}

func randomHexID(prefix string, byteCount int) (string, error) {
	if byteCount < 16 || byteCount > 32 {
		return "", errors.New("invalid identifier size")
	}
	value := make([]byte, byteCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}
