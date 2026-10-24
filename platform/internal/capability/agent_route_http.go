package capability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type agentRouteContextKey struct{}

// Composition Port: callers cannot install this private context through JSON.
func AgentCoordinationAuthority(ctx context.Context, scope sharedkernel.Scope) (sharedkernel.ExecutionLeaseBinding, policyasset.Snapshot, error) {
	bound, ok := ctx.Value(agentRouteContextKey{}).(skillRuntimeContext)
	if !ok || bound.Scope != scope || bound.Check == nil {
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, agentcoordination.RouteReasonParentBoundContext, nil)
	}
	if err := bound.Check(ctx); err != nil {
		if budgetAdmissionDeferred(err) {
			return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, err
		}
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, agentcoordination.RouteReasonParentLiveCheck, nil)
	}
	if bound.Policy.Runtime.Delegation == nil || bound.Policy.Runtime.Delegation.Validate() != nil {
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, agentcoordination.RouteReasonParentPolicy, nil)
	}
	return bound.Lease, bound.Policy, nil
}

func logAgentCoordinationDenial(runID, traceID string, err error) {
	if stage, reason, classified := agentcoordination.RouteErrorClassification(err); classified {
		log.Printf("agent_coordination_denied run_id=%q trace_id=%q stage=%s reason=%s", runID, traceID, stage, reason)
		return
	}
	if errors.Is(err, agentcoordination.ErrDenied) {
		log.Printf("agent_coordination_denied run_id=%q trace_id=%q stage=unclassified reason=denied", runID, traceID)
	}
}

func (m *Module) SetAgentRouter(router *agentcoordination.Router) { m.agentRouter = router }
func (m *Module) routeAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED", "POST required", "")
		return
	}
	if r.URL.Path == "/internal/agent/cancel" {
		m.cancelAgentChild(w, r)
		return
	}
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	if m.agentRouter == nil {
		m.error(w, 503, "AGENT_ROUTER_UNAVAILABLE", "business router is not configured", op.Context.TraceID)
		return
	}
	if op.Policy.Runtime.Delegation == nil || op.Policy.Runtime.Delegation.Validate() != nil {
		logAgentCoordinationDenial(op.Context.TaskID, op.Context.TraceID, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, agentcoordination.RouteReasonParentPolicy, nil))
		m.error(w, 403, "AGENT_DELEGATION_DENIED", "published delegation policy required", op.Context.TraceID)
		return
	}
	var input agentcoordination.RouteRequest
	var preparation agentcoordination.ChildPrepareRequest
	var admission agentcoordination.ChildAdmitRequest
	var childRead agentcoordination.ChildReadRequest
	var childCancel agentcoordination.ChildCancelRequest
	var groupRead agentcoordination.GroupReadRequest
	var admissionRead agentcoordination.ChildReadRequest
	var command any = &input
	if r.URL.Path == "/internal/agent/prepare" {
		command = &preparation
	} else if r.URL.Path == "/internal/agent/admit" {
		command = &admission
	} else if r.URL.Path == "/internal/agent/child" {
		command = &childRead
	} else if r.URL.Path == "/internal/agent/cancel" {
		command = &childCancel
	} else if r.URL.Path == "/internal/agent/gather" {
		command = &groupRead
	} else if r.URL.Path == "/internal/agent/admission-state" {
		command = &admissionRead
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(command) != nil || decoder.Decode(new(any)) != io.EOF {
		m.error(w, 400, "INVALID_REQUEST", "exact route command required", op.Context.TraceID)
		return
	}
	ctx, err := m.skillExecutionContext(r, op)
	if err != nil {
		logAgentCoordinationDenial(op.Context.TaskID, op.Context.TraceID, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, agentcoordination.RouteReasonParentBoundContext, nil))
		m.error(w, 403, "AGENT_DELEGATION_DENIED", "trusted execution lease required", op.Context.TraceID)
		return
	}
	bound, ok := ctx.Value(skillRuntimeContextKey{}).(skillRuntimeContext)
	if !ok {
		logAgentCoordinationDenial(op.Context.TaskID, op.Context.TraceID, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, agentcoordination.RouteReasonParentBoundContext, nil))
		m.error(w, 403, "AGENT_DELEGATION_DENIED", "trusted execution lease required", op.Context.TraceID)
		return
	}
	ctx = context.WithValue(ctx, agentRouteContextKey{}, bound)
	var response map[string]any
	if r.URL.Path == "/internal/agent/prepare" {
		var prepared agentcoordination.ChildPreparation
		prepared, err = m.agentRouter.PrepareChild(ctx, scopeFromHarness(op.Context), preparation)
		response = map[string]any{"preparation": prepared}
	} else if r.URL.Path == "/internal/agent/admit" {
		var admitted agentcoordination.ChildAdmission
		admitted, err = m.agentRouter.AdmitChild(ctx, scopeFromHarness(op.Context), admission)
		response = map[string]any{"admission": admitted}
	} else if r.URL.Path == "/internal/agent/child" {
		var result agentcoordination.ChildResult
		result, err = m.agentRouter.ReadChild(ctx, scopeFromHarness(op.Context), childRead)
		response = map[string]any{"child": result}
	} else if r.URL.Path == "/internal/agent/cancel" {
		var result agentcoordination.ChildCancellation
		result, err = m.agentRouter.CancelChild(ctx, scopeFromHarness(op.Context), childCancel)
		response = map[string]any{"cancellation": result}
	} else if r.URL.Path == "/internal/agent/gather" {
		var result agentcoordination.GroupResult
		result, err = m.agentRouter.ReadGroup(ctx, scopeFromHarness(op.Context), groupRead)
		response = map[string]any{"group": result}
	} else if r.URL.Path == "/internal/agent/admission-state" {
		var result agentcoordination.AdmissionState
		result, err = m.agentRouter.ReadAdmissionState(ctx, scopeFromHarness(op.Context), admissionRead)
		response = map[string]any{"admission_state": result}
	} else {
		var plan agentcoordination.RoutePlan
		plan, err = m.agentRouter.Plan(ctx, scopeFromHarness(op.Context), input)
		response = map[string]any{"route": plan}
	}
	if err != nil {
		logAgentCoordinationDenial(op.Context.TaskID, op.Context.TraceID, err)
		status, code := 503, "AGENT_ROUTER_UNAVAILABLE"
		if errors.Is(err, agentcoordination.ErrDenied) {
			status, code = 403, "AGENT_DELEGATION_DENIED"
		}
		if errors.Is(err, agentcoordination.ErrConflict) {
			status, code = 409, "AGENT_ROUTE_CONFLICT"
		}
		m.error(w, status, code, "business route planning failed", op.Context.TraceID)
		return
	}
	if r.URL.Path == "/internal/agent/admission-state" {
		if !m.currentCapability(w, r, op) {
			return
		}
		result, valid := response["admission_state"].(agentcoordination.AdmissionState)
		if !valid {
			m.error(w, 502, "AGENT_ADMISSION_STATE_INVALID", "admission snapshot is invalid", op.Context.TraceID)
			return
		}
		checkErr := m.agentRouter.CheckAdmissionState(ctx, scopeFromHarness(op.Context), admissionRead, result)
		if errors.Is(checkErr, agentcoordination.ErrConflict) {
			m.error(w, 409, "AGENT_ADMISSION_STATE_CHANGED", "admission progressed; read again without dispatch", op.Context.TraceID)
			return
		}
		if checkErr != nil {
			m.error(w, 403, "AGENT_ADMISSION_DISCLOSURE_DENIED", "admission authority changed", op.Context.TraceID)
			return
		}
		m.ok(w, response, op.Context.TraceID)
		return
	}
	if r.URL.Path == "/internal/agent/gather" {
		if !m.currentCapability(w, r, op) {
			return
		}
		result, valid := response["group"].(agentcoordination.GroupResult)
		if !valid {
			m.error(w, 502, "AGENT_GROUP_RESULT_INVALID", "group receipt is invalid", op.Context.TraceID)
			return
		}
		checkErr := m.agentRouter.CheckGroupResult(ctx, scopeFromHarness(op.Context), groupRead, result)
		// Children may finish between the audited read and disclosure check.
		// Re-read only that result, under fresh capability/authority checks;
		// never repeat routing, preparation or child dispatch.
		for retry := 0; retry < 2 && errors.Is(checkErr, agentcoordination.ErrConflict); retry++ {
			if !m.currentCapability(w, r, op) {
				return
			}
			result, checkErr = m.agentRouter.ReadGroup(ctx, scopeFromHarness(op.Context), groupRead)
			if checkErr != nil {
				break
			}
			if !m.currentCapability(w, r, op) {
				return
			}
			checkErr = m.agentRouter.CheckGroupResult(ctx, scopeFromHarness(op.Context), groupRead, result)
		}
		if errors.Is(checkErr, agentcoordination.ErrConflict) {
			m.error(w, 409, "AGENT_GROUP_RESULT_CHANGED", "group progressed before disclosure; read again without dispatch", op.Context.TraceID)
			return
		}
		if checkErr != nil {
			m.error(w, 403, "AGENT_GROUP_DISCLOSURE_DENIED", "group authority or result changed before disclosure", op.Context.TraceID)
			return
		}
		response["group"] = result
		m.ok(w, response, op.Context.TraceID)
		return
	}
	if r.URL.Path == "/internal/agent/child" {
		if !m.currentCapability(w, r, op) {
			return
		}
		result, valid := response["child"].(agentcoordination.ChildResult)
		if !valid || m.agentRouter.CheckChildResult(ctx, scopeFromHarness(op.Context), childRead, result) != nil {
			m.error(w, 403, "AGENT_CHILD_DISCLOSURE_DENIED", "child authority or result changed before disclosure", op.Context.TraceID)
			return
		}
		m.ok(w, response, op.Context.TraceID)
		return
	}
	m.currentResult(w, r, op, response)
}

// cancelAgentChild is a stop-only control path for an already admitted child.
// It authenticates the exact signed parent generation and workload identity,
// then relies on the persisted route/proof and child revision CAS. It does not
// authorize new execution or inspect current agent.delegate grants.
func (m *Module) cancelAgentChild(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorizeStopEnvelope(w, r)
	if !ok {
		return
	}
	if m.agentRouter == nil {
		m.error(w, 503, "AGENT_ROUTER_UNAVAILABLE", "business router is not configured", op.Context.TraceID)
		return
	}
	var request agentcoordination.ChildCancelRequest
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		m.error(w, 400, "INVALID_REQUEST", "exact route command required", op.Context.TraceID)
		return
	}
	lease, policyHash, err := m.authorizeStopOnlyExecution(r.Context(), op)
	if err != nil {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "current parent execution generation denied", op.Context.TraceID)
		return
	}
	if err := m.authenticateWorkload(r, op); err != nil {
		m.error(w, http.StatusForbidden, "WORKLOAD_AUTHENTICATION_DENIED", "current workload credential denied", op.Context.TraceID)
		return
	}
	retainWorkloadProof(r, op)
	clientID := strings.TrimSpace(r.Header.Get("X-Agent-Client-ID"))
	if clientID == "" {
		m.error(w, http.StatusForbidden, "WORKLOAD_AUTHENTICATION_DENIED", "current workload identity denied", op.Context.TraceID)
		return
	}
	ctx := r.Context()
	var result agentcoordination.ChildCancellation
	result, err = m.agentRouter.CancelChildStopOnly(ctx, scopeFromHarness(op.Context), request, agentcoordination.ChildStopIdentity{Lease: lease, PolicyHash: policyHash, MachinePrincipalID: clientID})
	if err != nil {
		if conflict, ok := childStopControlConflictResponse(err, op.Context.TraceID); ok {
			m.write(w, http.StatusConflict, conflict)
			return
		}
		status, code := 503, "AGENT_ROUTER_UNAVAILABLE"
		if errors.Is(err, agentcoordination.ErrDenied) {
			status, code = 403, "AGENT_DELEGATION_DENIED"
		}
		if errors.Is(err, agentcoordination.ErrConflict) {
			status, code = 409, "AGENT_ROUTE_CONFLICT"
		}
		m.error(w, status, code, "recorded child stop was denied or changed", op.Context.TraceID)
		return
	}
	m.ok(w, map[string]any{"cancellation": result}, op.Context.TraceID)
}

func childStopControlConflictResponse(err error, trace string) (response, bool) {
	var conflict *agentcoordination.ChildStopRevisionConflict
	if !errors.As(err, &conflict) || conflict == nil || conflict.ExecutionRevision == 0 || conflict.ExecutionRevision > 1<<63-1 ||
		(conflict.Status != "accepted" && conflict.Status != "running" && conflict.Status != "waiting") {
		return response{}, false
	}
	return response{
		Code:      1,
		ErrorCode: "AGENT_STOP_REVISION_CONFLICT",
		Message:   "child stop state changed; retry with the reported execution revision",
		Data: map[string]any{"stop_control": map[string]any{
			"version":            agentcoordination.ChildStopControlConflictVersion,
			"status":             conflict.Status,
			"execution_revision": conflict.ExecutionRevision,
		}},
		TraceID: trace,
	}, true
}

func (m *Module) authorizeStopEnvelope(w http.ResponseWriter, r *http.Request) (envelope, bool) {
	if m.internalToken == "" || !hmac.Equal([]byte(m.internalToken), []byte(strings.TrimSpace(r.Header.Get("X-Internal-Token")))) {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid internal credential", "")
		return envelope{}, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		m.error(w, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "request body exceeds limit", "")
		return envelope{}, false
	}
	if m.signingSecret != "" {
		supplied := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("X-Context-Signature")), "sha256=")
		mac := hmac.New(sha256.New, []byte(m.signingSecret))
		_, _ = mac.Write(requestSignaturePayload(r.Method, r.URL.RequestURI(), body))
		if supplied == "" || !hmac.Equal([]byte(supplied), []byte(fmt.Sprintf("%x", mac.Sum(nil)))) {
			m.error(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "invalid request signature", "")
			return envelope{}, false
		}
	}
	var op envelope
	if err := json.Unmarshal(body, &op); err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid capability envelope", "")
		return envelope{}, false
	}
	if err := m.validateContext(r, op.Context); err != nil {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", err.Error(), op.Context.TraceID)
		return envelope{}, false
	}
	return op, true
}
