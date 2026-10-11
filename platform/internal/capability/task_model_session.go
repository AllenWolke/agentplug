package capability

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// TaskEmbeddingSession is an internal composition port, never a serialized
// job or Agent credential. Its callbacks retain the verified execution context
// and reuse the ordinary approved-model/price/budget/capacity/invocation path.
type TaskEmbeddingSession struct {
	Scope  sharedkernel.Scope
	Policy policyasset.Snapshot
	Call   KnowledgeModelCall  `json:"-"`
	Check  KnowledgeModelCheck `json:"-"`
	Close  func()              `json:"-"`
}

// OpenTaskEmbeddingSession verifies a fresh signed embedding request using
// exactly the ordinary capability admission boundary. It does not issue a
// token, bypass workload authentication or revive an expired request. The
// scheduler must provide a request bound to the current task/lease, and open
// another session after legitimate context renewal rather than storing these
// callbacks. Opening performs no model send or budget reservation.
func (m *Module) OpenTaskEmbeddingSession(ctx context.Context, parent *http.Request, expected sharedkernel.Scope) (TaskEmbeddingSession, error) {
	empty := TaskEmbeddingSession{}
	if m == nil || m.publicKey == nil || ctx == nil || parent == nil || parent.URL == nil || parent.Body == nil || expected.ValidateTrusted() != nil || parent.Method != http.MethodPost || parent.URL.Path != "/internal/model/embed" || parent.URL.RawPath != "" || parent.URL.RawQuery != "" || parent.URL.Fragment != "" {
		return empty, &KnowledgeModelError{Status: 403, Code: "TASK_MODEL_CONTEXT_DENIED"}
	}
	lifetime, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(parent.Context(), cancel)
	var once sync.Once
	closeSession := func() { once.Do(func() { stop(); cancel() }) }
	if err := lifetime.Err(); err != nil {
		closeSession()
		return empty, err
	}
	r := parent.Clone(lifetime)
	capture := &modelCallResponse{header: make(http.Header)}
	op, ok := m.authorize(capture, r)
	if !ok {
		closeSession()
		var failure struct {
			Code string `json:"error_code"`
		}
		_ = json.Unmarshal(capture.body.Bytes(), &failure)
		if failure.Code == "" {
			failure.Code = "TASK_MODEL_CONTEXT_DENIED"
		}
		return empty, &KnowledgeModelError{Status: capture.status, Code: failure.Code}
	}
	c := op.Context
	scope := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentInstanceID: c.AgentInstanceID, AgentID: c.AgentID, PrincipalType: c.PrincipalType, PrincipalID: c.ActorID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, SessionID: c.SessionID, RunID: c.TaskID, ParentRunID: c.ParentRunID, AuthorizationEpoch: c.AuthorizationEpoch, TraceID: c.TraceID}
	if scope != expected {
		closeSession()
		return empty, &KnowledgeModelError{Status: 403, Code: "TASK_MODEL_CONTEXT_DENIED"}
	}
	check := m.knowledgeModelCheck(r, op, lifetime)
	if err := check(lifetime, "embed"); err != nil {
		closeSession()
		return empty, err
	}
	// Detach the public policy view from the private authorization envelope.
	raw, err := json.Marshal(op.Policy)
	var policy policyasset.Snapshot
	if err != nil || json.Unmarshal(raw, &policy) != nil {
		closeSession()
		return empty, ErrKnowledgePortUnavailable
	}
	call := m.knowledgeModelCall(r, op, lifetime)
	embeddingOnly := func(operation string) error {
		if operation != "embed" {
			return &KnowledgeModelError{Status: 403, Code: "TASK_MODEL_OPERATION_DENIED"}
		}
		return nil
	}
	return TaskEmbeddingSession{Scope: scope, Policy: policy, Close: closeSession, Check: func(ctx context.Context, operation string) error {
		if err := embeddingOnly(operation); err != nil {
			return err
		}
		return check(ctx, operation)
	}, Call: func(ctx context.Context, operation string, input map[string]any) (map[string]any, error) {
		if err := embeddingOnly(operation); err != nil {
			return nil, err
		}
		return call(ctx, operation, input)
	}}, nil
}
