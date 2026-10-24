package execution

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

const waitingAuthorizationEvent = "run_authorization_renewed"
const WaitingAuthorizationVersion = "waiting-run-authorization/v2"

type WaitingAuthorizationRequest struct {
	Version                    string `json:"version"`
	RequestID                  string `json:"request_id"`
	ExpectedRevision           uint64 `json:"expected_revision"`
	ExpectedAuthorizationEpoch uint64 `json:"expected_authorization_epoch"`
}
type WaitingAuthorizationReceipt struct {
	Version                    string    `json:"version"`
	RunID                      string    `json:"run_id"`
	RequestID                  string    `json:"request_id"`
	RequestDigest              string    `json:"request_digest"`
	ExecutionRevision          uint64    `json:"execution_revision"`
	PreviousAuthorizationEpoch uint64    `json:"previous_authorization_epoch"`
	AuthorizationEpoch         uint64    `json:"authorization_epoch"`
	ScopeHash                  string    `json:"scope_hash"`
	RequestHash                string    `json:"request_hash"`
	OriginalAuthorizationEpoch uint64    `json:"original_authorization_epoch"`
	OccurredAt                 time.Time `json:"occurred_at"`
	Replayed                   bool      `json:"replayed"`
}

// All ports join the owner transaction. They must fence current IAM/session,
// verify the original published policy and deployment, deny delegation, and
// refresh the corresponding root authority before recording Audit.
type WaitingAuthorizationPorts struct {
	Fence              func(context.Context, *sql.Tx) error
	Authorize          func(context.Context, *sql.Tx, BrowserRunActor, BudgetRunFacts) (uint64, error)
	RenewRootAuthority func(context.Context, *sql.Tx, sharedkernel.Scope, sharedkernel.Scope) error
	Audit              func(context.Context, *sql.Tx, sharedkernel.Scope, WaitingAuthorizationReceipt) error
}

func (s *SQLStore) SetWaitingAuthorizationPorts(ports WaitingAuthorizationPorts) {
	s.waitingAuthorization = &ports
}

var waitingAuthorizationID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func (r WaitingAuthorizationRequest) valid() bool {
	return r.Version == WaitingAuthorizationVersion && waitingAuthorizationID.MatchString(r.RequestID) && r.ExpectedRevision >= 2 && r.ExpectedRevision < 1<<53 && r.ExpectedAuthorizationEpoch > 0 && r.ExpectedAuthorizationEpoch < 1<<53
}

// RenewWaitingAuthorization records current authority separately from immutable
// execution identity. A pending checkpoint, SDK context and tool receipts retain
// the original Scope. It changes no Run, input, budget, lease or execution revision.
func (s *SQLStore) RenewWaitingAuthorization(ctx context.Context, actor BrowserRunActor, id string, request WaitingAuthorizationRequest) (WaitingAuthorizationReceipt, error) {
	var receipt WaitingAuthorizationReceipt
	if s == nil || s.waitingAuthorization == nil || !request.valid() || actor.Scope.Validate() != nil || actor.Scope.PrincipalType != "user" || actor.AuthenticationSession == "" || actor.AuthenticationRevision == 0 || !waitingAuthorizationID.MatchString(id) {
		return receipt, platformruntime.ErrInvalidRequest
	}
	p := s.waitingAuthorization
	if p.Fence == nil || p.Authorize == nil || p.RenewRootAuthority == nil || p.Audit == nil {
		return receipt, errors.New("waiting authorization unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	if err = p.Fence(ctx, tx); err != nil {
		return receipt, err
	}
	facts, err := s.BudgetRunForUpdateTx(ctx, tx, id)
	if err != nil {
		return receipt, err
	}
	scope := facts.Scope
	if scope.PrincipalType != "user" || scope.PrincipalID != actor.Scope.PrincipalID || scope.TenantID != actor.Scope.TenantID || scope.DepartmentID != actor.Scope.DepartmentID || scope.ApplicationID != actor.Scope.ApplicationID || scope.ParentRunID != "" {
		return receipt, ErrRunPermissionDenied
	}
	previous, err := s.expectedAuthorizationEpoch(ctx, tx, facts, scope)
	if err != nil {
		return receipt, err
	}
	raw, _ := json.Marshal(struct {
		RunID   string
		Request WaitingAuthorizationRequest
	}{id, request})
	digest := sha256.Sum256(raw)
	requestDigest := hex.EncodeToString(digest[:])
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type=? AND payload::jsonb->>'request_id'=? ORDER BY seq DESC LIMIT 1`), id, waitingAuthorizationEvent, request.RequestID).Scan(&saved)
	if err == nil {
		if json.Unmarshal(saved, &receipt) != nil || !validWaitingAuthorityReceipt(receipt, facts) || receipt.RequestDigest != requestDigest || receipt.ExecutionRevision != request.ExpectedRevision || receipt.PreviousAuthorizationEpoch != request.ExpectedAuthorizationEpoch || receipt.AuthorizationEpoch != previous {
			return WaitingAuthorizationReceipt{}, platformruntime.ErrRevisionConflict
		}
		epoch, authorizeErr := p.Authorize(ctx, tx, actor, facts)
		if authorizeErr != nil {
			return WaitingAuthorizationReceipt{}, authorizeErr
		}
		if epoch != receipt.AuthorizationEpoch {
			return WaitingAuthorizationReceipt{}, ErrRunPermissionDenied
		}
		receipt.Replayed = true
		return receipt, nil // read-only receipt replay; no execution or second audit
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return receipt, err
	}
	if facts.Status != platformruntime.StatusWaiting {
		return receipt, platformruntime.ErrInvalidTransition
	}
	if facts.Revision != request.ExpectedRevision || previous != request.ExpectedAuthorizationEpoch {
		return receipt, platformruntime.ErrRevisionConflict
	}
	// A committed supervised handler exit is required. Lease expiry or a
	// browser's waiting assertion is not proof of quiescence.
	if _, err = s.WaitingHandlerHandoffTx(ctx, tx, scope, facts.Revision); err != nil {
		return receipt, err
	}
	epoch, err := p.Authorize(ctx, tx, actor, facts)
	if err != nil {
		return receipt, err
	}
	if epoch < previous || epoch == 0 || epoch >= 1<<53 {
		return receipt, ErrRunPermissionDenied
	}
	if err = p.RenewRootAuthority(ctx, tx, scope, scope); err != nil {
		return receipt, err
	}
	receipt = WaitingAuthorizationReceipt{Version: WaitingAuthorizationVersion, RunID: id, RequestID: request.RequestID, RequestDigest: requestDigest, ExecutionRevision: facts.Revision, PreviousAuthorizationEpoch: previous, AuthorizationEpoch: epoch, OriginalAuthorizationEpoch: scope.AuthorizationEpoch, ScopeHash: waitingAuthorityScopeHash(scope), RequestHash: waitingAuthorityRequestHash(facts.RequestJSON), OccurredAt: time.Now().UTC()}
	if err = p.Audit(ctx, tx, scope, receipt); err != nil {
		return WaitingAuthorizationReceipt{}, err
	}
	payload, _ := json.Marshal(receipt)
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,?)`), id, waitingAuthorizationEvent, payload, receipt.OccurredAt); err != nil {
		return WaitingAuthorizationReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return WaitingAuthorizationReceipt{}, err
	}
	return receipt, nil
}

func (m *Module) renewWaitingAuthorization(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		m.writeError(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if r.Header.Get("X-Browser-Module") != "1" {
		m.writeError(w, 403, "BROWSER_AUTHENTICATION_REQUIRED")
		return
	}
	var request WaitingAuthorizationRequest
	if decodeJSON(r, &request) != nil || !request.valid() {
		m.writeError(w, 400, "INVALID_REQUEST")
		return
	}
	run, err := m.store.Get(id)
	if err != nil || run.Scope.PrincipalType != "user" || run.Scope.PrincipalID != r.Header.Get("X-Principal-ID") {
		m.writeError(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	if err = m.checkBrowserRunAccess(r, run.Scope, "history.continue"); err != nil {
		m.writeBrowserRunPermissionError(w, err)
		return
	}
	revision, err := strconv.ParseUint(r.Header.Get("X-Authentication-Revision"), 10, 64)
	if err != nil {
		m.writeBrowserRunPermissionError(w, ErrBrowserSessionInvalid)
		return
	}
	actor := BrowserRunActor{Scope: sharedkernel.Scope{TenantID: r.Header.Get("X-Tenant-ID"), DepartmentID: r.Header.Get("X-Department-ID"), ApplicationID: r.Header.Get("X-Application-ID"), PrincipalType: "user", PrincipalID: r.Header.Get("X-Principal-ID")}, AuthenticationSession: r.Header.Get("X-Authentication-Session"), AuthenticationRevision: revision}
	renewer, ok := m.store.(interface {
		RenewWaitingAuthorization(context.Context, BrowserRunActor, string, WaitingAuthorizationRequest) (WaitingAuthorizationReceipt, error)
	})
	if !ok {
		m.writeError(w, 503, "AUTHORIZATION_UNAVAILABLE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	receipt, err := renewer.RenewWaitingAuthorization(ctx, actor, id, request)
	if errors.Is(err, ErrRunPermissionDenied) || errors.Is(err, ErrBrowserSessionInvalid) {
		m.writeBrowserRunPermissionError(w, err)
		return
	}
	if err != nil {
		m.writeRuntimeError(w, err)
		return
	}
	m.writeJSON(w, 200, receipt)
}
