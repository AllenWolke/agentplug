package agentcoordination

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type ChildAdmitRequest struct {
	OperationKey     string `json:"operation_key"`
	Ordinal          int    `json:"ordinal"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

type ChildAdmission struct {
	Version          string `json:"version"`
	ParentRunID      string `json:"parent_run_id"`
	ChildRunID       string `json:"child_run_id"`
	ChildKey         string `json:"child_key"`
	OperationKey     string `json:"operation_key"`
	Ordinal          int    `json:"ordinal"`
	Status           string `json:"status"`
	Revision         uint64 `json:"revision"`
	InputFingerprint string `json:"input_fingerprint"`
}

// This trusted composition input contains only the saved plan and frozen input.
// No endpoint, policy or machine identity may be supplied by the Agent request.
type ChildExecutionAdmission struct {
	Parent         ParentFacts
	Target         Target
	Depth          int
	ChildKey       string
	RunID          string
	IdempotencyKey string
	InputSchema    string
	Input          map[string]any
}

type AdmittedChildExecution struct {
	Scope              sharedkernel.Scope
	RequestFingerprint string
	// DelegationAuthorityJSON is produced by the trusted platform admission
	// adapter from live IAM state. It is committed with the reservation and is
	// never accepted from a Run request or Agent payload.
	DelegationAuthorityJSON string
}

// The implementation must check current caller/parent/target-machine authority,
// immutable target policy, parent fence and shared-root budget in this transaction,
// then use Execution.CreateCoordinatedRunTx. No Agent RPC is allowed here.
type ChildExecutionAdmitter interface {
	AdmitChild(context.Context, *sql.Tx, ChildExecutionAdmission) (AdmittedChildExecution, error)
}

type ChildAdmissionStore interface {
	AdmitChild(context.Context, sharedkernel.Scope, ChildAdmitRequest) (ChildAdmission, error)
}

func (r *Router) AdmitChild(ctx context.Context, scope sharedkernel.Scope, request ChildAdmitRequest) (ChildAdmission, error) {
	if r == nil || scope.ValidateTrusted() != nil {
		return ChildAdmission{}, ErrDenied
	}
	store, ok := r.store.(ChildAdmissionStore)
	if !ok {
		return ChildAdmission{}, ErrUnavailable
	}
	return store.AdmitChild(ctx, scope, request)
}

func (s *SQLRouteStore) SetChildExecutionAdmitter(admitter ChildExecutionAdmitter) {
	s.children = admitter
}

func (s *SQLRouteStore) AdmitChild(ctx context.Context, scope sharedkernel.Scope, request ChildAdmitRequest) (ChildAdmission, error) {
	if s == nil || s.children == nil {
		return ChildAdmission{}, ErrUnavailable
	}
	if !identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 || request.ExpectedRevision != 2 {
		return ChildAdmission{}, ErrDenied
	}
	var result ChildAdmission
	err := s.Transact(ctx, scope, func(port RouteTransaction) error {
		unit, ok := port.(*sqlRouteTransaction)
		if !ok {
			return ErrUnavailable
		}
		parent, err := unit.Parent(ctx, scope)
		if err != nil {
			return err
		}
		plan, found, err := unit.Existing(request.OperationKey)
		if err != nil {
			return err
		}
		if !found || !parent.Active || parent.Policy == nil || parent.Policy.Validate() != nil || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.ChildDepth > parent.Policy.MaxDepth || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) {
			return ErrDenied
		}
		target := plan.Targets[request.Ordinal]
		if !eligible(parent, target, plan.TaskType) || unit.AuthorizeTarget(ctx, parent, target) != nil {
			return ErrDenied
		}
		var key, status, schema string
		var raw, inputFingerprint, childID, executionFingerprint sql.NullString
		var revision uint64
		err = unit.tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,prepared_input_schema,prepared_input_json,prepared_input_fingerprint,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR UPDATE`), unit.key, request.OperationKey, request.Ordinal).Scan(&key, &status, &revision, &schema, &raw, &inputFingerprint, &childID, &executionFingerprint)
		if err != nil {
			return err
		}
		if key != digest([]any{unit.key, plan.OperationKey, request.Ordinal, plan.Fingerprint}) || schema != target.InputSchema || !inputFingerprint.Valid || !hashValue(inputFingerprint.String) || !raw.Valid || len(raw.String) > 65536 {
			return ErrConflict
		}
		var input map[string]any
		decoder := json.NewDecoder(bytes.NewBufferString(raw.String))
		decoder.UseNumber()
		if decoder.Decode(&input) != nil || input == nil || decoder.Decode(new(any)) != io.EOF || digest([]any{schema, input}) != inputFingerprint.String {
			return ErrConflict
		}
		if _, forged := input["policy_snapshot"]; forged {
			return ErrDenied
		}
		runID := "child-" + key[:48]
		if status == "preparing" {
			if revision != request.ExpectedRevision || childID.Valid || executionFingerprint.Valid {
				return ErrConflict
			}
			admitted, err := s.children.AdmitChild(ctx, unit.tx, ChildExecutionAdmission{Parent: parent, Target: target, Depth: plan.ChildDepth, ChildKey: key, RunID: runID, IdempotencyKey: "child-" + key, InputSchema: schema, Input: input})
			if err != nil {
				return err
			}
			child := admitted.Scope
			if child.ValidateTrusted() != nil || child.RunID != runID || child.ParentRunID != scope.RunID || child.TenantID != scope.TenantID || child.DepartmentID != scope.DepartmentID || child.ApplicationID != scope.ApplicationID || child.PrincipalType != scope.PrincipalType || child.PrincipalID != scope.PrincipalID || child.SessionID != scope.SessionID || child.AgentID != target.AgentID || child.AgentInstanceID != target.InstallationID || child.InstallationID != target.InstallationID || child.AgentVersionID != target.VersionID || !hashValue(admitted.RequestFingerprint) || !validDelegationAuthorityJSON(admitted.DelegationAuthorityJSON) {
				return ErrDenied
			}
			updated, err := unit.tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_agent_child_reservation SET status='accepted',revision=revision+1,child_run_id=?,request_fingerprint=?,delegation_authority_json=? WHERE parent_key=? AND operation_key=? AND ordinal=? AND status='preparing' AND revision=? AND child_run_id IS NULL`), runID, admitted.RequestFingerprint, admitted.DelegationAuthorityJSON, unit.key, request.OperationKey, request.Ordinal, request.ExpectedRevision)
			if err != nil {
				return err
			}
			count, err := updated.RowsAffected()
			if err != nil || count != 1 {
				return ErrConflict
			}
			status, revision = "accepted", revision+1
		} else {
			// Accepted, in-flight, terminal and unknown replays never call creation.
			if revision < 3 || !childID.Valid || childID.String != runID || !executionFingerprint.Valid || !hashValue(executionFingerprint.String) {
				return ErrConflict
			}
			switch status {
			case "accepted", "running", "completed", "failed", "cancelled", "uncertain":
			default:
				return ErrConflict
			}
		}
		result = ChildAdmission{Version: "agent-child-admission/v1", ParentRunID: scope.RunID, ChildRunID: runID, ChildKey: key, OperationKey: request.OperationKey, Ordinal: request.Ordinal, Status: status, Revision: revision, InputFingerprint: inputFingerprint.String}
		unit.auditAction = "agent.child_accepted"
		return unit.Audit(plan)
	})
	if err != nil {
		return ChildAdmission{}, err
	}
	return result, nil
}
