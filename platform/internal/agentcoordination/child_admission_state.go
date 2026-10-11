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

// AdmissionState contains no business input, output or dispatch credential.
// Preparing means the original reservation has not admitted a Run in this
// snapshot; any subsequent admit still uses the original CAS and current IAM.
type AdmissionState struct {
	Version          string `json:"version"`
	ParentRunID      string `json:"parent_run_id"`
	OperationKey     string `json:"operation_key"`
	Ordinal          int    `json:"ordinal"`
	ChildKey         string `json:"child_key"`
	ChildRunID       string `json:"child_run_id"`
	Status           string `json:"status"`
	Revision         uint64 `json:"revision"`
	InputFingerprint string `json:"input_fingerprint"`
	OutputSchema     string `json:"output_schema"`
}

type ChildAdmissionStateStore interface {
	ReadAdmissionState(context.Context, sharedkernel.Scope, ChildReadRequest) (AdmissionState, error)
	CheckAdmissionState(context.Context, sharedkernel.Scope, ChildReadRequest, AdmissionState) error
}

func (r *Router) ReadAdmissionState(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest) (AdmissionState, error) {
	if r == nil || scope.ValidateTrusted() != nil {
		return AdmissionState{}, ErrDenied
	}
	store, ok := r.store.(ChildAdmissionStateStore)
	if !ok {
		return AdmissionState{}, ErrUnavailable
	}
	return store.ReadAdmissionState(ctx, scope, request)
}

func (r *Router) CheckAdmissionState(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest, receipt AdmissionState) error {
	if r == nil || scope.ValidateTrusted() != nil {
		return ErrDenied
	}
	store, ok := r.store.(ChildAdmissionStateStore)
	if !ok {
		return ErrUnavailable
	}
	return store.CheckAdmissionState(ctx, scope, request, receipt)
}

func (s *SQLRouteStore) ReadAdmissionState(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest) (AdmissionState, error) {
	var result AdmissionState
	err := s.admissionStateTransaction(ctx, scope, request, func(unit *sqlRouteTransaction, plan RoutePlan, current AdmissionState) error {
		result = current
		unit.auditAction = "agent.admission_read"
		return unit.Audit(plan)
	})
	return result, err
}

func (s *SQLRouteStore) CheckAdmissionState(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest, receipt AdmissionState) error {
	return s.admissionStateTransaction(ctx, scope, request, func(_ *sqlRouteTransaction, _ RoutePlan, current AdmissionState) error {
		if current != receipt {
			return ErrConflict
		}
		return nil
	})
}

func (s *SQLRouteStore) admissionStateTransaction(ctx context.Context, scope sharedkernel.Scope, request ChildReadRequest, callback func(*sqlRouteTransaction, RoutePlan, AdmissionState) error) error {
	if s == nil || s.children == nil || !identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 {
		return ErrDenied
	}
	reader, ok := s.children.(ChildExecutionReader)
	if !ok {
		return ErrUnavailable
	}
	return s.Transact(ctx, scope, func(port RouteTransaction) error {
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
		if !found || parent.Scope != scope || !parent.Active || parent.Policy == nil || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) {
			return ErrDenied
		}
		target := plan.Targets[request.Ordinal]
		if !eligible(parent, target, plan.TaskType) || unit.AuthorizeTarget(ctx, parent, target) != nil {
			return ErrDenied
		}
		var key, status, schema string
		var revision uint64
		var inputJSON, inputHash, childID, requestHash sql.NullString
		err = unit.tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,prepared_input_schema,prepared_input_json,prepared_input_fingerprint,child_run_id,request_fingerprint FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR SHARE`), unit.key, request.OperationKey, request.Ordinal).Scan(&key, &status, &revision, &schema, &inputJSON, &inputHash, &childID, &requestHash)
		if err != nil {
			return err
		}
		if key != digest([]any{unit.key, plan.OperationKey, request.Ordinal, plan.Fingerprint}) || schema != target.InputSchema || !inputJSON.Valid || len(inputJSON.String) > 65536 || !inputHash.Valid || !hashValue(inputHash.String) {
			return ErrConflict
		}
		decoder := json.NewDecoder(bytes.NewBufferString(inputJSON.String))
		decoder.UseNumber()
		var input map[string]any
		if decoder.Decode(&input) != nil || input == nil || decoder.Decode(new(any)) != io.EOF || digest([]any{schema, input}) != inputHash.String {
			return ErrConflict
		}
		if status == "preparing" {
			if revision != 2 || childID.Valid || requestHash.Valid {
				return ErrConflict
			}
		} else {
			if revision < 3 || !childID.Valid || childID.String != "child-"+key[:48] || !requestHash.Valid || !hashValue(requestHash.String) {
				return ErrConflict
			}
			// Verify the actual recorded Run and original fingerprint. The
			// response deliberately does not include any child output.
			if _, err := unit.readChildResult(ctx, parent, plan, request.Ordinal, reader); err != nil {
				return err
			}
		}
		result := AdmissionState{Version: "agent-child-admission-state/v1", ParentRunID: scope.RunID, OperationKey: request.OperationKey, Ordinal: request.Ordinal, ChildKey: key, ChildRunID: childID.String, Status: status, Revision: revision, InputFingerprint: inputHash.String, OutputSchema: target.OutputSchema}
		return callback(unit, plan, result)
	})
}
