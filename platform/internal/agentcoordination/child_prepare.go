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

type ChildPrepareRequest struct {
	OperationKey     string         `json:"operation_key"`
	Ordinal          int            `json:"ordinal"`
	ExpectedRevision uint64         `json:"expected_revision"`
	InputSchema      string         `json:"input_schema"`
	Input            map[string]any `json:"input"`
}
type ChildPreparation struct {
	Version          string `json:"version"`
	ParentRunID      string `json:"parent_run_id"`
	OperationKey     string `json:"operation_key"`
	Ordinal          int    `json:"ordinal"`
	ChildKey         string `json:"child_key"`
	Status           string `json:"status"`
	Revision         uint64 `json:"revision"`
	InputSchema      string `json:"input_schema"`
	InputFingerprint string `json:"input_fingerprint"`
}

// ChildPreparationStore freezes input without admitting or dispatching a Run.
// A route store without this optional capability must fail closed.
type ChildPreparationStore interface {
	PrepareChild(context.Context, sharedkernel.Scope, ChildPrepareRequest) (ChildPreparation, error)
}

func (r *Router) PrepareChild(ctx context.Context, scope sharedkernel.Scope, request ChildPrepareRequest) (ChildPreparation, error) {
	if r == nil || scope.ValidateTrusted() != nil {
		return ChildPreparation{}, ErrDenied
	}
	store, ok := r.store.(ChildPreparationStore)
	if !ok {
		return ChildPreparation{}, ErrUnavailable
	}
	return store.PrepareChild(ctx, scope, request)
}

// PrepareChild freezes input against an existing plan and selected target.
// It cannot create a Run, reserve money or send an Agent RPC. Replays are
// metadata-only, repeat current authority and never change the frozen input.
func (s *SQLRouteStore) PrepareChild(ctx context.Context, scope sharedkernel.Scope, request ChildPrepareRequest) (ChildPreparation, error) {
	if !identifier(request.OperationKey) || request.Ordinal < 0 || request.Ordinal > 15 || request.ExpectedRevision != 1 || request.Input == nil {
		return ChildPreparation{}, ErrDenied
	}
	if _, reserved := request.Input["policy_snapshot"]; reserved {
		return ChildPreparation{}, ErrDenied
	}
	encoded, err := json.Marshal(request.Input)
	if err != nil || len(encoded) > 65536 {
		return ChildPreparation{}, ErrDenied
	}
	fingerprint := digest([]any{request.InputSchema, request.Input})
	var result ChildPreparation
	err = s.Transact(ctx, scope, func(port RouteTransaction) error {
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
		if !found || parent.Policy == nil || parent.Policy.Validate() != nil || !parent.Active || plan.Version != "agent-route/v1" || plan.ParentRunID != scope.RunID || plan.PolicyHash != parent.PolicyHash || plan.ChildDepth != parent.Depth+1 || plan.ChildDepth > parent.Policy.MaxDepth || plan.EvidenceDigest != digest(plan.Targets) || request.Ordinal >= len(plan.Targets) {
			return ErrDenied
		}
		target := plan.Targets[request.Ordinal]
		if request.InputSchema != target.InputSchema || !eligible(parent, target, plan.TaskType) || unit.AuthorizeTarget(ctx, parent, target) != nil {
			return ErrDenied
		}
		var key, status, schema string
		var prior, priorInput sql.NullString
		var revision uint64
		err = unit.tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT child_key,status,revision,prepared_input_schema,prepared_input_fingerprint,prepared_input_json FROM platform_agent_child_reservation WHERE parent_key=? AND operation_key=? AND ordinal=? FOR UPDATE`), unit.key, request.OperationKey, request.Ordinal).Scan(&key, &status, &revision, &schema, &prior, &priorInput)
		if err != nil {
			return err
		}
		if key != digest([]any{unit.key, plan.OperationKey, request.Ordinal, plan.Fingerprint}) {
			return ErrConflict
		}
		if status == "reserved" {
			if revision != request.ExpectedRevision || prior.Valid || schema != "" {
				return ErrConflict
			}
			updated, err := unit.tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_agent_child_reservation SET status='preparing',revision=revision+1,prepared_input_schema=?,prepared_input_json=?,prepared_input_fingerprint=? WHERE parent_key=? AND operation_key=? AND ordinal=? AND status='reserved' AND revision=?`), request.InputSchema, string(encoded), fingerprint, unit.key, request.OperationKey, request.Ordinal, request.ExpectedRevision)
			if err != nil {
				return err
			}
			count, err := updated.RowsAffected()
			if err != nil || count != 1 {
				return ErrConflict
			}
			status, revision = "preparing", revision+1
		} else if status != "preparing" || revision != 2 || !prior.Valid || prior.String != fingerprint || schema != request.InputSchema {
			return ErrConflict
		} else {
			var original map[string]any
			decoder := json.NewDecoder(bytes.NewBufferString(priorInput.String))
			decoder.UseNumber()
			if !priorInput.Valid || len(priorInput.String) > 65536 || decoder.Decode(&original) != nil || original == nil || decoder.Decode(new(any)) != io.EOF || digest([]any{schema, original}) != fingerprint {
				return ErrConflict
			}
		}
		result = ChildPreparation{Version: "agent-child-preparation/v1", ParentRunID: scope.RunID, OperationKey: request.OperationKey, Ordinal: request.Ordinal, ChildKey: key, Status: status, Revision: revision, InputSchema: request.InputSchema, InputFingerprint: fingerprint}
		unit.auditAction = "agent.child_prepared"
		return unit.Audit(plan)
	})
	if err != nil {
		return ChildPreparation{}, err
	}
	return result, nil
}
