package capability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func modelSelectionScopeHash(s sharedkernel.Scope) string {
	// Trace is observational and may change during recovery; the execution identity
	// and its original authorization epoch remain part of the binding.
	s.TraceID = ""
	return modelRouteHash(s)
}

func validModelSelectionBinding(s sharedkernel.Scope, b policyasset.ModelSelectionBinding) bool {
	return s.ValidateTrusted() == nil && b.Selection.Validate() == nil &&
		isRouteSHA(b.PolicySHA256) && isRouteSHA(b.CommandFingerprint) && b.ValidateTask()
}

func (s *SQLModelInvocationStore) ensureModelSelectionSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_run_model_selection (
scope_hash VARCHAR(64) PRIMARY KEY,binding_json TEXT NOT NULL,created_at TIMESTAMPTZ(6) NOT NULL);`)
	return err
}

func (s *SQLModelInvocationStore) LookupModelSelection(ctx context.Context, scope sharedkernel.Scope) (policyasset.ModelSelectionBinding, bool, error) {
	if scope.ValidateTrusted() != nil {
		return policyasset.ModelSelectionBinding{}, false, ErrModelInvocationConflict
	}
	var raw string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT binding_json FROM platform_run_model_selection WHERE scope_hash=?`), modelSelectionScopeHash(scope)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return policyasset.ModelSelectionBinding{}, false, nil
	}
	if err != nil {
		return policyasset.ModelSelectionBinding{}, false, err
	}
	var binding policyasset.ModelSelectionBinding
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1024 || d.Decode(&binding) != nil || d.Decode(new(any)) != io.EOF || !validModelSelectionBinding(scope, binding) {
		return policyasset.ModelSelectionBinding{}, false, ErrModelRouteUnavailable
	}
	return binding, true, nil
}

func (s *SQLModelInvocationStore) BindModelSelection(ctx context.Context, scope sharedkernel.Scope, binding policyasset.ModelSelectionBinding) error {
	if !validModelSelectionBinding(scope, binding) {
		return ErrModelInvocationConflict
	}
	binding.Selection.Mode = binding.Selection.EffectiveMode()
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_run_model_selection(scope_hash,binding_json,created_at) VALUES(?,?,?) ON CONFLICT(scope_hash) DO NOTHING`), modelSelectionScopeHash(scope), string(raw), time.Now().UTC())
	if err != nil {
		return err
	}
	actual, found, err := s.LookupModelSelection(ctx, scope)
	if err != nil {
		return err
	}
	if !found || actual != binding {
		return ErrModelInvocationConflict
	}
	return nil
}

func (s *memoryModelInvocationStore) LookupModelSelection(ctx context.Context, scope sharedkernel.Scope) (policyasset.ModelSelectionBinding, bool, error) {
	if err := ctx.Err(); err != nil {
		return policyasset.ModelSelectionBinding{}, false, err
	}
	if scope.ValidateTrusted() != nil {
		return policyasset.ModelSelectionBinding{}, false, ErrModelInvocationConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, found := s.selections[modelSelectionScopeHash(scope)]
	if found && !validModelSelectionBinding(scope, b) {
		return policyasset.ModelSelectionBinding{}, false, ErrModelRouteUnavailable
	}
	return b, found, nil
}

func (s *memoryModelInvocationStore) BindModelSelection(ctx context.Context, scope sharedkernel.Scope, b policyasset.ModelSelectionBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validModelSelectionBinding(scope, b) {
		return ErrModelInvocationConflict
	}
	b.Selection.Mode = b.Selection.EffectiveMode()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selections == nil {
		s.selections = map[string]policyasset.ModelSelectionBinding{}
	}
	key := modelSelectionScopeHash(scope)
	if previous, found := s.selections[key]; found && previous != b {
		return ErrModelInvocationConflict
	}
	s.selections[key] = b
	return nil
}

var _ policyasset.ModelSelectionStore = (*SQLModelInvocationStore)(nil)
var _ policyasset.ModelSelectionStore = (*memoryModelInvocationStore)(nil)
