package capability

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/reversibleapi"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type reversibleTestSecrets map[string]string

func (s reversibleTestSecrets) ResolveSecret(_ context.Context, ref string) ([]byte, error) {
	v, found := s[ref]
	if !found {
		return nil, errors.New("credential unavailable")
	}
	return []byte(v), nil
}

func TestReversibleAPICancellationDurableUndoAndLateWritePostgres(t *testing.T) {
	for _, mode := range []string{"applied", "before_forward", "ack_lost", "other_writer", "wrong_control_credential"} {
		t.Run(mode, func(t *testing.T) {
			f := ownedMemoryUndo(t)
			if err := reversibleapi.Migrate(f.ctx, f.db); err != nil {
				t.Fatal(err)
			}
			credentials := reversibleTestSecrets{"forward": strings.Repeat("f", 32), "control": strings.Repeat("c", 32)}
			owner, err := reversibleapi.New(f.ctx, f.db, reversibleapi.Config{ToolName: "api.state.put", TenantID: f.scope.TenantID, ApplicationID: f.scope.ApplicationID, AgentIDs: []string{f.scope.AgentID}, ForwardToken: []byte(credentials["forward"]), ControlToken: []byte(credentials["control"])})
			if err != nil {
				t.Fatal(err)
			}
			var applies, undos atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Decode in a recorder and restore the immutable body before handing
				// to the actual SQL API owner; no model/provider response fixture.
				var q reversibleapi.Request
				json.NewDecoder(r.Body).Decode(&q)
				raw, _ := json.Marshal(q)
				r.Body = http.NoBody
				r.Body = io.NopCloser(bytes.NewReader(raw))
				if q.Action == "apply" {
					applies.Add(1)
				}
				if q.Action == "undo" && undos.Add(1) == 1 && mode == "ack_lost" {
					recorder := httptest.NewRecorder()
					owner.ServeHTTP(recorder, r)
					if recorder.Code != 200 {
						t.Error("undo did not commit")
					}
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					connection.Close()
					return
				}
				owner.ServeHTTP(w, r)
			}))
			defer server.Close()
			provider, err := NewReversibleAPIToolProvider([]ReversibleAPIBinding{{ToolName: "api.state.put", Endpoint: server.URL, TenantID: f.scope.TenantID, ApplicationID: f.scope.ApplicationID, AgentIDs: []string{f.scope.AgentID}, TimeoutSeconds: 3, ForwardSecretRef: "forward", ControlSecretRef: "control"}}, credentials, true, func(string, bool) (*http.Client, error) {
				return &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			tools, err := NewSQLToolInvocationStore(f.db)
			if err != nil {
				t.Fatal(err)
			}
			if err = tools.EnsureSchema(f.ctx); err != nil {
				t.Fatal(err)
			}
			inverse, err := provider.CancellationBinding(f.coordinator, tools)
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{"key": "case-status", "value": "draft"}
			fp, _ := ToolCommandFingerprint("api.state.put", payload)
			descriptor, _ := provider.DescribeTool("api.state.put")
			q := ToolReceiptQuery{Scope: f.scope, Name: "api.state.put", CallID: "api-call", Fingerprint: fp, RuntimeAudit: &ToolRuntimeAuditBinding{Descriptor: descriptor, PolicyHash: strings.Repeat("a", 64)}}
			step, err := inverse.Step(q)
			if err != nil {
				t.Fatal(err)
			}
			tools.SetExecutionAdmission(func(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope) error {
				return memoryCompensationAuthority{}.guard(ctx, tx, s, "running")
			})
			if err = tools.SetCancellationRegistrar(func(ctx context.Context, tx *sql.Tx, q ToolReceiptQuery) error {
				s, err := inverse.Step(q)
				if err != nil {
					return err
				}
				return f.coordinator.RegisterTx(ctx, tx, s)
			}); err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(f.ctx, toolReceiptContextKey{}, q)
			invocation, _, err := tools.AcquireTool(ctx, ToolReceiptScopeHash(f.scope), q.CallID, fp, "api-fixture", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err = tools.BeginTool(ctx, invocation.Lease); err != nil {
				t.Fatal(err)
			}
			if mode != "before_forward" {
				if result, err := provider.request(f.ctx, step, "apply", payload); err != nil || result.State != "applied" {
					t.Fatal("forward failed", err)
				}
			}
			if mode == "other_writer" {
				if _, err = f.db.ExecContext(f.ctx, `UPDATE reversible_api.value SET owner_stamp='concurrent-writer' WHERE owner_stamp=$1`, step.ID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "wrong_control_credential" {
				credentials["control"] = strings.Repeat("x", 32)
			}
			if _, _, err = inverse.Registration.Port.Lookup(f.ctx, step); err == nil {
				t.Fatal("unbound context obtained inverse authority")
			}
			f.stop(t)
			engine, err := compensation.NewEngine(f.coordinator, "api-compensation-worker", inverse.Registration)
			if err != nil {
				t.Fatal(err)
			}
			if handled, err := engine.Tick(f.ctx, f.scope); err != nil || !handled {
				t.Fatal(err)
			}
			if mode == "ack_lost" {
				if err = f.coordinator.TryFinalize(f.ctx, f.scope); err == nil {
					t.Fatal("lost acknowledgement finalized without receipt")
				}
				if _, err = f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_compensation_step SET retry_at=clock_timestamp() WHERE step_id=?`), step.ID); err != nil {
					t.Fatal(err)
				}
				if handled, err := engine.Tick(f.ctx, f.scope); err != nil || !handled {
					t.Fatal(err)
				}
				if undos.Load() != 1 {
					t.Fatal("lost acknowledgement replayed undo")
				}
			}
			progress, _, err := f.coordinator.Progress(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "other_writer" || mode == "wrong_control_credential" {
				if progress.Unresolved != 1 || progress.Compensated != 0 || progress.NoEffect != 0 {
					t.Fatal("unverified inverse accepted", progress)
				}
				if err = f.coordinator.TryFinalize(f.ctx, f.scope); err == nil {
					t.Fatal("unsafe cancellation finalized")
				}
			} else {
				if progress.Unresolved != 0 {
					t.Fatal("undo incomplete", progress)
				}
				if err = f.coordinator.TryFinalize(f.ctx, f.scope); err != nil {
					t.Fatal(err)
				}
				if result, err := provider.request(f.ctx, step, "apply", payload); err == nil || result.State == "applied" {
					t.Fatal("late forward resurrected reversed effect")
				}
			}
		})
	}
}
