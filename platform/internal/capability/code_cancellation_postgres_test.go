package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protocol "github.com/lexagent/code-runtime-contract"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Actual PostgreSQL preregistration/engine, with a named HTTP controller
// fixture. Native sandbox and real IAM startup are separate acceptance gates.
func TestCodeCancellationCleanupProofAndUnknownPostgres(t *testing.T) {
	for _, mode := range []string{"completed", "not_found", "unknown", "cleanup_missing", "wrong_binding", "tampered_metadata"} {
		t.Run(mode, func(t *testing.T) {
			f := ownedMemoryUndo(t)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := protocol.NewSigner(private)
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			binding := CodeBinding{ToolName: "code.python", ControllerID: "controller-proof", ProfileID: "profile-proof", Language: "python", TenantID: f.scope.TenantID, ApplicationID: f.scope.ApplicationID, AgentIDs: []string{f.scope.AgentID}, Limits: protocol.Limits{MemoryBytes: 128 << 20, CPUMilli: 500, CPUSeconds: 5, PIDs: 16, DiskBytes: 8 << 20, TimeoutSeconds: 15, OutputBytes: 64 << 10}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/v1/receipt" || r.Method != "POST" {
					t.Error("cancellation submitted code")
					w.WriteHeader(403)
					return
				}
				var body struct {
					Permit string `json:"permit"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					w.WriteHeader(400)
					return
				}
				permit, err := protocol.Verify(body.Permit, public, binding.ControllerID, "receipt", time.Now())
				if err != nil || permit.Code != "" || permit.LeaseFence != 0 || permit.ProfileID != binding.ProfileID || permit.Limits != binding.Limits || !strings.HasPrefix(permit.ApprovalID, "cancel-control-") {
					t.Error("invalid cancellation control permit")
					w.WriteHeader(403)
					return
				}
				status := "completed"
				var result *protocol.Result
				if mode == "not_found" || mode == "unknown" {
					status = mode
				} else {
					started := time.Now().Add(-time.Millisecond)
					result = &protocol.Result{Version: "code-execution/v1", Status: "succeeded", StartedAt: started, FinishedAt: started.Add(time.Millisecond), DurationMS: 1, Limits: binding.Limits, ContainerRemoved: mode != "cleanup_missing", Stdout: "private business output"}
				}
				fp := permit.Fingerprint
				if mode == "wrong_binding" {
					fp = strings.Repeat("c", 64)
				}
				json.NewEncoder(w).Encode(map[string]any{"version": "code-receipt/v1", "scope_hash": permit.ScopeHash, "tool_name": permit.ToolName, "call_id": permit.CallID, "fingerprint": fp, "status": status, "result": result})
			}))
			defer server.Close()
			binding.Endpoint = server.URL
			provider, err := NewCodeToolProvider([]CodeBinding{binding}, signer, true, func(string, bool) (*http.Client, error) {
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
			fp, _ := protocol.Fingerprint("code.python", "print(20)")
			descriptor, _ := provider.DescribeTool("code.python")
			query := ToolReceiptQuery{Scope: f.scope, Name: "code.python", CallID: "code-call", Fingerprint: fp, RuntimeAudit: &ToolRuntimeAuditBinding{Descriptor: descriptor, PolicyHash: strings.Repeat("a", 64)}}
			step, err := inverse.Step(query)
			if err != nil {
				t.Fatal(err)
			}
			tools.SetExecutionAdmission(func(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope) error {
				return memoryCompensationAuthority{}.guard(ctx, tx, s, "running")
			})
			if err = tools.SetCancellationRegistrar(func(ctx context.Context, tx *sql.Tx, q ToolReceiptQuery) error {
				actual, err := inverse.Step(q)
				if err != nil {
					return err
				}
				return f.coordinator.RegisterTx(ctx, tx, actual)
			}); err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(f.ctx, toolReceiptContextKey{}, query)
			invocation, replay, err := tools.AcquireTool(ctx, ToolReceiptScopeHash(f.scope), query.CallID, fp, "code-fixture", time.Minute)
			if err != nil || replay {
				t.Fatal(err)
			}
			if err = tools.BeginTool(ctx, invocation.Lease); err != nil {
				t.Fatal(err)
			}
			if _, _, err = inverse.Registration.Port.Lookup(f.ctx, step); err == nil {
				t.Fatal("public context obtained control permit")
			}
			if mode == "tampered_metadata" {
				query.RuntimeAudit.Descriptor.Risk = "read_only"
				raw, _ := json.Marshal(query)
				if _, err = f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET recovery_query=? WHERE scope_hash=? AND call_id=?`), string(raw), invocation.ScopeHash, query.CallID); err != nil {
					t.Fatal(err)
				}
			}
			f.stop(t)
			engine, err := compensation.NewEngine(f.coordinator, "code-proof-worker", inverse.Registration)
			if err != nil {
				t.Fatal(err)
			}
			if handled, err := engine.Tick(f.ctx, f.scope); err != nil || !handled {
				t.Fatal("cleanup sweep", err)
			}
			progress, found, err := f.coordinator.Progress(f.ctx, f.scope)
			if err != nil || !found {
				t.Fatal(err)
			}
			if mode == "completed" {
				if progress.NoEffect != 1 || progress.Unresolved != 0 {
					t.Fatal("cleanup proof missing", progress)
				}
				if err = f.coordinator.TryFinalize(f.ctx, f.scope); err != nil {
					t.Fatal(err)
				}
				if requests.Load() != 1 {
					t.Fatal("unnecessary receipt calls")
				}
			} else {
				if progress.NoEffect != 0 || progress.Unresolved != 1 {
					t.Fatal("unproved cleanup accepted", progress)
				}
				if err = f.coordinator.TryFinalize(f.ctx, f.scope); err == nil {
					t.Fatal("unknown cleanup finalized")
				}
				if mode == "tampered_metadata" && requests.Load() != 0 {
					t.Fatal("invalid owner contacted controller")
				}
			}
			var original string
			if err = f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT status FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), invocation.ScopeHash, query.CallID).Scan(&original); err != nil || original != "running" {
				t.Fatal("cleanup rewrote original outcome", original, err)
			}
		})
	}
}

func TestCodeCancellationVersionPinsScopedControllerPolicy(t *testing.T) {
	signer, binding := scopedCodeFixture(t)
	factory := func(string, bool) (*http.Client, error) {
		return &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}, nil
	}
	first, err := NewCodeToolProvider([]CodeBinding{binding}, signer, false, factory)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := first.cancellationVersion()
	if err != nil {
		t.Fatal(err)
	}
	binding.ProfileID = "new-profile"
	second, err := NewCodeToolProvider([]CodeBinding{binding}, signer, false, factory)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := second.cancellationVersion()
	if err != nil || v1 == v2 {
		t.Fatal("policy change reused inverse version")
	}
	if strings.Contains(v1, "example.com") || len(v1) > 128 {
		t.Fatal("private origin exposed")
	}
}
