package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Both executable processes and all SQL/authentication facts are isolated.
// This is a declared SDK fixture, not one of the three published business Agents.
func verifyRuntimeCheckpointRecovery(t *testing.T, ctx context.Context, platformBinary, dsn string, db *sql.DB) {
	t.Helper()
	scope := sharedkernel.Scope{TenantID: "recovery-process", DepartmentID: "recovery-dept", ApplicationID: "recovery-app", PrincipalType: "user", PrincipalID: "recovery-user", AgentID: "checkpoint-recovery-fixture", AgentVersionID: "recovery-version", AgentInstanceID: "recovery-install", InstallationID: "recovery-install"}
	iam := identity.NewSQLStore(db)
	for _, err := range []error{
		iam.CreateTenant(ctx, identity.Tenant{ID: scope.TenantID, Code: scope.TenantID, Name: "Recovery fixture", Status: "active", Revision: 1}),
		iam.CreateDepartment(ctx, identity.Department{ID: scope.DepartmentID, TenantID: scope.TenantID, Code: scope.DepartmentID, Name: "Recovery", Status: "active", Revision: 1}),
		iam.CreateApplication(ctx, identity.Application{ID: scope.ApplicationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, Code: scope.ApplicationID, Name: "Recovery", Status: "active", Revision: 1}),
		iam.CreatePrincipal(ctx, identity.Principal{ID: "recovery-manager", Type: identity.PrincipalUser, TenantID: scope.TenantID, IsActive: true}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	machine, secret, session := seedRuntimeGoIdentityForMachine(t, ctx, db, scope, "recovery-manager", "recovery-machine")
	agentAddress, internalAddress := processFreeAddress(t), processFreeAddress(t)
	directory := filepath.Join("..", "..", "..", "sdk", "go")
	agentBinary := filepath.Join(t.TempDir(), "checkpoint-agent")
	command := exec.CommandContext(ctx, "go", "build", "-race", "-o", agentBinary, "./internal/checkpoint-recovery-agent")
	command.Dir = directory
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build recovery fixture: %v %s", err, raw)
	}
	raw, err := os.ReadFile(agentBinary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	artifact := "sha256:" + hex.EncodeToString(digest[:])
	read := func(name string) json.RawMessage {
		raw, err := os.ReadFile(filepath.Join(directory, "internal", "checkpoint-recovery-agent", name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	seedRuntimeCatalog(t, ctx, db, scope, read("manifest.json"), read("input.schema.json"), read("output.schema.json"), artifact, "http://"+agentAddress)
	snapshot := policyasset.Snapshot{ModelProfileID: "go-process-models", PromptVersionID: "recovery-prompt", ToolPolicyID: "recovery-tools", MemoryPolicyID: "go-process-memory", KnowledgePolicyID: "recovery-knowledge", RuntimePolicyID: "recovery-runtime", Revision: 1, Hash: strings.Repeat("c", 64), Model: policyasset.ModelPolicy{Provider: "unused", Model: "unused", MaxTokens: 64, BudgetCents: 1}, Prompt: policyasset.PromptPolicy{Template: "Recover only recorded business state.", TemplateHash: "recovery-prompt"}, Tool: policyasset.ToolPolicy{AllowedTools: []string{"runtime.inspect"}}, Memory: policyasset.MemoryPolicy{WorkingTTLSeconds: 600, TaskTTLSeconds: 600, MaxEntries: 10}, Knowledge: policyasset.KnowledgePolicy{AllowedScopes: []string{"unused"}}, Runtime: policyasset.RuntimePolicy{MaxAttempts: 1, TaskTimeoutSeconds: 90, LeaseSeconds: 2}}
	if err := policyasset.NewSQLResolver(db).Upsert(ctx, scope, snapshot); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stopDirectory := t.TempDir()
	stopKey := make([]byte, 32)
	if _, err := rand.Read(stopKey); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "controller.key")
	if err := os.WriteFile(keyFile, stopKey, 0600); err != nil {
		t.Fatal(err)
	}
	environment := []string{"PLATFORM_INTERNAL_ADDR=" + internalAddress, "PLATFORM_CONTEXT_PUBLIC_KEY=" + base64.StdEncoding.EncodeToString(public), "PLATFORM_CONTEXT_PRIVATE_KEY=" + base64.StdEncoding.EncodeToString(private), "PLATFORM_EXECUTION_STOP_RECEIPT_DIR=" + stopDirectory, "PLATFORM_EXECUTION_STOP_RECEIPT_KEY_FILE=" + keyFile}
	startAgent := func() (*exec.Cmd, <-chan struct{}, time.Time) {
		cmd := exec.CommandContext(ctx, agentBinary)
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		cmd.Env = append(os.Environ(), "AGENT_HTTP_ADDR="+agentAddress, "AGENT_PLATFORM_PUBLIC_KEY_BASE64="+base64.StdEncoding.EncodeToString(public), "PLATFORM_CAPABILITY_URL=http://"+internalAddress, "INTERNAL_TOKEN=fixture-internal-token-with-32-bytes", "INTERNAL_SIGNING_SECRET=fixture-signing-secret-with-32-bytes", "AGENT_CLIENT_ID="+machine, "AGENT_CLIENT_SECRET="+secret, "OTEL_EXPORTER_OTLP_ENDPOINT=")
		started := time.Now().UTC()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		t.Cleanup(func() {
			select {
			case <-done:
			default:
				_ = cmd.Process.Kill()
				<-done
			}
		})
		client := http.Client{Timeout: time.Second}
		waitRuntimeRecovery(t, ctx, "SDK fixture readiness", func() bool {
			select {
			case <-done:
				t.Fatalf("SDK fixture exited before readiness: %s", diagnostics.String())
			default:
			}
			response, err := client.Get("http://" + agentAddress + "/health/ready")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			return response.StatusCode == 200
		})
		return cmd, done, started
	}
	oldAgent, oldDone, started := startAgent()
	const runID = "recovery-process-run"
	launchPlatformFixtureWithControl(t, ctx, platformBinary, dsn, true, environment, func(client *http.Client, address string, crash func()) {
		invokeRuntimeRecovery(t, ctx, client, address, scope, session, "conversation/sessions", map[string]any{"id": "recovery-session", "kind": "qa", "agent_id": scope.AgentID, "agent_version_id": scope.AgentVersionID, "title": "Recovery", "status": "active", "can_continue": true}, 201)
		invokeRuntimeRecovery(t, ctx, client, address, scope, session, "conversation/sessions/recovery-session/runs", map[string]any{"run_id": runID, "idempotency_key": "recovery-command", "request": map[string]any{}}, 202)
		waitRuntimeRecovery(t, ctx, "persisted business effect", func() bool {
			var count int
			err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_business_checkpoint WHERE idempotency_key='effect-recorded' AND revision=1`).Scan(&count)
			return err == nil && count == 1
		})
		// Linux-only runner: freeze the old worker before losing the dispatcher.
		// A transport disconnect alone must not be treated as process exit.
		if err := oldAgent.Process.Signal(syscall.Signal(19)); err != nil {
			t.Fatal("freeze owned Linux SDK worker", err)
		}
		crash() // No graceful graph cancellation or fabricated lease mutation.
	})
	// Let the real persisted owner lease expire; do not edit execution tables.
	time.Sleep(3 * time.Second)
	launchPlatformFixtureWithControl(t, ctx, platformBinary, dsn, true, environment, func(client *http.Client, address string, _ func()) {
		runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer runs.Close()
		var pending platformruntime.Run
		waitRuntimeRecovery(t, ctx, "fenced recovery intent", func() bool {
			var err error
			pending, err = runs.Get(runID)
			return err == nil && pending.Status == platformruntime.StatusRecovering
		})
		if err := oldAgent.Process.Kill(); err != nil {
			t.Fatal("stop owned SDK process", err)
		}
		<-oldDone // Actual OS exit is required BEFORE producing controller evidence.
		stopped := time.Now().UTC()
		hash := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
		body, err := json.Marshal(map[string]any{"schema": "runtime-process-stop/v1", "run_id": runID, "execution_revision": pending.Revision - 1, "lease_token_hash": hash([]byte(pending.LeaseToken)), "request_hash": hash(pending.RequestJSON), "endpoint": pending.AgentEndpoint, "runtime_id": hash([]byte(fmt.Sprintf("owned-sdk-pid-%d", oldAgent.Process.Pid))), "image_digest": artifact, "started_at": started, "stopped_at": stopped, "observed_at": stopped, "running": false, "restart_disabled": true})
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, stopKey)
		_, _ = mac.Write(body)
		envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature": hex.EncodeToString(mac.Sum(nil))})
		path := filepath.Join(stopDirectory, hash([]byte(runID))+".json")
		if err := os.WriteFile(path+".tmp", envelope, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
		startAgent()
		waitRuntimeRecovery(t, ctx, "recovered terminal run", func() bool {
			run, err := runs.Get(runID)
			if err == nil && (run.Status == platformruntime.StatusFailed || run.Status == platformruntime.StatusCancelled) {
				t.Fatalf("recovery reached incorrect terminal status %s", run.Status)
			}
			return err == nil && run.Status == platformruntime.StatusSucceeded
		})
		var output []byte
		if err := db.QueryRowContext(ctx, `SELECT output_json FROM platform_execution_outcome WHERE run_id=$1`, runID).Scan(&output); err != nil {
			t.Fatal(err)
		}
		var result struct {
			Status     string `json:"status"`
			Revision   int    `json:"checkpoint_revision"`
			Sequence   string `json:"sequence"`
			Reexecuted bool   `json:"tool_reexecuted"`
		}
		if json.Unmarshal(output, &result) != nil || result.Status != "recovered" || result.Revision != 2 || result.Sequence != "9007199254740993" || result.Reexecuted {
			t.Fatal("recovered business result mismatch")
		}
		var receipts, versions, proofs int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_tool_invocation WHERE call_id='recovery-inspect' AND status='completed'`).Scan(&receipts); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_business_checkpoint WHERE idempotency_key IN ('effect-recorded','recovery-completed')`).Scan(&versions); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_execution_event WHERE run_id=$1 AND event_type='runtime_process_stop_confirmed'`, runID).Scan(&proofs); err != nil {
			t.Fatal(err)
		}
		if receipts != 1 || versions != 2 || proofs != 1 {
			t.Fatalf("recovery durable counts: tool=%d state=%d stop=%d", receipts, versions, proofs)
		}
	})
}

func waitRuntimeRecovery(t *testing.T, ctx context.Context, label string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal(label + " timed out")
}

func invokeRuntimeRecovery(t *testing.T, ctx context.Context, client *http.Client, address string, scope sharedkernel.Scope, session, path string, value any, want int) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/modules/"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": scope.PrincipalID, "X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Authentication-Revision": "1", "X-Authentication-Session": session, "X-Trace-ID": strings.Repeat("6", 32), "Content-Type": "application/json"} {
		r.Header.Set(name, value)
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("recovery fixture %s HTTP %d want %d", path, response.StatusCode, want)
	}
}
