package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/usagecost"
)

func verifyRuntimeGoExample(t *testing.T, ctx context.Context, db *sql.DB, client *http.Client, address string, f runtimeGoFixture, base runtimeIndexFixture) {
	t.Helper()
	expectedModels := int64(5)
	if f.answerCache {
		expectedModels = 6
	}
	_, port, err := net.SplitHostPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, f.binary)
	command.Env = append(os.Environ(), "PORT="+port, "AGENT_HTTP_ADDR="+f.address, "AGENT_PLATFORM_PUBLIC_KEY_BASE64="+base64.StdEncoding.EncodeToString(f.public), "AGENT_PLATFORM_ISSUER=platform", "AGENT_PLATFORM_AUDIENCE=agent-runtime", "AGENT_PLATFORM_AGENT_ID="+f.scope.AgentID, "PLATFORM_CAPABILITY_URL="+f.capabilityURL, "INTERNAL_TOKEN=fixture-internal-token-with-32-bytes", "INTERNAL_SIGNING_SECRET=fixture-signing-secret-with-32-bytes", "AGENT_CLIENT_ID="+f.machine, "AGENT_CLIENT_SECRET="+f.secret, "OTEL_EXPORTER_OTLP_ENDPOINT=")
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var processErr error
	go func() { processErr = command.Wait(); close(done) }()
	defer func() {
		select {
		case <-done:
			return
		default:
			_ = command.Process.Kill()
			<-done
		}
	}()
	c := *client
	c.Timeout = 5 * time.Second
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := c.Get("http://" + f.address + "/health/ready")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case <-done:
			t.Fatalf("Go process failed before readiness: %v %s", processErr, output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Go example readiness timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	invoke := func(method, path string, value any, actor, session string, want int, target any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/modules/"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": actor, "X-Tenant-ID": f.scope.TenantID, "X-Department-ID": f.scope.DepartmentID, "X-Application-ID": f.scope.ApplicationID, "X-Authentication-Revision": "1", "X-Authentication-Session": session, "X-Trace-ID": strings.Repeat("5", 32), "Content-Type": "application/json"} {
			r.Header.Set(name, value)
		}
		response, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			raw, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
			t.Fatalf("Go process flow %s: status=%d want=%d body=%s", path, response.StatusCode, want, raw)
		}
		if target != nil && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target) != nil {
			t.Fatal("invalid Go flow response")
		}
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "go-operations", "knowledge", "runbook.md"))
	if err != nil {
		t.Fatal(err)
	}
	invoke("PUT", "knowledge/sources/go-operations/documents/runbook", map[string]any{"expected_source_revision": 0, "expected_document_version": 0, "idempotency_key": "go-process-source", "body": string(body), "acl": knowledge.DocumentACL{OwnerPrincipalID: base.scope.PrincipalID, Readers: []string{f.scope.PrincipalID, f.machine}}}, base.scope.PrincipalID, base.session, 200, nil)
	var index knowledge.IndexTaskReceipt
	invoke("POST", "knowledge/indexes/go-operations/tasks", knowledge.IndexTaskRequest{InstallationID: f.scope.InstallationID, IdempotencyKey: "go-process-index", Mode: "full", Config: knowledge.IndexSettings{Dimensions: f.dimensions, WindowRunes: 4096, OverlapRunes: 64, MaximumDocuments: 10, MaximumChunks: 100}}, base.scope.PrincipalID, base.session, 202, &index)
	// Poll through the task's published deadline plus outcome projection time;
	// a cold valid execution must not fail before its configured runtime limit.
	indexWait, runWait := 15*time.Second, time.Duration(f.taskTimeoutSeconds)*time.Second+5*time.Second
	if f.live {
		indexWait, runWait = 90*time.Second, 330*time.Second
	}
	deadline = time.Now().Add(indexWait)
	for {
		var detail knowledge.IndexTaskDetail
		invoke("GET", "knowledge/indexes/go-operations/tasks/"+index.RunID, nil, base.scope.PrincipalID, base.session, 200, &detail)
		if detail.Status == "succeeded" {
			break
		}
		if detail.Status == "failed" {
			t.Fatal("Go knowledge index failed")
		}
		if time.Now().After(deadline) {
			t.Fatalf("Go knowledge index timeout: status=%s revision=%d supplier_calls=%d", detail.Status, detail.Revision, f.calls.Load())
		}
		time.Sleep(100 * time.Millisecond)
	}
	invoke("POST", "conversation/sessions", map[string]any{"id": "go-process-session", "kind": "qa", "agent_id": f.scope.AgentID, "agent_version_id": f.scope.AgentVersionID, "title": "Operations diagnosis", "status": "active", "can_continue": true}, f.scope.PrincipalID, f.session, 201, nil)
	runRequest := map[string]any{"run_id": "go-process-run", "idempotency_key": "go-process-command", "request": map[string]any{"service": "api", "symptom": "latency increased", "observations": "p95=2s"}}
	invoke("POST", "conversation/sessions/go-process-session/runs", runRequest, f.scope.PrincipalID, f.session, 202, nil)
	deadline = time.Now().Add(runWait)
	for {
		var run struct {
			Status string `json:"status"`
		}
		invoke("GET", "execution/platform/runs/go-process-run", nil, f.scope.PrincipalID, f.session, 200, &run)
		if f.live {
			var truncated int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_model_invocation WHERE status='completed' AND billing_state='done' AND response_json::jsonb->>'completion_status'='incomplete' AND response_json::jsonb->>'model_version_id' IN ($1,$2)`, f.chatVersion, f.embeddingVersion).Scan(&truncated); err != nil {
				t.Fatal("live known-output diagnostic unavailable")
			}
			if truncated > 0 {
				t.Fatal("live answer or retrieval output was truncated; known usage settled, full acceptance failed without resend")
			}
			var unresolved int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_model_invocation WHERE status='reconcile' AND billing_state='manual' AND billing_recovery_json::jsonb->'reservation'->>'run_id'=$1`, runtimeFixtureBillingRunID("go-process-run")).Scan(&unresolved); err != nil {
				t.Fatal("live model reconciliation diagnostic unavailable")
			}
			if unresolved > 0 {
				count, input, output, _, _ := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
				t.Fatalf("live supplier result requires manual reconciliation; no resend: run_status=%s unresolved=%d settled_models=%d input_tokens=%d output_tokens=%d", run.Status, unresolved, count, input, output)
			}
		}
		if run.Status == "succeeded" {
			break
		}
		if run.Status == "failed" {
			var event []byte
			_ = db.QueryRowContext(ctx, `SELECT event_payload FROM platform_execution_outcome WHERE run_id='go-process-run'`).Scan(&event)
			f.cache.mu.Lock()
			deniedRoute := f.cache.deniedRoute
			f.cache.mu.Unlock()
			t.Fatalf("Go governed execution failed: %s; safe_denial=%s", event, deniedRoute)
		}
		if time.Now().After(deadline) {
			count, input, output, cost, ledgerErr := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
			t.Fatalf("Go governed execution timeout: status=%s settled_models=%d input_tokens=%d output_tokens=%d cost_micros=%d ledger_available=%t", run.Status, count, input, output, cost, ledgerErr == nil)
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.cache.mu.Lock()
	cacheFailure := f.cache.failure
	f.cache.mu.Unlock()
	if cacheFailure != "" {
		t.Fatal("runtime cache verification failed: " + cacheFailure)
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT output_json FROM platform_execution_outcome WHERE run_id='go-process-run'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Schema      string         `json:"schema"`
		Service     string         `json:"service"`
		Answer      string         `json:"answer"`
		Context     map[string]any `json:"context_checks"`
		NotifyMe    bool           `json:"notify_me"`
		Sandbox     bool           `json:"sandbox_check"`
		Collaborate bool           `json:"collaborate"`
		Knowledge   struct {
			References []map[string]any `json:"references"`
		} `json:"knowledge"`
	}
	var outputFields map[string]json.RawMessage
	resultErr, fieldsErr := json.Unmarshal(raw, &result), json.Unmarshal(raw, &outputFields)
	requiredFields := []string{"schema", "service", "answer", "knowledge", "context_checks", "notify_me", "sandbox_check", "collaborate"}
	requiredFieldsPresent := fieldsErr == nil
	for _, key := range requiredFields {
		if _, ok := outputFields[key]; !ok {
			requiredFieldsPresent = false
		}
	}
	if resultErr != nil || result.Schema != "schema://example-go-operations/output/v2" || result.Service != "api" || strings.TrimSpace(result.Answer) == "" || result.Context == nil || result.NotifyMe || result.Sandbox || result.Collaborate || len(result.Knowledge.References) != 1 || !requiredFieldsPresent {
		t.Fatalf("Go output v2 contract invalid: schema=%q answer_present=%t references=%d context_present=%t required_fields_present=%t option_echoes_false=%t", result.Schema, strings.TrimSpace(result.Answer) != "", len(result.Knowledge.References), result.Context != nil, requiredFieldsPresent, !result.NotifyMe && !result.Sandbox && !result.Collaborate)
	}
	before := f.calls.Load()
	if f.live {
		count, _, _, _, err := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
		if err != nil || count != expectedModels {
			t.Fatal("live RAG invocations not settled", err, count)
		}
		before = int32(count)
	}
	invoke("POST", "conversation/sessions/go-process-session/runs", runRequest, f.scope.PrincipalID, f.session, 202, nil)
	after := f.calls.Load()
	if f.live {
		count, _, _, _, err := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
		if err != nil {
			t.Fatal(err)
		}
		after = int32(count)
	}
	if after != before || int64(before) != expectedModels {
		t.Fatal("Go flow replay sent model or missing RAG stages", before, f.calls.Load())
	}
	countModels, inputTokens, outputTokens, costMicros, ledgerErr := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
	runModels, runInput, runOutput, runCost, runErr := settledRuntimeModelsForRun(ctx, db, f.chatVersion, f.embeddingVersion, runtimeFixtureBillingRunID("go-process-run"))
	indexModels, indexInput, indexOutput, indexCost, indexErr := settledRuntimeModelsForRun(ctx, db, f.chatVersion, f.embeddingVersion, index.RunID)
	runUsageScope := usagecost.Scope{TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID, AgentID: f.scope.AgentID, AgentVersionID: f.scope.AgentVersionID, RunID: "go-process-run"}
	indexUsageScope := usagecost.Scope{TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID, AgentID: f.scope.AgentID, AgentVersionID: f.scope.AgentVersionID, RunID: index.RunID}
	runUsageEvents, runUsageInput, runUsageOutput, runUsageCost, runUsageErr := settledRuntimeUsageForRun(ctx, db, runUsageScope)
	indexUsageEvents, indexUsageInput, indexUsageOutput, indexUsageCost, indexUsageErr := settledRuntimeUsageForRun(ctx, db, indexUsageScope)
	usageStore := usagecost.NewSQLStore(db)
	used, snapshotErr := usageStore.GetSnapshot(ctx, runUsageScope)
	runReservations, runReservedMicros, runBudgetErr := settledRuntimeBudgetForRun(ctx, db, "go-process-run")
	indexReservations, indexReservedMicros, indexBudgetErr := settledRuntimeBudgetForRun(ctx, db, index.RunID)
	usageScopeKey := usagecost.ScopeKey(runUsageScope)
	runUsageMatchesModels := runUsageEvents == runModels && runUsageInput == runInput && runUsageOutput == runOutput && runUsageCost == runCost
	indexUsageMatchesModels := indexUsageEvents == indexModels && indexUsageInput == indexInput && indexUsageOutput == indexOutput && indexUsageCost == indexCost
	snapshotMatchesAgentVersion := used.ScopeKey == usageScopeKey && used.InputTokens == runUsageInput+indexUsageInput && used.OutputTokens == runUsageOutput+indexUsageOutput && used.UsedMicros == runUsageCost+indexUsageCost
	if snapshotErr != nil || runUsageErr != nil || indexUsageErr != nil || ledgerErr != nil || runErr != nil || indexErr != nil || runBudgetErr != nil || indexBudgetErr != nil || countModels != expectedModels || indexModels != 1 || runModels != expectedModels-1 || runReservations != runModels || indexReservations != indexModels || runReservedMicros != runCost || indexReservedMicros != indexCost || countModels != runModels+indexModels || inputTokens != runInput+indexInput || outputTokens != runOutput+indexOutput || costMicros != runCost+indexCost || inputTokens < 1 || outputTokens < 1 || !runUsageMatchesModels || !indexUsageMatchesModels || runUsageEvents+indexUsageEvents != countModels || !snapshotMatchesAgentVersion || runCost != 100*(runInput+runOutput) || costMicros != 100*(inputTokens+outputTokens) {
		t.Fatalf("Go model usage scope mismatch: models_total=%d models_run=%d models_index=%d usage_events_run=%d usage_events_index=%d run_input=%d usage_run_input=%d index_input=%d usage_index_input=%d run_output=%d usage_run_output=%d index_output=%d usage_index_output=%d run_cost=%d usage_run_cost=%d index_cost=%d usage_index_cost=%d snapshot_input=%d snapshot_output=%d snapshot_cost=%d snapshot_scope_match=%t run_reservations=%d index_reservations=%d reads_ok=%t", countModels, runModels, indexModels, runUsageEvents, indexUsageEvents, runInput, runUsageInput, indexInput, indexUsageInput, runOutput, runUsageOutput, indexOutput, indexUsageOutput, runCost, runUsageCost, indexCost, indexUsageCost, used.InputTokens, used.OutputTokens, used.UsedMicros, used.ScopeKey == usageScopeKey, runReservations, indexReservations, snapshotErr == nil && runUsageErr == nil && indexUsageErr == nil && runBudgetErr == nil && indexBudgetErr == nil)
	}
	expectedInput, expectedOutput, expectedCost := int64(100), int64(30), int64(13000)
	if f.answerCache {
		expectedInput, expectedOutput, expectedCost = 120, 40, 16000
	}
	if !f.live && (inputTokens != expectedInput || outputTokens != expectedOutput || costMicros != expectedCost) {
		t.Fatal("loopback fixture usage changed")
	}
	f.cache.mu.Lock()
	cacheOK := f.cache.done && f.cache.hits && f.cache.failure == "" && f.cache.savedInput+f.cache.savedOutput > 0
	cacheInput, cacheOutput := f.cache.savedInput, f.cache.savedOutput
	f.cache.mu.Unlock()
	if !cacheOK {
		t.Fatal("RAG cache repeat did not hit all three stages without model sends")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_memory_entry WHERE value_json::jsonb->>'service'='api'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("Go memory not persisted", err, count)
	}
	// Directly changing a fixture's Grant is not the public authorization API.
	// It checks current enforcement without claiming preview/CAS grant workflow.
	if _, err := db.ExecContext(ctx, `UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, f.scope.PrincipalID+"-go-run"); err != nil {
		t.Fatal(err)
	}
	invoke("POST", "conversation/sessions/go-process-session/runs", runRequest, f.scope.PrincipalID, f.session, 403, nil)
	after = f.calls.Load()
	if f.live {
		count, _, _, _, err := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
		if err != nil {
			t.Fatal(err)
		}
		after = int32(count)
	}
	if after != before {
		t.Fatal("revoked replay reached model")
	}
	if err := command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if processErr != nil {
			t.Fatal("Go example graceful shutdown failed", processErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Go example did not stop")
	}
	if f.live {
		writeRuntimeLiveEvidence(t, inputTokens, outputTokens, costMicros, cacheInput, cacheOutput)
	}
	if f.answerCache {
		f.cache.mu.Lock()
		proof := f.cache.answer
		f.cache.mu.Unlock()
		if proof == nil {
			t.Fatal("actual public answer cache proof absent")
		}
		proof.TotalModelInvocations, proof.TotalInputTokens, proof.TotalOutputTokens, proof.TotalCostMicros = countModels, inputTokens, outputTokens, costMicros
		raw, err := json.MarshalIndent(proof, "", "  ")
		if err != nil || os.WriteFile(os.Getenv("PLATFORM_TEST_PUBLIC_ANSWER_EVIDENCE"), append(raw, '\n'), 0600) != nil {
			t.Fatal("answer evidence write failed")
		}
	}
}
