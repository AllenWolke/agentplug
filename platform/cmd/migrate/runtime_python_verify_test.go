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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/usagecost"
)

// The host driver launches the existing formal Python image with these private
// credentials, in the disposable database's network namespace. No Docker socket
// or project database is exposed to the platform test process or the Agent.
func verifyRuntimePythonExample(t *testing.T, ctx context.Context, db *sql.DB, client *http.Client, address string, f runtimeGoFixture, base runtimeIndexFixture) {
	t.Helper()
	_, port, err := net.SplitHostPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]string{
		"PORT": port, "APP_ENV": "production", "AGENT_PLATFORM_PUBLIC_KEY_BASE64": base64.StdEncoding.EncodeToString(f.public),
		"AGENT_PLATFORM_ISSUER": "platform", "AGENT_PLATFORM_AUDIENCE": "agent-runtime",
		"PLATFORM_CAPABILITY_URL": f.capabilityURL, "INTERNAL_TOKEN": "fixture-internal-token-with-32-bytes",
		"INTERNAL_SIGNING_SECRET": "fixture-signing-secret-with-32-bytes", "AGENT_CLIENT_ID": f.machine, "AGENT_CLIENT_SECRET": f.secret,
		"OTEL_EXPORTER_OTLP_ENDPOINT": "",
	}
	raw, err := json.Marshal(config)
	configPath := os.Getenv("PLATFORM_TEST_PYTHON_RUNTIME_CONFIG")
	if err != nil || os.WriteFile(configPath+".pending", raw, 0600) != nil || os.Rename(configPath+".pending", configPath) != nil {
		t.Fatal("private Python runtime handoff failed")
	}
	c := *client
	c.Timeout = 5 * time.Second
	deadline := time.Now().Add(25 * time.Second)
	for {
		response, err := c.Get("http://" + f.address + "/health/ready")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("formal Python image readiness timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	invoke := func(method, path string, value any, actor, session string, want int, target any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, method, "http://"+address+"/modules/"+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{"X-Internal-Token": "gateway-fixture-0123456789abcdef0123456789abcdef", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": actor, "X-Tenant-ID": f.scope.TenantID, "X-Department-ID": f.scope.DepartmentID, "X-Application-ID": f.scope.ApplicationID, "X-Authentication-Revision": "1", "X-Authentication-Session": session, "X-Trace-ID": strings.Repeat("5", 32), "Content-Type": "application/json"} {
			request.Header.Set(name, value)
		}
		response, err := c.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			data, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
			t.Fatalf("Python flow %s status=%d want=%d body=%s", path, response.StatusCode, want, data)
		}
		if target != nil && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target) != nil {
			t.Fatal("invalid Python flow response")
		}
	}
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "python-documents", "knowledge", "handbook.md"))
	if err != nil {
		t.Fatal(err)
	}
	invoke("PUT", "knowledge/sources/python-documents/documents/runbook", map[string]any{"expected_source_revision": 0, "expected_document_version": 0, "idempotency_key": "python-process-source", "body": string(body), "acl": knowledge.DocumentACL{OwnerPrincipalID: base.scope.PrincipalID, Readers: []string{f.scope.PrincipalID, f.machine}}}, base.scope.PrincipalID, base.session, 200, nil)
	var index knowledge.IndexTaskReceipt
	invoke("POST", "knowledge/indexes/python-documents/tasks", knowledge.IndexTaskRequest{InstallationID: f.scope.InstallationID, IdempotencyKey: "python-process-index", Mode: "full", Config: knowledge.IndexSettings{Dimensions: f.dimensions, WindowRunes: 4096, OverlapRunes: 64, MaximumDocuments: 10, MaximumChunks: 100}}, base.scope.PrincipalID, base.session, 202, &index)
	// The published runtime policy allows a 60-second task. The old 25-second
	// polling window could fail a valid, still-running cold process before its
	// actual task deadline; allow five seconds for terminal outcome projection.
	indexWait, runWait := 20*time.Second, time.Duration(f.taskTimeoutSeconds)*time.Second+5*time.Second
	if f.live {
		indexWait, runWait = 90*time.Second, 330*time.Second
	}
	deadline = time.Now().Add(indexWait)
	for {
		var detail knowledge.IndexTaskDetail
		invoke("GET", "knowledge/indexes/python-documents/tasks/"+index.RunID, nil, base.scope.PrincipalID, base.session, 200, &detail)
		if detail.Status == "succeeded" {
			break
		}
		if detail.Status == "failed" || time.Now().After(deadline) {
			t.Fatalf("Python index incomplete: %s", detail.Status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	invoke("POST", "conversation/sessions", map[string]any{"id": "python-process-session", "kind": "qa", "agent_id": f.scope.AgentID, "agent_version_id": f.scope.AgentVersionID, "title": "Owned document teaching query", "status": "active", "can_continue": true}, f.scope.PrincipalID, f.session, 201, nil)
	request := map[string]any{"run_id": "python-process-run", "idempotency_key": "python-process-command", "request": map[string]any{"question": "How are knowledge index versions and access permissions checked?", "top_k": 1, "cache_mode": "use"}}
	if f.toolLoop {
		request["request"].(map[string]any)["workflow_mode"] = "tool_loop"
	}
	invoke("POST", "conversation/sessions/python-process-session/runs", request, f.scope.PrincipalID, f.session, 202, nil)
	deadline = time.Now().Add(runWait)
	for {
		var state struct {
			Status string `json:"status"`
		}
		invoke("GET", "execution/platform/runs/python-process-run", nil, f.scope.PrincipalID, f.session, 200, &state)
		if f.live {
			var unresolved int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_model_invocation WHERE (status='reconcile' AND billing_state='manual') OR (status='completed' AND billing_state='done' AND response_json::jsonb->>'completion_status'='incomplete')`).Scan(&unresolved); err != nil || unresolved > 0 {
				t.Fatal("external result truncated or uncertain; no automatic resend", err, unresolved)
			}
		}
		if state.Status == "succeeded" {
			break
		}
		if state.Status == "failed" || time.Now().After(deadline) {
			var outcome []byte
			_ = db.QueryRowContext(ctx, `SELECT event_payload FROM platform_execution_outcome WHERE run_id='python-process-run'`).Scan(&outcome)
			t.Fatalf("Python execution incomplete status=%s outcome=%s", state.Status, outcome)
		}
		time.Sleep(100 * time.Millisecond)
	}
	var output []byte
	if err := db.QueryRowContext(ctx, `SELECT output_json FROM platform_execution_outcome WHERE run_id='python-process-run'`).Scan(&output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Schema       string           `json:"schema"`
		Question     string           `json:"question"`
		Answer       string           `json:"answer"`
		References   []map[string]any `json:"references"`
		RetrievedIDs []string         `json:"retrieved_ids"`
		CitationIDs  []string         `json:"citation_ids"`
		Citations    []map[string]any `json:"evaluation_citations"`
		Claims       []struct {
			Text string `json:"text"`
		} `json:"evaluation_claims"`
		AnswerCacheHit bool           `json:"answer_cache_hit"`
		Usage          map[string]any `json:"usage"`
		Billing        map[string]any `json:"billing"`
		Collaborate    bool           `json:"collaborate"`
	}
	var outputFields map[string]json.RawMessage
	resultErr, fieldsErr := json.Unmarshal(output, &result), json.Unmarshal(output, &outputFields)
	requiredFields := []string{"schema", "question", "answer", "references", "retrieved_ids", "citation_ids", "evaluation_citations", "evaluation_claims", "answer_cache_hit", "usage", "billing", "collaborate", "model_metadata"}
	requiredFieldsPresent := fieldsErr == nil
	for _, key := range requiredFields {
		if _, ok := outputFields[key]; !ok {
			requiredFieldsPresent = false
		}
	}
	const expectedQuestion = "How are knowledge index versions and access permissions checked?"
	citationMatchesRetrieved := len(result.CitationIDs) == 1 && len(result.RetrievedIDs) == 1 && result.CitationIDs[0] == result.RetrievedIDs[0]
	claimMatchesAnswer := len(result.Claims) == 1 && result.Claims[0].Text == result.Answer
	if resultErr != nil || result.Schema != "schema://example-python-documents/output/v3" || result.Question != expectedQuestion || strings.TrimSpace(result.Answer) == "" || len(result.References) != 1 || len(result.RetrievedIDs) != len(result.References) || len(result.CitationIDs) != 1 || len(result.Citations) != 1 || !citationMatchesRetrieved || !claimMatchesAnswer || result.AnswerCacheHit || result.Usage == nil || result.Billing == nil || result.Collaborate || !requiredFieldsPresent {
		t.Fatalf("Python output v3 contract invalid: schema=%q answer_present=%t references=%d retrieved_ids=%d citation_ids=%d evaluation_citations=%d claims=%d citation_matches=%t claim_matches=%t answer_cache_hit=%t usage_object=%t billing_object=%t collaborate=%t required_fields_present=%t", result.Schema, strings.TrimSpace(result.Answer) != "", len(result.References), len(result.RetrievedIDs), len(result.CitationIDs), len(result.Citations), len(result.Claims), citationMatchesRetrieved, claimMatchesAnswer, result.AnswerCacheHit, result.Usage != nil, result.Billing != nil, result.Collaborate, requiredFieldsPresent)
	}
	count, input, generated, cost, err := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
	runCount, runInput, runOutput, runCost, runErr := settledRuntimeModelsForRun(ctx, db, f.chatVersion, f.embeddingVersion, runtimeFixtureBillingRunID("python-process-run"))
	indexCount, indexInput, indexOutput, indexCost, indexErr := settledRuntimeModelsForRun(ctx, db, f.chatVersion, f.embeddingVersion, index.RunID)
	runUsageScope := usagecost.Scope{TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID, AgentID: f.scope.AgentID, AgentVersionID: f.scope.AgentVersionID, RunID: "python-process-run"}
	indexUsageScope := usagecost.Scope{TenantID: f.scope.TenantID, DepartmentID: f.scope.DepartmentID, ApplicationID: f.scope.ApplicationID, AgentID: f.scope.AgentID, AgentVersionID: f.scope.AgentVersionID, RunID: index.RunID}
	runUsageEvents, runUsageInput, runUsageOutput, runUsageCost, runUsageErr := settledRuntimeUsageForRun(ctx, db, runUsageScope)
	indexUsageEvents, indexUsageInput, indexUsageOutput, indexUsageCost, indexUsageErr := settledRuntimeUsageForRun(ctx, db, indexUsageScope)
	usageStore := usagecost.NewSQLStore(db)
	used, snapshotErr := usageStore.GetSnapshot(ctx, runUsageScope)
	runReservations, runReservedMicros, runBudgetErr := settledRuntimeBudgetForRun(ctx, db, "python-process-run")
	indexReservations, indexReservedMicros, indexBudgetErr := settledRuntimeBudgetForRun(ctx, db, index.RunID)
	usageScopeKey := usagecost.ScopeKey(runUsageScope)
	runUsageMatchesModels := runUsageEvents == runCount && runUsageInput == runInput && runUsageOutput == runOutput && runUsageCost == runCost
	indexUsageMatchesModels := indexUsageEvents == indexCount && indexUsageInput == indexInput && indexUsageOutput == indexOutput && indexUsageCost == indexCost
	snapshotMatchesAgentVersion := used.ScopeKey == usageScopeKey && used.InputTokens == runUsageInput+indexUsageInput && used.OutputTokens == runUsageOutput+indexUsageOutput && used.UsedMicros == runUsageCost+indexUsageCost
	expectedModels, expectedInput, expectedOutput, expectedCost := int64(5), int64(100), int64(30), int64(13000)
	if f.toolLoop {
		expectedModels, expectedInput, expectedOutput, expectedCost = 7, 140, 50, 19000
		assertRuntimeToolLoopReceipt(t, ctx, db)
	}
	if err != nil || runErr != nil || indexErr != nil || snapshotErr != nil || runUsageErr != nil || indexUsageErr != nil || runBudgetErr != nil || indexBudgetErr != nil || count != expectedModels || runCount != expectedModels-1 || indexCount != 1 || runReservations != runCount || indexReservations != indexCount || runReservedMicros != runCost || indexReservedMicros != indexCost || count != runCount+indexCount || input != runInput+indexInput || generated != runOutput+indexOutput || cost != runCost+indexCost || input < 1 || generated < 1 || !runUsageMatchesModels || !indexUsageMatchesModels || runUsageEvents+indexUsageEvents != count || !snapshotMatchesAgentVersion || runCost != 100*(runInput+runOutput) || cost != 100*(input+generated) || (!f.live && (input != expectedInput || generated != expectedOutput || cost != expectedCost)) {
		t.Fatalf("Python model invocation scope mismatch: models_total=%d models_run=%d models_index=%d usage_events_run=%d usage_events_index=%d run_input=%d usage_run_input=%d index_input=%d usage_index_input=%d run_output=%d usage_run_output=%d index_output=%d usage_index_output=%d run_cost=%d usage_run_cost=%d index_cost=%d usage_index_cost=%d snapshot_input=%d snapshot_output=%d snapshot_cost=%d snapshot_scope_match=%t run_reservations=%d index_reservations=%d reads_ok=%t", count, runCount, indexCount, runUsageEvents, indexUsageEvents, runInput, runUsageInput, indexInput, indexUsageInput, runOutput, runUsageOutput, indexOutput, indexUsageOutput, runCost, runUsageCost, indexCost, indexUsageCost, used.InputTokens, used.OutputTokens, used.UsedMicros, used.ScopeKey == usageScopeKey, runReservations, indexReservations, err == nil && runErr == nil && indexErr == nil && snapshotErr == nil && runUsageErr == nil && indexUsageErr == nil && runBudgetErr == nil && indexBudgetErr == nil)
	}
	var memory int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_memory_entry WHERE value_json::jsonb->>'answer'=$1`, result.Answer).Scan(&memory); err != nil || memory != 1 {
		t.Fatal("Python memory not durable", err, memory)
	}
	invoke("POST", "conversation/sessions/python-process-session/runs", request, f.scope.PrincipalID, f.session, 202, nil)
	after, _, _, _, err := settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
	if err != nil || after != count {
		t.Fatal("Python idempotent replay resent model", err, after)
	}
	if _, err := db.ExecContext(ctx, `UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id=$1`, f.scope.PrincipalID+"-go-run"); err != nil {
		t.Fatal(err)
	}
	invoke("POST", "conversation/sessions/python-process-session/runs", request, f.scope.PrincipalID, f.session, 403, nil)
	after, _, _, _, err = settledRuntimeModels(ctx, db, f.chatVersion, f.embeddingVersion)
	if err != nil || after != count {
		t.Fatal("Python revoked replay reached model", err, after)
	}
	proof := map[string]any{"result": "PASS", "agent_id": f.scope.AgentID, "image_id": os.Getenv("PLATFORM_TEST_PYTHON_ARTIFACT"), "model_invocations": count, "input_tokens": input, "output_tokens": generated, "cost_micros": cost, "references": len(result.References), "whole_answer_claim": true, "durable_memory": true, "idempotent_replay_no_model_send": true, "revoked_replay_denied": true, "scope": "Actual formal Python image/repository SDK, Linux platform process, PostgreSQL pgvector source/index/ACL, signed renewed context, model policies and invocation/budget/usage ledgers. Controlled loopback supplier and seeded Catalog/IAM authentication; not external semantic Evaluation, five-account login or complete task 3."}
	raw, err = json.MarshalIndent(proof, "", "  ")
	if f.live {
		proof["external_models"] = true
		proof["scope"] = "Actual formal Python image/repository SDK/Linux platform/PostgreSQL pgvector/caller-machine IAM/current contexts and SQL governed invocation-budget-usage ledgers with operator-approved external LLM and embeddings. Owned handbook and query only; independent RAG Evaluation, five-account login and complete task 3 remain unaccepted."
		raw, err = json.MarshalIndent(proof, "", "  ")
	}
	if err != nil || os.WriteFile(os.Getenv("PLATFORM_TEST_PYTHON_EVIDENCE"), append(raw, '\n'), 0600) != nil {
		t.Fatal("Python evidence write failed")
	}
}
