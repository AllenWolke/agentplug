package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/usagecost"
)

type runtimeModelTarget struct {
	Model, SecretFile, BaseURL string
	Live                       bool
}

// Credentials remain in owned temporary mounts; only model names and clean
// HTTPS targets leave the operator's ignored credential directory.
func runtimeLiveModelTargets(t *testing.T, destination string) (runtimeModelTarget, runtimeModelTarget) {
	t.Helper()
	root := filepath.Join("..", "..", "..", ".local-secrets", "model-providers", "runtime-mounts")
	read := func(name string) []byte {
		t.Helper()
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16384 {
			t.Fatal("regular bounded local model configuration required; secret suppressed")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("local model configuration unavailable; secret suppressed")
		}
		return raw
	}
	var config struct {
		Embedding struct{ Model, BaseURL, KeyFile string }
		LLM       struct{ Model, BaseURL, KeyFile string }
	}
	// The public configuration uses snake_case while key contents stay separate.
	var data map[string]struct {
		Model   string `json:"model"`
		BaseURL string `json:"base_url"`
		KeyFile string `json:"key_file"`
	}
	if json.Unmarshal(read("providers.json"), &data) != nil || len(data) != 2 {
		t.Fatal("two local model metadata entries required")
	}
	config.Embedding.Model, config.Embedding.BaseURL, config.Embedding.KeyFile = data["embedding"].Model, data["embedding"].BaseURL, data["embedding"].KeyFile
	config.LLM.Model, config.LLM.BaseURL, config.LLM.KeyFile = data["llm"].Model, data["llm"].BaseURL, data["llm"].KeyFile
	prepare := func(model, endpoint, inputFile, expectedFile, outputFile string) runtimeModelTarget {
		t.Helper()
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || inputFile != expectedFile || strings.TrimSpace(model) == "" {
			t.Fatal("clean operator-provided HTTPS model metadata required")
		}
		if u.Hostname() != "api.deepseek.com" && !strings.HasSuffix(u.Hostname(), ".maas.aliyuncs.com") {
			t.Fatal("operator's approved model host required")
		}
		key := strings.TrimSpace(string(read(inputFile)))
		for _, c := range key {
			if c < 33 || c > 126 {
				t.Fatal("pure local API credential required; secret suppressed")
			}
		}
		if key == "" || len(key) > 8192 || os.WriteFile(filepath.Join(destination, outputFile), []byte(key), 0600) != nil {
			t.Fatal("temporary model credential mount unavailable; secret suppressed")
		}
		return runtimeModelTarget{Model: model, SecretFile: outputFile, BaseURL: strings.TrimRight(endpoint, "/"), Live: true}
	}
	return prepare(config.LLM.Model, config.LLM.BaseURL, config.LLM.KeyFile, "deepseek.key", "go-live-chat.key"),
		prepare(config.Embedding.Model, config.Embedding.BaseURL, config.Embedding.KeyFile, "embedding.key", "go-live-embedding.key")
}

type runtimeKnowledgeReplay struct {
	server                                 *httptest.Server
	mu                                     sync.Mutex
	done, hits                             bool
	before, after, savedInput, savedOutput int64
	queryStages                            int64
	repeatStatus                           int
	rewriteHit, embeddingHit, rerankingHit bool
	retrievalHit                           bool
	failure                                string
	deniedRoute                            string
	answer                                 *runtimeAnswerCacheProof
}

func settledRuntimeModels(ctx context.Context, db *sql.DB, chat, embedding string) (int64, int64, int64, int64, error) {
	var count, input, output, cost int64
	err := db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM((response_json::jsonb->'usage'->>'input_tokens')::bigint),0),COALESCE(SUM((response_json::jsonb->'usage'->>'output_tokens')::bigint),0),COALESCE(SUM((response_json::jsonb->'billing'->>'cost_micros')::bigint),0) FROM platform_model_invocation WHERE status='completed' AND billing_state='done' AND response_json::jsonb->>'model_version_id' IN ($1,$2)`, chat, embedding).Scan(&count, &input, &output, &cost)
	return count, input, output, cost, err
}

func settledRuntimeModelsForRun(ctx context.Context, db *sql.DB, chat, embedding, runID string) (int64, int64, int64, int64, error) {
	var count, input, output, cost int64
	err := db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM((response_json::jsonb->'usage'->>'input_tokens')::bigint),0),COALESCE(SUM((response_json::jsonb->'usage'->>'output_tokens')::bigint),0),COALESCE(SUM((response_json::jsonb->'billing'->>'cost_micros')::bigint),0) FROM platform_model_invocation WHERE status='completed' AND billing_state='done' AND response_json::jsonb->>'model_version_id' IN ($1,$2) AND billing_recovery_json::jsonb->'reservation'->>'run_id'=$3`, chat, embedding, runID).Scan(&count, &input, &output, &cost)
	return count, input, output, cost, err
}

func settledRuntimeBudgetForRun(ctx context.Context, db *sql.DB, runID string) (int64, int64, error) {
	var count, settled int64
	err := db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(settled_micros),0) FROM platform_model_budget_reservation WHERE run_id=$1 AND status='settled'`, runID).Scan(&count, &settled)
	return count, settled, err
}

// Usage snapshots are keyed by tenant/department/application/agent/version;
// run-level evidence must instead aggregate immutable events with all six
// scope dimensions, including RunID.
func settledRuntimeUsageForRun(ctx context.Context, db *sql.DB, scope usagecost.Scope) (int64, int64, int64, int64, error) {
	var count, input, output, cost int64
	err := db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(input_tokens),0),COALESCE(SUM(output_tokens),0),COALESCE(SUM(cost_micros),0) FROM platform_usage_event WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND agent_id=$4 AND agent_version_id=$5 AND run_id=$6`,
		scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, scope.RunID).Scan(&count, &input, &output, &cost)
	return count, input, output, cost, err
}

// This trusted test proxy repeats only the already signed knowledge request,
// while its platform run is live. It never changes scope or bypasses IAM. The
// repeat exercises actual cache receipts, not just model idempotency replay.
func newRuntimeKnowledgeReplay(t *testing.T, db *sql.DB, address, chat, embedding string) *runtimeKnowledgeReplay {
	t.Helper()
	proof := &runtimeKnowledgeReplay{}
	client := &http.Client{Timeout: 150 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	proof.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			http.Error(w, "bounded fixture request required", 400)
			return
		}
		forward := func() (int, []byte, error) {
			request, err := http.NewRequestWithContext(r.Context(), r.Method, "http://"+address+r.URL.RequestURI(), bytes.NewReader(body))
			if err != nil {
				return 0, nil, err
			}
			request.Header = r.Header.Clone()
			response, err := client.Do(request)
			if err != nil {
				return 0, nil, err
			}
			defer response.Body.Close()
			encoded, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
			if len(encoded) > 8<<20 {
				return 0, nil, errors.New("bounded fixture response required")
			}
			return response.StatusCode, encoded, err
		}
		status, encoded, err := forward()
		if err != nil {
			http.Error(w, "platform fixture forwarding failed", 502)
			return
		}
		if status >= http.StatusBadRequest {
			var envelope struct {
				ErrorCode string `json:"error_code"`
			}
			if json.Unmarshal(encoded, &envelope) == nil && envelope.ErrorCode != "" && len(envelope.ErrorCode) <= 64 && strings.IndexFunc(envelope.ErrorCode, func(r rune) bool {
				return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
			}) < 0 {
				proof.mu.Lock()
				if proof.deniedRoute == "" {
					proof.deniedRoute = fmt.Sprintf("route=%s status=%d code=%s", r.URL.Path, status, envelope.ErrorCode)
				}
				proof.mu.Unlock()
			}
		}
		if r.URL.Path == "/internal/knowledge/search" && status == 200 {
			proof.mu.Lock()
			defer proof.mu.Unlock()
			if !proof.done {
				proof.done = true
				before, _, _, _, beforeErr := settledRuntimeModels(r.Context(), db, chat, embedding)
				repeatedStatus, repeated, repeatErr := forward()
				after, _, _, _, afterErr := settledRuntimeModels(r.Context(), db, chat, embedding)
				proof.before, proof.after, proof.repeatStatus = before, after, repeatedStatus
				var result struct {
					Data struct {
						References []map[string]any `json:"references"`
					} `json:"data"`
				}
				decoded := json.Unmarshal(repeated, &result) == nil
				refs := len(result.Data.References)
				if decoded && refs == 1 {
					ref := result.Data.References[0]
					proof.rewriteHit = ref["rewrite_cache_hit"] == true
					proof.embeddingHit = ref["embedding_cache_hit"] == true
					proof.rerankingHit = ref["reranking_cache_hit"] == true
					proof.retrievalHit = ref["retrieval_cache_hit"] == true
				}
				// The global count includes the index task, which uses this same
				// approved embedding model before the business Run starts. Assert
				// stability across the repeated query, and use immutable Run
				// attribution below for the exact three query-stage records; do not
				// couple cache correctness to the indexer's batch count.
				// This fixture indexes one 352-rune source with a 4096-rune window,
				// so the aggregate at this point is one index embedding plus the
				// three business query stages. The Run-scoped count below verifies
				// the latter independently of the index task.
				invocationsStable := beforeErr == nil && afterErr == nil && before == 4 && before == after
				receiptsHit := decoded && refs == 1 && proof.rewriteHit && proof.embeddingHit && proof.rerankingHit
				// Billing keeps the immutable Run attribution. Query receipt IDs
				// are added after persistence, so they cannot identify a SQL row.
				// The final answer has not started yet: exactly three query-stage
				// records belong to this Run; the index owns a different Run.
				var usageErr error
				proof.queryStages, proof.savedInput, proof.savedOutput, _, usageErr = settledRuntimeModelsForRun(r.Context(), db, chat, embedding, runtimeFixtureBillingRunID("go-process-run"))
				proof.hits = invocationsStable && repeatErr == nil && repeatedStatus == http.StatusOK && receiptsHit && usageErr == nil && proof.queryStages == 3
				if !proof.hits {
					// Only bounded counters and booleans are emitted. Never include
					// request/response bodies, model IDs, invocation IDs or errors.
					proof.failure = fmt.Sprintf("cache proof mismatch: before_models=%d after_models=%d expected_prequery_models=4 model_count_read_ok=%t repeat_status=%d repeat_transport_ok=%t refs=%d receipts_decoded=%t rewrite_hit=%t embedding_hit=%t reranking_hit=%t retrieval_hit=%t query_stage_count=%d query_input_tokens=%d query_output_tokens=%d query_usage_read_ok=%t", before, after, beforeErr == nil && afterErr == nil, repeatedStatus, repeatErr == nil, refs, decoded, proof.rewriteHit, proof.embeddingHit, proof.rerankingHit, proof.retrievalHit, proof.queryStages, proof.savedInput, proof.savedOutput, usageErr == nil)
				}
				if proof.failure == "" && os.Getenv("PLATFORM_TEST_PUBLIC_ANSWER_CACHE") == "1" {
					answer, err := verifyRuntimeAnswerCache(r, body, client, address, db, chat, embedding)
					if err != nil {
						proof.failure = err.Error()
					} else {
						proof.answer = &answer
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(encoded)
	}))
	t.Cleanup(proof.server.Close)
	return proof
}

func writeRuntimeLiveEvidence(t *testing.T, input, output, cost, savedInput, savedOutput int64) {
	t.Helper()
	path := os.Getenv("PLATFORM_TEST_LIVE_EVIDENCE")
	if path == "" {
		t.Fatal("owned live model evidence path required")
	}
	record := map[string]any{
		"result": "PASS", "actual_linux_platform_process": true, "actual_go_sdk_process": true,
		"postgresql_pgvector": true, "embedding_dimensions": 1024, "external_model_invocations_settled": 5,
		"input_tokens": input, "output_tokens": output, "platform_cost_micros": cost,
		"price_scope": "approved teaching ledger price 100000 micros per 1000 input/output tokens; not supplier invoice prices",
		"cache":       map[string]any{"rewrite_hit": true, "embedding_hit": true, "reranking_hit": true, "repeat_model_invocations": 0, "repeat_billed_tokens": 0, "saved_input_tokens": savedInput, "saved_output_tokens": savedOutput, "boundary": "same live authorized run; no cross-run answer cache claim"},
		"checks":      []string{"actual authorized source full index", "query rewriting", "metadata ACL before candidate retrieval", "BM25 and pgvector hybrid", "Top-K", "reranking", "cited answer", "memory persistence", "SDK governed capability calls and lease binding", "idempotent replay", "current Grant revocation", "graceful Agent shutdown"},
		"data":        "only owned operations teaching runbook and synthetic latency question", "credentials_logged": false,
		"catalog_and_policy_metadata": "isolated SQL fixtures; not public approval API acceptance",
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil || os.WriteFile(path, append(raw, '\n'), 0600) != nil {
		t.Fatal("owned live evidence write failed")
	}
}
