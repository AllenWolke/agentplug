package evaluationproduct

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Uses the repository's actual metric-service binary and built-in lexical
// entailment implementation. It never substitutes an HTTP score response.
func realRAGMetricEvaluator(t *testing.T) RemoteMetricEvaluator {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	binary := filepath.Join(t.TempDir(), "metric-service")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/metric-service")
	build.Dir = filepath.Join("..", "..", "..", "workers", "metric-runner")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual metric worker: %v %s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(key[:])
	command := exec.CommandContext(ctx, binary)
	// The scoring process receives no database/model/platform credentials.
	for _, key := range []string{"PATH", "SystemRoot", "WINDIR", "TMP", "TEMP"} {
		if value, ok := os.LookupEnv(key); ok {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Env = append(command.Env, "LEXAGENT_METRIC_SERVICE_ADDR="+address, "LEXAGENT_METRIC_SERVICE_TOKEN="+token)
	var diagnostics bytes.Buffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = command.Process.Kill()
			<-done
		}
	})
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case <-done:
			t.Fatal("actual metric worker exited before readiness")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("actual metric worker readiness timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return RemoteMetricEvaluator{URL: "http://" + address, Token: token, Timeout: 2 * time.Second}
}

func TestRealFrozenRAGMetricService(t *testing.T) {
	exerciseRealFrozenRAGMetricService(t, func() ExecutionStore { return newMemoryStore() })
}

func exerciseRealFrozenRAGMetricService(t *testing.T, factory func() ExecutionStore) {
	evaluator := realRAGMetricEvaluator(t)
	formula := json.RawMessage(`{"input_citations_field":"expected.citations","output_claims_field":"evaluation_claims","gate":{"min_entailment":1,"require_all_claims":true,"fail_on_unknown":true,"expected_revision":"v1"}}`)
	for _, tc := range []struct{ name, claim, citation, want string }{
		{"supported", "Only authorized users may retrieve documents.", "approved-1", "passed"},
		{"fabricated-source", "Everyone may retrieve all documents.", "approved-1", "failed"},
		{"unknown-reference", "Only authorized users may retrieve documents.", "invented-1", "failed"},
		{"wrong-revision", "Only authorized users may retrieve documents.", "approved-1", "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := factory()
			scope := Scope{TenantID: "rag-frozen-real", DepartmentID: "documents", ApplicationID: "app-" + tc.name}
			revision := "v1"
			if tc.name == "wrong-revision" {
				revision = "v2"
			}
			sample := map[string]any{"case_id": "case-1", "input": map[string]any{"question": "Who may retrieve documents?"}, "expected": map[string]any{"citations": []map[string]any{{"id": "approved-1", "revision": revision, "source": "approved-dataset", "content": "Only authorized users may retrieve documents."}}}}
			data, _ := json.Marshal(sample)
			run := seedProductRunWithFormula(t, store, scope, "real-rag-"+tc.name, "manual_gold", "grounding", []json.RawMessage{data}, formula)
			invoker := &testAgentInvoker{fn: func(_ context.Context, request InvocationRequest) (InvocationResult, error) {
				if strings.Contains(string(request.Input), "approved-dataset") || strings.Contains(string(request.Input), "expected") {
					t.Error("gold evidence leaked to Agent")
				}
				output, _ := json.Marshal(map[string]any{"evaluation_citations": []map[string]any{{"id": tc.citation, "revision": "v1", "content": tc.claim}}, "evaluation_claims": []map[string]any{{"id": "whole-answer", "text": tc.claim, "citation_ids": []string{tc.citation}}}})
				return InvocationResult{Output: output, ProviderMode: "real", CitationGrounding: "passed"}, nil
			}}
			var artifacts ArtifactWriter = &testArtifactWriter{}
			if writer, ok := store.(ArtifactWriter); ok {
				artifacts = writer
			}
			runner, err := NewRunner(store, invoker, evaluator, artifacts, RunnerOptions{Workers: 1, PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if runner.Start(ctx) != nil || runner.Enqueue(ctx, scope, run) != nil {
				t.Fatal("evaluation admission failed")
			}
			defer func() { _ = runner.Close(context.Background()) }()
			waitForRun(t, store, scope, run.ID, "succeeded")
			row, err := store.Get(ctx, scope, KindEvidence, evidenceResourceID(run.ID))
			if err != nil {
				t.Fatal(err)
			}
			var evidence EvidenceData
			if json.Unmarshal(row.Data, &evidence) != nil || evidence.CitationGrounding != tc.want || evidence.DomainGrounding != "unknown" || evidence.Gate.State == GatePass {
				t.Fatalf("actual worker verdict or missing domain boundary incorrect: %+v", evidence)
			}
		})
	}
}
