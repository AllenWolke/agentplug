package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/prompt"
)

func parallelRerankFixture(t *testing.T) (knowledgeQueryModels, []knowledge.HybridChunk) {
	t.Helper()
	m := stagedKnowledgeFixture(t)
	var p prompt.Program
	if err := json.Unmarshal([]byte(m.request.Policy.Prompt.Template), &p); err != nil {
		t.Fatal(err)
	}
	p.ExecutionModes = append(p.ExecutionModes, "knowledge-score-vector/v4")
	raw, _ := json.Marshal(p)
	m.request.Policy.Prompt.Template = string(raw)
	m.request.Policy.Model.MaxInputTokens = 32768
	chunks := make([]knowledge.HybridChunk, 25)
	for i := range chunks {
		chunks[i] = knowledge.HybridChunk{Chunk: knowledge.Chunk{ID: fmt.Sprintf("source-%d", i), Text: "完整独立证据"}}
	}
	return m, chunks
}

func parallelPassages(input map[string]any) []rerankPassage {
	var data struct {
		Input struct{ Passages []rerankPassage } `json:"input"`
	}
	_ = json.Unmarshal([]byte(input["messages"].([]map[string]string)[1]["content"]), &data)
	return data.Input.Passages
}

func parallelReply(passages []rerankPassage) map[string]any {
	scores := make([]float64, len(passages))
	for i := range scores {
		scores[i] = .75
	}
	raw, _ := json.Marshal(map[string]any{"scores": scores})
	return map[string]any{"model_version_id": "chat", "invocation_id": "call-" + passages[0].ID, "text": string(raw)}
}

func TestParallelRerankBoundsConcurrencyAndKeepsCanonicalOrder(t *testing.T) {
	m, chunks := parallelRerankFixture(t)
	first, second := make(chan struct{}), make(chan struct{})
	var active, peak, calls atomic.Int32
	m.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
		n := active.Add(1)
		defer active.Add(-1)
		calls.Add(1)
		for prior := peak.Load(); n > prior && !peak.CompareAndSwap(prior, n); prior = peak.Load() {
		}
		passages := parallelPassages(input)
		switch passages[0].ID {
		case "p0":
			close(first)
			<-second
			time.Sleep(5 * time.Millisecond) // force a different completion order
		case "p8":
			close(second)
			<-first
		}
		return parallelReply(passages), nil
	}
	result, err := m.Rerank(context.Background(), m.scope, "定义", chunks)
	if err != nil || peak.Load() != 2 || calls.Load() != 4 || active.Load() != 0 || len(result.Scores) != 25 {
		t.Fatal(err, peak.Load(), calls.Load(), active.Load(), len(result.Scores))
	}
	for i, score := range result.Scores {
		if score.ChunkID != chunks[i].ID {
			t.Fatal("completion order changed citation identity", i, score)
		}
	}
	for i, want := range []string{"call-p0", "call-p8", "call-p16", "call-p24"} {
		if result.InvocationIDs[i] != want {
			t.Fatal("receipt order", result.InvocationIDs)
		}
	}
}

func TestParallelRerankHonorsCapacityOneAndDeniedHint(t *testing.T) {
	m, chunks := parallelRerankFixture(t)
	var calls, active, peak atomic.Int32
	m.request.ModelParallelism = func(context.Context) (int, error) { return 1, nil }
	m.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
		n := active.Add(1)
		defer active.Add(-1)
		calls.Add(1)
		for prior := peak.Load(); n > prior && !peak.CompareAndSwap(prior, n); prior = peak.Load() {
		}
		return parallelReply(parallelPassages(input)), nil
	}
	result, err := m.Rerank(context.Background(), m.scope, "定义", chunks)
	if err != nil || peak.Load() != 1 || calls.Load() != 4 || len(result.Scores) != 25 {
		t.Fatal("capacity-one wave changed evidence or exceeded capacity", err, peak.Load(), calls.Load())
	}
	m.request.ModelParallelism = func(context.Context) (int, error) { return 0, context.Canceled }
	before := calls.Load()
	if _, err := m.Rerank(context.Background(), m.scope, "定义", chunks); err == nil || calls.Load() != before {
		t.Fatal("denied capacity lookup reached a model")
	}
}

func TestParallelRerankFailureJoinsDispatchedCallsAndStopsNextWave(t *testing.T) {
	for _, failure := range []string{"unknown", "schema", "authority"} {
		t.Run(failure, func(t *testing.T) {
			m, chunks := parallelRerankFixture(t)
			var calls, completed atomic.Int32
			var revoked atomic.Bool
			first, second := make(chan struct{}), make(chan struct{})
			unknown := errors.New("unknown provider response")
			m.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
				calls.Add(1)
				defer completed.Add(1)
				passages := parallelPassages(input)
				if passages[0].ID == "p0" {
					close(first)
					<-second
					if failure == "unknown" {
						return nil, unknown
					}
					if failure == "schema" {
						return map[string]any{"model_version_id": "chat", "invocation_id": "bad", "text": `{"scores":[0.5]}`}, nil
					}
					revoked.Store(true)
				} else {
					close(second)
					<-first
					time.Sleep(5 * time.Millisecond)
				}
				return parallelReply(passages), nil
			}
			_, err := m.RerankWithCheck(context.Background(), m.scope, "定义", chunks, func() error {
				if revoked.Load() {
					return knowledge.ErrKnowledgeAuthorityChanged
				}
				return nil
			})
			if err == nil || calls.Load() != 2 || completed.Load() != 2 {
				t.Fatal("failed wave was retried, leaked or followed by another send", err, calls.Load(), completed.Load())
			}
		})
	}
}

func TestParallelRerankCancelledBeforeDispatchSendsNothing(t *testing.T) {
	m, chunks := parallelRerankFixture(t)
	var calls atomic.Int32
	m.request.ModelCall = func(context.Context, string, map[string]any) (map[string]any, error) {
		calls.Add(1)
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.Rerank(ctx, m.scope, "定义", chunks)
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal(err, calls.Load())
	}
}
