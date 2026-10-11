package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	agenteval "github.com/lexagent/agent-evaluation"
	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

type scriptedPort struct {
	calls  []string
	handle func(string, map[string]any) (map[string]any, error)
}

func TestPublishedServiceWiringStartsAndExposesExactManifest(t *testing.T) {
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"fixture", "judge"} {
		t.Run(mode, func(t *testing.T) {
			server, err := executionServer(mode, key, nil, "platform", "agent-runtime")
			if err != nil {
				t.Fatal(err)
			}
			ready := httptest.NewRecorder()
			server.Handler().ServeHTTP(ready, httptest.NewRequest("GET", "/health/ready", nil))
			if ready.Code != 200 {
				t.Fatal("service not ready")
			}
			manifest := httptest.NewRecorder()
			server.Handler().ServeHTTP(manifest, httptest.NewRequest("GET", "/.well-known/agent-manifest.json", nil))
			var actual, expected any
			json.Unmarshal(manifest.Body.Bytes(), &actual)
			raw, _ := Manifest(mode)
			json.Unmarshal(raw, &expected)
			a, _ := json.Marshal(actual)
			e, _ := json.Marshal(expected)
			if manifest.Code != 200 || string(a) != string(e) {
				t.Fatal("manifest wiring drift")
			}
		})
	}
}

func (p *scriptedPort) ValidateCurrentExecution(context.Context) error { return nil }

func (p *scriptedPort) Post(_ context.Context, path string, in map[string]any) (map[string]any, error) {
	p.calls = append(p.calls, path)
	return p.handle(path, in)
}
func judgeRequest() agentplatform.ExecuteRequest {
	rubric := agenteval.Rubric{Version: agenteval.RubricVersion, ID: "teaching-v1", Criteria: map[string]string{"faithfulness": "Every claim must be supported by an evidence reference"}}
	in := agenteval.JudgeInput{Version: "agent-eval-judge-input/v1", SourceRunID: "source-1", SourceOutputHash: strings.Repeat("a", 64), Rubric: rubric, RubricHash: agenteval.RubricDigest(rubric), Evidence: map[string]json.RawMessage{"output": json.RawMessage(`{"answer":"teaching"}`)}}
	b, _ := json.Marshal(in)
	var input map[string]any
	_ = json.Unmarshal(b, &input)
	return agentplatform.ExecuteRequest{InputSchema: "schema://agent-eval-judge/input/v1", IdempotencyKey: "grade-1", Input: input, Scope: agentplatform.ScopeKey{RunID: "grader-1", AgentVersionID: "grader-version"}}
}

func TestRegistrationSchemasMatchPublishedManifest(t *testing.T) {
	for _, mode := range []string{"fixture", "judge"} {
		files, err := RegistrationFiles(mode)
		if err != nil || len(files) != 3 {
			t.Fatal(mode, err)
		}
		var manifest struct {
			Schemas map[string]string `json:"schemas"`
		}
		if json.Unmarshal(files["manifest.json"], &manifest) != nil {
			t.Fatal("invalid manifest")
		}
		for _, kind := range []string{"input", "output"} {
			var schema struct {
				ID string `json:"$id"`
			}
			if json.Unmarshal(files[kind+".schema.json"], &schema) != nil || schema.ID != manifest.Schemas[kind] {
				t.Fatal(mode, kind, "registration schema mismatch")
			}
		}
	}
	if _, err := RegistrationFiles("unsupported"); err == nil {
		t.Fatal("unsupported registration accepted")
	}
}
func TestJudgeUsesGovernedContextAndIdempotentModel(t *testing.T) {
	p := &scriptedPort{handle: func(path string, in map[string]any) (map[string]any, error) {
		switch path {
		case "/internal/context/prepare":
			return map[string]any{"messages": []any{map[string]any{"role": "system", "content": "published judge prompt"}}, "prompt_template_hash": "approved-hash"}, nil
		case "/internal/model/generate":
			if in["prompt_template_hash"] != "approved-hash" || in["idempotency_key"] != "grade-1:model-review:v1" || in["model"] != nil {
				t.Fatal("model policy or idempotency bypass")
			}
			return map[string]any{"model": "recorded-model", "text": `{"verdicts":[{"metric_id":"faithfulness","value":true,"evidence":["output"],"reason":"The answer matches the cited teaching evidence"}]}`}, nil
		default:
			t.Fatal("unexpected public capability")
			return nil, nil
		}
	}}
	out, e := runJudge(context.Background(), judgeRequest(), p)
	if e != nil || len(p.calls) != 2 {
		t.Fatal(e)
	}
	j := out["judgement"].(agenteval.Judgement)
	if j.JudgeRunID != "grader-1" || j.SourceRunID != "source-1" || j.ScoringModel != "recorded-model" || j.ScoringModelVersion != "" || j.SourceRedactedOutputHash == "" {
		t.Fatal("missing provenance or invented model version")
	}
}
func TestJudgeFailureOrInventedEvidenceNeverProducesScore(t *testing.T) {
	for _, mode := range []string{"failure", "invalid-json", "invented-evidence"} {
		t.Run(mode, func(t *testing.T) {
			p := &scriptedPort{handle: func(path string, _ map[string]any) (map[string]any, error) {
				if path == "/internal/context/prepare" {
					return map[string]any{"messages": []any{"prepared"}, "prompt_template_hash": "hash"}, nil
				}
				if mode == "failure" {
					return nil, errors.New("provider unavailable")
				}
				text := "invalid"
				if mode == "invented-evidence" {
					text = `{"verdicts":[{"metric_id":"faithfulness","value":true,"evidence":["secret-source"],"reason":"claimed support"}]}`
				}
				return map[string]any{"text": text}, nil
			}}
			out, e := runJudge(context.Background(), judgeRequest(), p)
			if e == nil || out != nil {
				t.Fatal("failure manufactured a judgement")
			}
		})
	}
}

func TestJudgePreservesBudgetAndRevocationWithoutLeakingProviderError(t *testing.T) {
	for _, stage := range []string{"/internal/context/prepare", "/internal/model/generate"} {
		for _, code := range []string{"MODEL_BUDGET_EXCEEDED", "CAPABILITY_DENIED"} {
			t.Run(stage+"/"+code, func(t *testing.T) {
				p := &scriptedPort{handle: func(path string, _ map[string]any) (map[string]any, error) {
					if path == stage {
						return nil, &agentplatform.AppError{Code: code, Message: "private-provider-secret", Details: map[string]any{"token": "private-token"}, Retryable: true}
					}
					return map[string]any{"messages": []any{"prepared"}, "prompt_template_hash": "hash"}, nil
				}}
				out, err := runJudge(context.Background(), judgeRequest(), p)
				var app *agentplatform.AppError
				if out != nil || !errors.As(err, &app) || app.Code != code || app.Details != nil || app.Retryable || app.Message == "private-provider-secret" {
					t.Fatal("classification lost, score fabricated or private failure leaked")
				}
				if stage == "/internal/context/prepare" && len(p.calls) != 1 {
					t.Fatal("model invoked after governed context refusal")
				}
			})
		}
	}
}
func TestFixtureRequiresRealPermissionDenialAndDoesNotReplayUnknown(t *testing.T) {
	for _, test := range []struct {
		scenario    string
		error       error
		expectError bool
		calls       int
	}{{"permission_boundary", nil, true, 1}, {"permission_boundary", &agentplatform.AppError{Code: "CAPABILITY_DENIED"}, false, 1}, {"permission_boundary", errors.New("network error"), true, 1}, {"unknown_side_effect", nil, false, 1}, {"ambiguous", nil, false, 0}, {"low_confidence_route", nil, false, 0}, {"multistep", nil, false, 2}, {"unrecognized", nil, true, 0}} {
		t.Run(test.scenario, func(t *testing.T) {
			p := &scriptedPort{handle: func(_ string, in map[string]any) (map[string]any, error) {
				return map[string]any{"data": map[string]any{"fixture": true}, "observation": map[string]any{"version": "runtime-observation/v1", "run_id": "fixture-run", "tool_name": in["name"], "call_id": in["call_id"], "status": "succeeded"}}, test.error
			}}
			out, e := runFixture(context.Background(), agentplatform.ExecuteRequest{InputSchema: "schema://agent-eval-simulation/input/v1", IdempotencyKey: "case-1", Input: map[string]any{"scenario": test.scenario}, Scope: agentplatform.ScopeKey{RunID: "fixture-run"}}, p)
			if (e != nil) != test.expectError || len(p.calls) != test.calls {
				t.Fatalf("unexpected behavior %v, calls=%d", e, len(p.calls))
			}
			if !test.expectError && out["side_effect_replayed"] != false {
				t.Fatal("unknown effect replayed")
			}
		})
	}
}
