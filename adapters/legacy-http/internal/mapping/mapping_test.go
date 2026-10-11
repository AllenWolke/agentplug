package mapping

import (
	"encoding/json"
	"testing"
)

func TestApplyDeclarativePlan(t *testing.T) {
	p, err := DecodeWirePlan(json.RawMessage(`{"mapping_id":"demo","version":"1.0.0","kind":"legacy-http","request":{"question":{"source":"input.question"}},"response":{"answer":{"source":"body.answer"}},"hash":"published"}`), "published")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(p.Request, map[string]any{"question": "q"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["question"] != "q" {
		t.Fatalf("%v", got)
	}
	if _, err := DecodeWirePlan(json.RawMessage(`{"mapping_id":"demo","version":"1.0.0","kind":"legacy-http","request":{"x":{"source":"input..secret"}},"response":{"answer":{"source":"body.answer"}},"hash":"published"}`), "published"); err == nil {
		t.Fatal("unsafe path accepted")
	}
}

func TestApplyEnforcesConstraints(t *testing.T) {
	plan, err := DecodeWirePlan(json.RawMessage(`{"mapping_id":"demo","version":"1.0.0","kind":"legacy-http","request":{"question":{"source":"input.question","required":true,"max_length":4},"count":{"source":"input.count","convert":"to_int"},"tone":{"source":"input.tone","default":"neutral"}},"response":{"answer":{"source":"body.answer"}},"hash":"published"}`), "published")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(plan.Request, map[string]any{"question": "ok", "count": "42"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["count"] != int64(42) || got["tone"] != "neutral" {
		t.Fatalf("convert/default not applied: %#v", got)
	}
	if _, err := Apply(plan.Request, map[string]any{"count": "1"}, nil, nil); err == nil {
		t.Fatal("missing required value accepted")
	}
	if _, err := Apply(plan.Request, map[string]any{"question": "too-long"}, nil, nil); err == nil {
		t.Fatal("max_length violation accepted")
	}
	if _, err := Apply(plan.Request, map[string]any{"question": "ok", "count": "abc"}, nil, nil); err == nil {
		t.Fatal("impossible convert accepted")
	}
}

func TestDecodeWirePlanRejectsUnsupportedConvert(t *testing.T) {
	raw := json.RawMessage(`{"mapping_id":"demo","version":"1.0.0","kind":"legacy-http","request":{"x":{"source":"input.x","convert":"eval"}},"response":{"answer":{"source":"body.answer"}},"hash":"published"}`)
	if _, err := DecodeWirePlan(raw, "published"); err == nil {
		t.Fatal("unsupported convert function accepted")
	}
}

func TestDecodeWirePlanRejectsCanonicalDSL(t *testing.T) {
	raw := json.RawMessage(`{"api_version":"agent-mapping/v1","metadata":{"mapping_id":"legacy-demo","version":"1.0.0"},"spec":{"upstream_ref":"endpoint://legacy-demo","operations":{"invoke":{"request":{"method":"POST","path":"/agent/invoke","body":{"object":{"payload":{"from_input":"payload"}}}},"response":{"success_status":[200],"output":{"from_body":"payload"}}}}}}`)
	if _, err := DecodeWirePlan(raw, "published"); err == nil {
		t.Fatal("adapter accepted canonical DSL instead of a compiled wire plan")
	}
}

func TestDecodeWirePlanDoesNotCompileCallerDSL(t *testing.T) {
	raw := []byte(`{"mapping_id":"demo","version":"1.0.0","kind":"legacy-http","request":{"message":{"source":"input.question"}},"response":{"answer":{"source":"body.answer"}},"hash":"published-hash","revision":4}`)
	plan, err := DecodeWirePlan(json.RawMessage(raw), "published-hash")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Revision != 4 || plan.Request["message"].Source != "input.question" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if _, err = DecodeWirePlan(json.RawMessage(raw), "other-hash"); err == nil {
		t.Fatal("hash mismatch accepted")
	}
}

// TestTwoReplicasMapTheSamePublishedPlanIdentically proves that two adapter
// replicas handed the same immutable plan produce byte-identical upstream
// requests and responses, so horizontal scaling cannot change mapping semantics.
// TestTwoReplicasMapTheSamePublishedPlanIdentically 证明两个 Adapter 副本拿到同一份
// 不可变计划时产出逐字节一致的上游请求与响应，使水平扩缩容不会改变映射语义。
func TestTwoReplicasMapTheSamePublishedPlanIdentically(t *testing.T) {
	raw := json.RawMessage(`{"mapping_id":"demo","version":"1.0.0","kind":"legacy-http","request":{"question":{"source":"input.question","required":true},"tone":{"source":"input.tone","default":"neutral"}},"response":{"answer":{"source":"body.answer"}},"hash":"published"}`)
	first, err := DecodeWirePlan(raw, "published")
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeWirePlan(raw, "published")
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"question": "q"}
	body := map[string]any{"answer": 42}
	firstRequest, err := Apply(first.Request, input, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, err := Apply(second.Request, input, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstResponse, err := Apply(first.Response, input, nil, body)
	if err != nil {
		t.Fatal(err)
	}
	secondResponse, err := Apply(second.Response, input, nil, body)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(firstRequest)
	secondJSON, _ := json.Marshal(secondRequest)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("replicas disagreed on the request mapping: %s vs %s", firstJSON, secondJSON)
	}
	firstJSON, _ = json.Marshal(firstResponse)
	secondJSON, _ = json.Marshal(secondResponse)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("replicas disagreed on the response mapping: %s vs %s", firstJSON, secondJSON)
	}
}
