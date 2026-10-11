package agentplatform

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicCheckpointSignedTransportAndLargeIntegerRestore(t *testing.T) {
	now := time.Now()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/internal/state/checkpoint" && r.URL.Path != "/internal/context/prepare" && r.URL.Path != "/internal/tool/invoke" {
			t.Error("checkpoint bypassed the platform")
		}
		raw, _ := io.ReadAll(r.Body)
		digest := sha256.Sum256(raw)
		proof, _ := json.Marshal([]string{"platform-capability/v2", "POST", r.URL.RequestURI(), hex.EncodeToString(digest[:])})
		mac := hmac.New(sha256.New, []byte("fixture-secret"))
		_, _ = mac.Write(proof)
		if r.Header.Get("X-Context-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) || !strings.HasPrefix(r.Header.Get("X-Platform-Context"), "Bearer ") {
			t.Error("checkpoint request was not signed")
		}
		var envelope struct {
			Input map[string]any `json:"input"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&envelope) != nil {
			t.Error("invalid body")
		}
		if r.URL.Path == "/internal/tool/invoke" {
			if envelope.Input["call_id"] != "approved-call" || envelope.Input["confirmation_token"] != "opaque-approval" || envelope.Input["confirmed"] != nil {
				t.Error("SDK changed approval binding or asserted boolean consent")
			}
			_, _ = w.Write([]byte(`{"data":{"receipt":"committed"}}`))
			return
		}
		if r.URL.Path == "/internal/context/prepare" {
			_, _ = w.Write([]byte(`{"data":{"messages":[{"role":"system","content":"approved"},{"role":"user","content":"question"}],"prompt_template_hash":"published"}}`))
			return
		}
		if envelope.Input["operation"] == "save" {
			value := envelope.Input["value"].(map[string]any)
			if value["sequence"] != json.Number("9007199254740993") || envelope.Input["idempotency_key"] != "stable-step" {
				t.Error("checkpoint identity or integer changed")
			}
		}
		_, _ = w.Write([]byte(`{"data":{"checkpoint":{"revision":1,"value":{"sequence":9007199254740993}}}}`))
	}))
	defer server.Close()
	client, err := NewCapabilityClient(CapabilityConfig{BaseURL: server.URL, InternalToken: "fixture-internal", SigningSecret: "fixture-secret", Now: func() time.Time { return now.Add(-time.Minute) }}, renewalFixtureRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"sequence": json.Number("9007199254740993")}
	if _, err := client.SaveCheckpoint(context.Background(), "harness", "loop", "schema://state/v1", "stable-step", 0, value); err != nil {
		t.Fatal(err)
	}
	result, err := client.LoadCheckpoint(context.Background(), "harness", "loop", "schema://state/v1", 0)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := result["checkpoint"].(map[string]any)
	if checkpoint["value"].(map[string]any)["sequence"] != json.Number("9007199254740993") {
		t.Fatal("checkpoint round-trip lost integer precision")
	}
	if _, err := client.SaveCheckpoint(context.Background(), "harness", "loop", "schema://state/v1", "", 0, value); err == nil {
		t.Fatal("missing idempotency key accepted")
	}
	if _, err := client.LoadCheckpoint(context.Background(), "harness", "loop", "schema://state/v1", 65); err == nil {
		t.Fatal("unbounded history accepted")
	}
	if requests != 2 {
		t.Fatalf("unexpected retry or invalid request submitted: %d", requests)
	}
	prepared, err := client.PrepareContext(context.Background(), []map[string]any{{"role": "user", "content": "question"}}, nil)
	if err != nil || prepared["prompt_template_hash"] != "published" || requests != 3 {
		t.Fatalf("context preparation bypassed signed platform transport: %+v %v", prepared, err)
	}
	if _, err = client.InvokeTool(context.Background(), "clock.now", "approved-call", map[string]any{}, "opaque-approval"); err != nil || requests != 4 {
		t.Fatal("approved tool transport failed", err)
	}
	if _, err = client.InvokeTool(context.Background(), "clock.now", "", map[string]any{}, "opaque-approval"); err == nil || requests != 4 {
		t.Fatal("missing approval call ID submitted")
	}
}
