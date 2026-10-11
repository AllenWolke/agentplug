package agentplatform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedExecutionFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "fixtures", "execution-v2-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request ExecuteRequest
	if err = json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if request.ProtocolVersion != ProtocolVersion || request.Scope.AuthorizationEpoch != 3 || request.Operation != "run" {
		t.Fatalf("fixture decoded incorrectly: %+v", request)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var canonical map[string]any
	if err = json.Unmarshal(encoded, &canonical); err != nil || canonical["protocol_version"] != ProtocolVersion {
		t.Fatalf("fixture re-encode failed: %v", err)
	}
}

func TestSharedResumeDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "fixtures", "execution-v2-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request ExecuteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	request.Operation = "resume"
	request.ResumeInput = map[string]any{"decision": "approve", "reviewer_id": "reviewer-a"}
	// One pinned digest across Python, Go and Java; not a self-signed assertion.
	// 三种语言使用同一固定摘要，避免签名与验签共同遗漏字段造成假通过。
	hash, err := CanonicalBodyHash(request)
	if err != nil || hash != "b3b300c491c0e717dd493556b96cef294c30fcc93cd3eea53fb5beb986a1530a" {
		t.Fatalf("resume digest mismatch: %s, %v", hash, err)
	}
}
