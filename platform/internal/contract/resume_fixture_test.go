package contract

import (
	"encoding/json"
	"os"
	"testing"
)

// The gateway and all SDKs must sign the same recovery envelope.
// 平台网关与所有 SDK 必须对相同恢复信封生成一致摘要。
func TestSharedResumeDigest(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/fixtures/execution-v2-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var request ExecuteRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	request.Operation = "resume"
	request.ResumeInput = map[string]any{"decision": "approve", "reviewer_id": "reviewer-a"}
	hash, err := CanonicalExecuteBodyHash(request)
	if err != nil || hash != "b3b300c491c0e717dd493556b96cef294c30fcc93cd3eea53fb5beb986a1530a" {
		t.Fatalf("shared resume digest mismatch: %s, %v", hash, err)
	}
}
