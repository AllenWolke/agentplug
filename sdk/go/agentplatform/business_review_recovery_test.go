package agentplatform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRuntimeRecoveryBusinessReviewBoundary(t *testing.T) {
	now := time.Now().UTC()
	request := ExecuteRequest{Operation: "resume", IdempotencyKey: "review-idem", Scope: ScopeKey{RunID: "review-run", PrincipalID: "owner"}, Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": strings.Repeat("c", 64)}}}
	claims := Claims{ExecutionRevision: 5, BodyHash: strings.Repeat("d", 64), LeaseTokenHash: strings.Repeat("b", 64), PolicySnapshotHash: strings.Repeat("c", 64)}
	base := runtimeRecoveryCommand{Version: runtimeRecoveryVersion, OriginOperation: "invoke", BusinessReview: &runtimeBusinessReview{Decision: "approve", ReviewerID: "reviewer"}, Reference: runtimeRecoveryStopReference{Version: runtimeRecoveryStopVersion, RunID: "review-run", StoppedRevision: 2, ReadyRevision: 4, Operation: "resume", BodyHash: strings.Repeat("d", 64), PolicyHash: strings.Repeat("c", 64), LeaseTokenHash: strings.Repeat("a", 64), RequestHash: strings.Repeat("e", 64), ResumeInputHash: strings.Repeat("f", 64), Source: "sdk-cancel-exit/v1", Checkpoints: []runtimeRecoveryCheckpoint{{StateKey: strings.Repeat("1", 64), Revision: 1, SchemaID: "schema://test/graph/v1", ContentHash: strings.Repeat("2", 64), ExecutionRevision: 2, ExpiresAt: now.Add(time.Hour)}}}}
	for _, scenario := range []string{"valid", "self", "extra", "null", "token", "invoke", "invalid_id"} {
		t.Run(scenario, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			review := fields["business_review"].(map[string]any)
			switch scenario {
			case "self":
				review["reviewer_id"] = "owner"
			case "extra":
				review["comment"] = "secret"
			case "null":
				fields["business_review"] = nil
			case "token":
				fields["confirmation_token"] = "untrusted"
			case "invoke":
				fields["reference"].(map[string]any)["operation"] = "invoke"
			case "invalid_id":
				review["reviewer_id"] = "with space"
			}
			req := request
			req.ResumeInput = fields
			command, err := decodeRuntimeRecoveryCommand(req)
			valid := err == nil && validRuntimeRecoveryCommand(command, req, claims, "", now)
			if valid != (scenario == "valid") {
				t.Fatalf("boundary %s: %v %v", scenario, valid, err)
			}
		})
	}
}
