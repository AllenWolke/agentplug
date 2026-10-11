package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// HandlerHandoff is produced by a supervised SDK only after its business
// handler has returned. It is not a browser assertion, a process-stop receipt
// or permission to execute. A transport failure without this receipt remains
// uncertain even if the execution lease expires.
type HandlerHandoff struct {
	Version           string `json:"version"`
	RunID             string `json:"run_id"`
	ExecutionRevision uint64 `json:"execution_revision"`
	BodyHash          string `json:"body_hash"`
	LeaseTokenHash    string `json:"lease_token_hash"`
	InputFingerprint  string `json:"input_fingerprint"`
	OriginOperation   string `json:"origin_operation"`
	HarnessKey        string `json:"harness_key"`
	ToolName          string `json:"tool_name"`
	CallID            string `json:"call_id"`
	LastEventSeq      uint64 `json:"last_event_seq"`
}

var handoffDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var handoffKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var handoffIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// Validate binds the receipt to the exact command and execution lease observed
// by the platform dispatcher. Trust in the registered SDK endpoint and the
// post-exit production path must be established independently of these fields.
func (h HandlerHandoff) Validate(runID string, revision uint64, bodyHash, leaseToken string) error {
	if h.Version != "sdk-handler-exit/v1" || h.RunID != runID || !handoffIdentifier.MatchString(runID) ||
		h.ExecutionRevision == 0 || h.ExecutionRevision >= 1<<53 || h.ExecutionRevision != revision ||
		h.LastEventSeq == 0 || h.LastEventSeq >= 1<<53 ||
		!handoffDigest.MatchString(h.BodyHash) || h.BodyHash != bodyHash ||
		!handoffDigest.MatchString(h.LeaseTokenHash) || !handoffDigest.MatchString(h.InputFingerprint) ||
		(h.OriginOperation != "invoke" && h.OriginOperation != "run") ||
		!handoffKey.MatchString(h.HarnessKey) || !handoffIdentifier.MatchString(h.ToolName) || !handoffIdentifier.MatchString(h.CallID) || leaseToken == "" {
		return fmt.Errorf("%w: handler handoff binding", ErrSchemaValidation)
	}
	digest := sha256.Sum256([]byte(leaseToken))
	if h.LeaseTokenHash != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: handler handoff lease", ErrSchemaValidation)
	}
	return nil
}
