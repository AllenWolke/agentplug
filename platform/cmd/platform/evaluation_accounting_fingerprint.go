package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// A stopped historical case may still need its original accounting provenance
// after correcting the platform's numeric signature bug. This accepts only the
// recorded old fingerprint for non-admission; it grants no send, retry, refund
// or stop evidence. VerifyBudgetTx still checks the exact frozen case, policy,
// parent and Scope, and cancellation independently requires actual exit proof.
func evaluationAccountingFingerprintMatches(request contract.ExecuteRequest, saved string, admission bool, status platformruntime.Status) bool {
	current, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil || saved == "" {
		return false
	}
	if current == saved {
		return true
	}
	if admission || (status != platformruntime.StatusCancelling && status != platformruntime.StatusCancelled && status != platformruntime.StatusFailed && status != platformruntime.StatusSucceeded) {
		return false
	}
	return legacyEvaluationAccountingFingerprint(request) == saved
}

func legacyEvaluationAccountingFingerprint(request contract.ExecuteRequest) string {
	request.ContextToken = ""
	raw, err := json.Marshal(request)
	if err != nil {
		return ""
	}
	var legacy map[string]any
	if json.Unmarshal(raw, &legacy) != nil {
		return ""
	}
	delete(legacy, "context_token")
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(legacy) != nil {
		return ""
	}
	digest := sha256.Sum256(bytes.TrimSuffix(out.Bytes(), []byte("\n")))
	return hex.EncodeToString(digest[:])
}
