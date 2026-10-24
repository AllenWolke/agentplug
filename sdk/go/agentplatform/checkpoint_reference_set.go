package agentplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// expandRuntimeRecovery pages metadata only. The verified signed request is
// retained untouched; only the parser's private copy is normalized to v1.
func expandRuntimeRecovery(ctx context.Context, client *CapabilityClient, request ExecuteRequest) (runtimeRecoveryCommand, error) {
	if request.ResumeInput["version"] != "runtime-recovery/v2" {
		return decodeRuntimeRecoveryCommand(request)
	}
	if client == nil || client.ValidateCurrentExecution(ctx) != nil {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	normalized, err := publicClone(request.ResumeInput)
	if err != nil {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	ref, ok := normalized["reference"].(map[string]any)
	_, inline := ref["checkpoints"]
	_, group := normalized["group_resume"]
	if !ok || ref["version"] != "runtime-recovery-stop/v2" || inline || group {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	set, ok := ref["checkpoint_set"].(map[string]any)
	count, valid := handoffUint64(set["count"])
	digest, hash := set["digest"].(string)
	if !ok || len(set) != 3 || set["version"] != "recovery-checkpoint-set/v1" || !valid || count <= 128 || count > 8192 || !hash || !validHandoffDigest(digest) {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	refs := []any{}
	items := [][]any{}
	for uint64(len(refs)) < count {
		offset := len(refs)
		limit := min(64, int(count)-offset)
		page, err := client.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "load", "reference_set": set, "offset": offset, "limit": 64})
		if err != nil {
			return runtimeRecoveryCommand{}, err
		}
		pageOffset, number := handoffUint64(page["offset"])
		values, list := page["references"].([]any)
		if len(page) != 4 || page["version"] != "recovery-checkpoint-page/v1" || !sameRecoveryJSONValue(page["set"], set) || !number || pageOffset != uint64(offset) || !list || len(values) != limit {
			return runtimeRecoveryCommand{}, ErrInvalidTransition
		}
		for _, v := range values {
			r, ok := v.(map[string]any)
			if !ok || len(r) != 6 {
				return runtimeRecoveryCommand{}, ErrInvalidTransition
			}
			item := []any{}
			for _, field := range []string{"state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at"} {
				value, exists := r[field]
				if !exists {
					return runtimeRecoveryCommand{}, ErrInvalidTransition
				}
				item = append(item, value)
			}
			refs = append(refs, r)
			items = append(items, item)
		}
	}
	encoded, err := json.Marshal(items)
	hashValue := sha256.Sum256(encoded)
	if err != nil || hex.EncodeToString(hashValue[:]) != digest {
		return runtimeRecoveryCommand{}, ErrInvalidTransition
	}
	normalized["version"] = "runtime-recovery/v1"
	ref["version"] = "runtime-recovery-stop/v1"
	delete(ref, "checkpoint_set")
	ref["checkpoints"] = refs
	parserRequest := request
	parserRequest.ResumeInput = normalized
	command, err := decodeRuntimeRecoveryCommandBounded(parserRequest, 8<<20)
	if err == nil {
		command.maximumCheckpoints = 8192
	}
	return command, err
}

// A bounded metadata reply is still not permission to read checkpoint values.
// Values are independently read and validated through the current gateway.

// CheckpointReferenceSetDigest preserves the platform's ordered metadata wire format.
func CheckpointReferenceSetDigest(references []map[string]any) (string, error) {
	items := make([][]any, 0, len(references))
	for _, reference := range references {
		if len(reference) != 6 {
			return "", ErrInvalidTransition
		}
		row := []any{}
		for _, field := range []string{"state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at"} {
			value, ok := reference[field]
			if !ok {
				return "", ErrInvalidTransition
			}
			row = append(row, value)
		}
		items = append(items, row)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}
