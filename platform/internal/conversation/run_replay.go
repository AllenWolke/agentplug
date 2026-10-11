package conversation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrRunReplayConflict = errors.New("conversation run replay conflict")

// RunReplayResolver verifies an accepted command's durable execution source.
// Matching a replay is not permission to re-dispatch or read its result.
type RunReplayResolver interface {
	MatchRunReplay(context.Context, Scope, string, RunStartRequest) (bool, error)
}

func (m *Module) SetRunReplayResolver(resolver RunReplayResolver) { m.replay = resolver }

// BusinessRequestHash compares browser commands independently of the approved
// policy snapshot that the platform always overwrites, never browser policy.
func BusinessRequestHash(body []byte) (string, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var input map[string]any
	if err := decoder.Decode(&input); err != nil || input == nil {
		return "", ErrInvalidQuery
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", ErrInvalidQuery
	}
	if _, signedEnvelope := input["protocol_version"]; signedEnvelope {
		return "", ErrInvalidQuery
	}
	delete(input, "policy_snapshot")
	canonical, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// RunCommandFingerprint lets the composition adapter verify an optional
// client fingerprint against the accepted command, including its old epoch.
func RunCommandFingerprint(scope sharedkernel.Scope, key string, body []byte) (string, error) {
	return runFingerprint(scope, key, body)
}
