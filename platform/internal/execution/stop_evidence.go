package execution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

var ErrStopEvidenceAbsent = errors.New("runtime stop evidence absent")
var ErrStopEvidenceInvalid = errors.New("runtime stop evidence invalid")

type StopEvidence struct {
	Source    string `json:"source"`
	Digest    string `json:"digest"`
	RuntimeID string `json:"runtime_id"`
}

// StopEvidenceVerifier is an operator/controller trust boundary, never a browser
// or Agent claim. Implementations must establish exit of this exact generation.
type StopEvidenceVerifier interface {
	VerifyStopped(context.Context, platformruntime.Run) (StopEvidence, error)
}

type FileStopEvidence struct {
	Directory string
	Key       []byte
}
type signedStopReceipt struct {
	Payload   string `json:"payload_base64"`
	Signature string `json:"signature"`
}
type processStopReceipt struct {
	Schema            string    `json:"schema"`
	RunID             string    `json:"run_id"`
	ExecutionRevision uint64    `json:"execution_revision"`
	LeaseHash         string    `json:"lease_token_hash"`
	RequestHash       string    `json:"request_hash"`
	Endpoint          string    `json:"endpoint"`
	RuntimeID         string    `json:"runtime_id"`
	ImageDigest       string    `json:"image_digest"`
	StartedAt         time.Time `json:"started_at"`
	StoppedAt         time.Time `json:"stopped_at"`
	ObservedAt        time.Time `json:"observed_at"`
	Running           bool      `json:"running"`
	RestartDisabled   bool      `json:"restart_disabled"`
}

func stopHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func strictStopJSON(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return ErrStopEvidenceInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrStopEvidenceInvalid
	}
	return nil
}

func (v FileStopEvidence) VerifyStopped(ctx context.Context, run platformruntime.Run) (StopEvidence, error) {
	invalid := func() (StopEvidence, error) { return StopEvidence{}, ErrStopEvidenceInvalid }
	if err := ctx.Err(); err != nil {
		return StopEvidence{}, err
	}
	if v.Directory == "" || len(v.Key) != 32 || run.Revision < 2 || run.LeaseToken == "" || run.AgentEndpoint == "" {
		return invalid()
	}
	name := filepath.Join(v.Directory, stopHash([]byte(run.ID))+".json")
	info, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return StopEvidence{}, ErrStopEvidenceAbsent
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32768 {
		return invalid()
	}
	raw, err := os.ReadFile(name)
	if err != nil || len(raw) > 32768 {
		return invalid()
	}
	var envelope signedStopReceipt
	if strictStopJSON(raw, &envelope) != nil {
		return invalid()
	}
	body, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return invalid()
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil {
		return invalid()
	}
	mac := hmac.New(sha256.New, v.Key)
	mac.Write(body)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return invalid()
	}
	var proof processStopReceipt
	if strictStopJSON(body, &proof) != nil {
		return invalid()
	}
	now := time.Now().UTC()
	if proof.Schema != "runtime-process-stop/v1" || proof.RunID != run.ID || proof.ExecutionRevision != run.Revision-1 || proof.LeaseHash != stopHash([]byte(run.LeaseToken)) || proof.RequestHash != stopHash(run.RequestJSON) || proof.Endpoint != run.AgentEndpoint || proof.Running || !proof.RestartDisabled || len(proof.RuntimeID) != 64 || len(proof.ImageDigest) != 71 || proof.ImageDigest[:7] != "sha256:" || proof.StartedAt.IsZero() || proof.StartedAt.After(run.CreatedAt) || proof.StoppedAt.Before(run.UpdatedAt) || !proof.StoppedAt.After(proof.StartedAt) || proof.ObservedAt.Before(proof.StoppedAt) || proof.ObservedAt.After(now.Add(30*time.Second)) {
		return invalid()
	}
	if _, err := hex.DecodeString(proof.RuntimeID); err != nil {
		return invalid()
	}
	if _, err := hex.DecodeString(proof.ImageDigest[7:]); err != nil {
		return invalid()
	}
	return StopEvidence{Source: proof.Schema, Digest: stopHash(body), RuntimeID: proof.RuntimeID}, nil
}
