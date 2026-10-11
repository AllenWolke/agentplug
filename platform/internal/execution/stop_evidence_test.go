package execution

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedControllerStopEvidenceBindsExactGeneration(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	run := platformruntime.Run{ID: "operator-stop", Revision: 4, LeaseToken: "private-lease", RequestJSON: []byte(`{"scope":"entire signed command"}`), AgentEndpoint: "http://agent:8080", CreatedAt: now.Add(-time.Minute), UpdatedAt: now}
	proof := processStopReceipt{Schema: "runtime-process-stop/v1", RunID: run.ID, ExecutionRevision: 3, LeaseHash: stopHash([]byte(run.LeaseToken)), RequestHash: stopHash(run.RequestJSON), Endpoint: run.AgentEndpoint, RuntimeID: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), StartedAt: now.Add(-time.Hour), StoppedAt: now.Add(time.Second), ObservedAt: now.Add(2 * time.Second), RestartDisabled: true}
	key := []byte(strings.Repeat("k", 32))
	dir := t.TempDir()
	verifier := FileStopEvidence{Directory: dir, Key: key}
	write := func(p processStopReceipt, signingKey []byte) {
		t.Helper()
		body, _ := json.Marshal(p)
		mac := hmac.New(sha256.New, signingKey)
		mac.Write(body)
		raw, _ := json.Marshal(signedStopReceipt{Payload: base64.StdEncoding.EncodeToString(body), Signature: hex.EncodeToString(mac.Sum(nil))})
		if err := os.WriteFile(filepath.Join(dir, stopHash([]byte(run.ID))+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verifier.VerifyStopped(context.Background(), run); !errors.Is(err, ErrStopEvidenceAbsent) {
		t.Fatal(err)
	}
	write(proof, key)
	receipt, err := verifier.VerifyStopped(context.Background(), run)
	if err != nil || receipt.Source != proof.Schema || receipt.RuntimeID != proof.RuntimeID || len(receipt.Digest) != 64 {
		t.Fatal("valid receipt rejected", err)
	}
	for _, name := range []string{"run", "revision", "lease", "command", "endpoint", "running", "restart", "before-intent", "future", "wrong-signature"} {
		t.Run(name, func(t *testing.T) {
			candidate := proof
			signingKey := key
			switch name {
			case "run":
				candidate.RunID = "other"
			case "revision":
				candidate.ExecutionRevision++
			case "lease":
				candidate.LeaseHash = strings.Repeat("c", 64)
			case "command":
				candidate.RequestHash = strings.Repeat("d", 64)
			case "endpoint":
				candidate.Endpoint = "http://other:8080"
			case "running":
				candidate.Running = true
			case "restart":
				candidate.RestartDisabled = false
			case "before-intent":
				candidate.StoppedAt = run.UpdatedAt.Add(-time.Second)
			case "future":
				candidate.ObservedAt = time.Now().Add(time.Hour)
			case "wrong-signature":
				signingKey = []byte(strings.Repeat("x", 32))
			}
			write(candidate, signingKey)
			if _, err := verifier.VerifyStopped(context.Background(), run); !errors.Is(err, ErrStopEvidenceInvalid) {
				t.Fatal("invalid proof accepted", err)
			}
		})
	}
	write(proof, key)
	changed := run
	changed.RequestJSON = []byte(`{"scope":"other-user"}`)
	if _, err := verifier.VerifyStopped(context.Background(), changed); !errors.Is(err, ErrStopEvidenceInvalid) {
		t.Fatal("scope change accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.VerifyStopped(ctx, run); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled observation accepted", err)
	}
}
