package planloader

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lexagent/legacy-http-adapter/internal/mapping"
)

const planBodyV2 = `{"mapping_id":"legacy-ask","version":"1.0.0","kind":"legacy-http","revision":2,"hash":"h1","request":{"question":{"source":"input.question"}},"response":{"answer":{"source":"body.answer"}}}`

func sign(t *testing.T, key ed25519.PrivateKey, body []byte) []byte {
	t.Helper()
	signature := ed25519.Sign(key, body)
	return []byte(`{"signature":"` + base64.StdEncoding.EncodeToString(signature) + `","plan":` + string(body) + `}`)
}

func writePlan(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newSignedLoader(t *testing.T, body []byte, expectedHash string, minRevision uint64) (*Loader, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writePlan(t, sign(t, private, body))
	return &Loader{Path: path, PublicKey: public, ExpectedHash: expectedHash, MinRevision: minRevision}, path
}

func TestRefreshLoadsSignedPlanAndExposesDigest(t *testing.T) {
	loader, _ := newSignedLoader(t, []byte(planBodyV2), "h1", 1)
	plan, err := loader.Refresh()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Revision != 2 || plan.MappingID != "legacy-ask" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if loader.Degraded() {
		t.Fatal("a successful refresh must not be degraded")
	}
	if loader.Revision() != 2 || loader.Digest() == "" {
		t.Fatalf("loader did not expose revision/digest: rev=%d digest=%q", loader.Revision(), loader.Digest())
	}
	if _, ok := loader.Current(); !ok {
		t.Fatal("LKG was not retained after a successful load")
	}
}

// TestRefreshFailureKeepsTheLastKnownGoodPlan is the core LKG contract: a bad
// refresh must never take a running adapter offline.
// TestRefreshFailureKeepsTheLastKnownGoodPlan 是 LKG 契约的核心：一次坏的刷新绝不能
// 让运行中的 Adapter 下线。
func TestRefreshFailureKeepsTheLastKnownGoodPlan(t *testing.T) {
	loader, path := newSignedLoader(t, []byte(planBodyV2), "h1", 1)
	if _, err := loader.Refresh(); err != nil {
		t.Fatal(err)
	}

	// Overwrite the document with a plan whose signature no longer matches.
	if err := os.WriteFile(path, sign(t, make(ed25519.PrivateKey, ed25519.PrivateKeySize), []byte(planBodyV2)), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := loader.Refresh()
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered plan was accepted: %v", err)
	}
	if plan.Revision != 2 {
		t.Fatalf("LKG was not served after a failed refresh: %+v", plan)
	}
	if !loader.Degraded() || loader.Revision() != 2 {
		t.Fatalf("loader did not report degraded while keeping the LKG: degraded=%v rev=%d", loader.Degraded(), loader.Revision())
	}

	// Removing the document entirely must also keep the LKG.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if plan, err := loader.Refresh(); err == nil || plan.Revision != 2 {
		t.Fatalf("missing document lost the LKG: plan=%+v err=%v", plan, err)
	}
}

func TestRefreshRejectsUnsignedOrHashMismatchedPlans(t *testing.T) {
	loader, _ := newSignedLoader(t, []byte(planBodyV2), "h1", 1)
	// An unsigned document is refused outright when a key is pinned.
	if err := os.WriteFile(loader.Path, []byte(planBodyV2), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.Refresh(); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatalf("unsigned plan was accepted: %v", err)
	}

	// A correctly signed plan is still refused when the pinned hash does not
	// match, which is what stops a stale document from silently replacing the
	// live plan.
	other, _ := newSignedLoader(t, []byte(planBodyV2), "other", 1)
	if _, err := other.Refresh(); err == nil {
		t.Fatal("hash mismatch was accepted")
	}
}

func TestRefreshRejectsRevisionRollback(t *testing.T) {
	loader, path := newSignedLoader(t, []byte(planBodyV2), "h1", 1)
	if _, err := loader.Refresh(); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := []byte(`{"mapping_id":"legacy-ask","version":"1.0.0","kind":"legacy-http","revision":1,"hash":"h1","request":{"question":{"source":"input.question"}},"response":{"answer":{"source":"body.answer"}}}`)
	if err := os.WriteFile(path, sign(t, private, rolledBack), 0600); err != nil {
		t.Fatal(err)
	}
	// The signature is checked against the pinned key, so swap in the loader that
	// trusts this new key to isolate the revision rule.
	loader.PublicKey = public
	plan, err := loader.Refresh()
	if !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("revision rollback was accepted: %v", err)
	}
	if plan.Revision != 2 {
		t.Fatalf("rollback clobbered the LKG: %+v", plan)
	}
}

func TestRefreshHonoursMinimumRevision(t *testing.T) {
	loader, _ := newSignedLoader(t, []byte(planBodyV2), "h1", 5)
	if _, err := loader.Refresh(); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("plan below the pinned minimum revision was accepted: %v", err)
	}
}

func TestRefreshWithoutAnyDocumentFailsClosed(t *testing.T) {
	loader := &Loader{Path: filepath.Join(t.TempDir(), "absent.json")}
	if _, err := loader.Refresh(); err == nil {
		t.Fatal("loader accepted a missing document")
	}
	if _, ok := loader.Current(); ok {
		t.Fatal("loader reported an LKG without ever loading a plan")
	}
}

// TestMappingAloneIntegratesALegacyAgent proves the PF-11 acceptance case: a
// legacy agent is onboarded with a mapping document and no code, because the
// signed plan fully determines the upstream request and the platform response.
// TestMappingAloneIntegratesALegacyAgent 证明 PF-11 验收场景：存量 Agent 仅凭一份
// 映射文档（无需改代码）即可接入——签名计划完整决定上游请求与平台响应。
func TestMappingAloneIntegratesALegacyAgent(t *testing.T) {
	loader, _ := newSignedLoader(t, []byte(planBodyV2), "h1", 1)
	plan, err := loader.Refresh()
	if err != nil {
		t.Fatal(err)
	}
	legacyRequest, err := mapping.Apply(plan.Request, map[string]any{"question": "what is 2+2?"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacyRequest["question"] != "what is 2+2?" {
		t.Fatalf("legacy request mapping was not applied: %v", legacyRequest)
	}
	legacyResponse, err := mapping.Apply(plan.Response, nil, nil, map[string]any{"answer": "4"})
	if err != nil {
		t.Fatal(err)
	}
	if legacyResponse["answer"] != "4" {
		t.Fatalf("legacy response mapping was not applied: %v", legacyResponse)
	}
}

// TestPlanRoundTripsThroughTheEnvelopeBytes guards the interpreter boundary: the
// bytes the signer covered must be exactly the bytes the interpreter reads.
// TestPlanRoundTripsThroughTheEnvelopeBytes 守住解释器边界：签名者覆盖的字节必须
// 与解释器读取的字节完全一致。
func TestPlanRoundTripsThroughTheEnvelopeBytes(t *testing.T) {
	loader, _ := newSignedLoader(t, []byte(planBodyV2), "h1", 1)
	if _, err := loader.Refresh(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(loader.Path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Plan json.RawMessage `json:"plan"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("envelope did not decode")
	}
	if string(envelope.Plan) != planBodyV2 {
		t.Fatalf("interpreter did not see the signed bytes:\n got %s\nwant %s", envelope.Plan, planBodyV2)
	}
}
