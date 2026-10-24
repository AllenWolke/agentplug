package policyasset

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/jsonvaluecache"
)

func TestKnowledgePolicyDecodeIsolationAndNaturalExpiry(t *testing.T) {
	cache := jsonvaluecache.New(2, 4096, parseKnowledgePolicy, cloneKnowledgePolicy)
	raw := []byte(`{"allowed_scopes":["kb"],"require_references":true,"document_bindings":[{"knowledge_scope":"kb","provider_id":"platform-knowledge","knowledge_base_id":"kb","provider_document_id":"doc","document_version":"v1","status":"active","owner_id":"owner","ownership_source":"published","valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-02-01T00:00:00Z"}]}`)
	before, err := cache.Decode(raw)
	if err != nil || before.ValidateDocuments() != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !before.DocumentBindings[0].Effective(now) {
		t.Fatal("valid source unexpectedly denied")
	}
	before.AllowedScopes[0] = "poison"
	before.DocumentBindings[0].OwnerID = "foreign"
	*before.DocumentBindings[0].ValidFrom = now.AddDate(1, 0, 0)
	*before.DocumentBindings[0].ValidUntil = now.AddDate(2, 0, 0)
	fresh, err := cache.Decode(raw)
	if err != nil || fresh.AllowedScopes[0] != "kb" || fresh.DocumentBindings[0].OwnerID != "owner" || !fresh.DocumentBindings[0].Effective(now) {
		t.Fatal("cached value mutated", err)
	}
	if fresh.DocumentBindings[0].Effective(now.AddDate(0, 1, 0)) {
		t.Fatal("cached decoding froze temporal authority")
	}
	fresh.DocumentBindings[0].Status = "deleted"
	changed, _ := json.Marshal(fresh)
	next, err := cache.Decode(changed)
	if err != nil || next.DocumentBindings[0].Effective(now) {
		t.Fatal("changed source reused old bytes", err)
	}
	for range 2 {
		if _, err := cache.Decode([]byte(`{"allowed_scopes":3}`)); err == nil {
			t.Fatal("corrupt JSON accepted")
		}
	}
}
