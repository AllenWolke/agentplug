package policyasset

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func publicationFixture() DraftPublication {
	scope := Scope{TenantID: "publication-tenant", DepartmentID: "publication-department", ApplicationID: "publication-app", AgentID: "publication-agent", AgentVersionID: "publication-version"}
	return DraftPublication{InstallationID: "publication-installation", Scope: scope, Assets: []DraftAsset{
		{ID: "fixture-model", Type: AssetModel, Content: json.RawMessage(`{"provider":"sql-fixture-only","model":"fixture-model","max_tokens":128,"budget_cents":10}`)},
		{ID: "fixture-prompt", Type: AssetPrompt, Content: json.RawMessage(`{"template_hash":"fixture-template-hash","template":"Use authorised evidence only."}`)},
		{ID: "fixture-tool", Type: AssetTool, Content: json.RawMessage(`{"allowed_tools":["fixture-tool"]}`)},
		{ID: "fixture-memory", Type: AssetMemory, Content: json.RawMessage(`{"max_entries":8}`)},
		{ID: "fixture-knowledge", Type: AssetKnowledge, Content: json.RawMessage(`{"allowed_scopes":["fixture-knowledge"],"require_references":true}`)},
		{ID: "fixture-runtime", Type: AssetRuntime, Content: json.RawMessage(`{"max_attempts":1,"task_timeout_seconds":60,"lease_seconds":10}`)},
	}}
}

func TestPreparePublicationRejectsIncompleteOrSecretBearingComponents(t *testing.T) {
	f := publicationFixture()
	if _, err := PreparePublication(f, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	incomplete := f
	incomplete.Assets = append([]DraftAsset(nil), f.Assets[:5]...)
	if _, err := PreparePublication(incomplete, "fixture-admin"); err == nil {
		t.Fatal("incomplete bundle accepted")
	}
	duplicate := f
	duplicate.Assets = append([]DraftAsset(nil), f.Assets...)
	duplicate.Assets[5] = duplicate.Assets[0]
	if _, err := PreparePublication(duplicate, "fixture-admin"); err == nil {
		t.Fatal("duplicate family accepted")
	}
	secret := f
	secret.Assets = append([]DraftAsset(nil), f.Assets...)
	secret.Assets[0].Content = json.RawMessage(`{"provider":"fixture","model":"fixture","max_tokens":1,"api_key":"must-not-be-a-policy-field"}`)
	if _, err := PreparePublication(secret, "fixture-admin"); err == nil {
		t.Fatal("credential field accepted into policy")
	}
}

func TestSQLPreparedPublicationPersistsSixPoliciesAndMatchesExactRetry(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	f := publicationFixture()
	drafts, err := PreparePublication(f, "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	assets := map[AssetType]Asset{}
	refs := map[AssetType]AssetRef{}
	for _, draft := range drafts {
		if err := store.CreateAsset(ctx, draft); err != nil {
			t.Fatal(err)
		}
		published, err := store.PublishAsset(ctx, f.Scope, draft.Type, draft.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		assets[draft.Type] = published
		refs[draft.Type] = AssetRef{ID: published.ID, Revision: published.Revision}
	}
	request := PublishSnapshotRequest{Scope: f.Scope, Assets: refs}
	snapshot, err := store.PublishSnapshot(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	read, err := store.GetSnapshot(ctx, f.Scope)
	if err != nil || read.Hash != snapshot.Hash || !PublicationMatchesSnapshot(read, request, assets) {
		t.Fatal("persisted publication retry not recognised", err)
	}
	if _, err := store.PublishSnapshot(ctx, request); !errors.Is(err, ErrAssetConflict) {
		t.Fatal("CAS publication replay unexpectedly added revision", err)
	}
	different := read
	different.Runtime.MaxAttempts++
	if PublicationMatchesSnapshot(different, request, assets) {
		t.Fatal("different policy content acknowledged as retry")
	}
	wrongRevision := request
	wrongRevision.ExpectedRevision = 4
	if PublicationMatchesSnapshot(read, wrongRevision, assets) {
		t.Fatal("different CAS source acknowledged as retry")
	}
	wrongScope := request
	wrongScope.Scope.AgentVersionID = "other-version"
	if PublicationMatchesSnapshot(read, wrongScope, assets) {
		t.Fatal("cross-version references accepted")
	}
	wrongReferences := request
	wrongReferences.Assets = map[AssetType]AssetRef{}
	for typ, ref := range refs {
		wrongReferences.Assets[typ] = ref
	}
	wrongReferences.Assets[AssetModel] = AssetRef{ID: "other-model", Revision: 2}
	if PublicationMatchesSnapshot(read, wrongReferences, assets) {
		t.Fatal("different model reference acknowledged as retry")
	}
	var versions int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_policy_snapshot_revision`)).Scan(&versions); err != nil || versions != 1 {
		t.Fatal("duplicate snapshot history", versions, err)
	}
}
