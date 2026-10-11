package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
)

func commandFixtureHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestReadMigrationSubjectsStrictBoundedInput(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `[{"principal_type":"user","subject_id":"u","extra":true}]`, `[{"principal_type":"user","subject_id":"u"}] {}`, strings.Repeat(" ", (1<<20)+1)} {
		if _, err := readMigrationSubjects(strings.NewReader(input)); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	subjects, err := readMigrationSubjects(strings.NewReader(`[{"principal_type":"user","subject_id":"u"}]`))
	if err != nil || len(subjects) != 1 || subjects[0].ID != "u" {
		t.Fatal(subjects, err)
	}
}

func TestMigrationMappingBatchCoverageAndStrictInput(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `[{"subject":{"principal_type":"user","subject_id":"u"},"unexpected":true}]`, `[] {}`} {
		if _, err := readMigrationMappings(strings.NewReader(input)); err == nil {
			t.Fatal("invalid mapping accepted")
		}
	}
	snapshot := identity.PermissionSnapshot{Principal: identity.Principal{Type: identity.PrincipalUser, ID: "user", TenantID: "tenant", IsActive: true, Revision: 1}, Mode: "legacy", Roles: identity.BuiltinRoleDefinitions()}
	source := identity.MigrationSource{Snapshot: snapshot, AuthenticationDigest: "opaque-authentication-digest"}
	// This test exercises command composition only. Source digests in real
	// command execution are produced by the SQL maintenance reader.
	raw, _ := json.Marshal(source)
	source.SourceDigest = commandFixtureHash(raw)
	target := snapshot
	target.Mode = "v2"
	selection := migrationMappingSelection{Subject: identity.MigrationSubject{Type: identity.PrincipalUser, ID: "user"}, Mapping: identity.MigrationMapping{ExpectedSourceDigest: source.SourceDigest, Basis: "explicit mapping", Target: target}}
	batch := identity.MigrationSourceBatch{TenantID: "tenant", ReadAt: time.Now().UTC(), Sources: []identity.MigrationSource{source}}
	previews, err := previewMigrationBatch(batch, []migrationMappingSelection{selection})
	if err != nil || len(previews) != 1 || !previews[0].PreviewOnly || previews[0].ResourceOwnershipVerified {
		t.Fatal(previews, err)
	}
	if _, err := previewMigrationBatch(batch, nil); err == nil {
		t.Fatal("partial selection accepted")
	}
	selection.Subject.ID = "foreign"
	if _, err := previewMigrationBatch(batch, []migrationMappingSelection{selection}); err == nil {
		t.Fatal("foreign mapping accepted")
	}
	batch.Sources = append(batch.Sources, source)
	if _, err := previewMigrationBatch(batch, []migrationMappingSelection{selection, selection}); err == nil {
		t.Fatal("duplicate mapping accepted")
	}
}
