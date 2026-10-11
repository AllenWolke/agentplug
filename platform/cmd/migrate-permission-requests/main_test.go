package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type importFixture struct {
	calls []string
	fail  string
}

func (f *importFixture) ImportLegacyPermissionRequestFromPlan(_ context.Context, _ sharedkernel.Scope, e identity.LegacyRequestMigrationEntry, _ string) (identity.PermissionRequest, error) {
	f.calls = append(f.calls, e.Source.ID)
	if e.Source.ID == f.fail {
		return identity.PermissionRequest{}, identity.ErrIdentityConflict
	}
	return identity.PermissionRequest{ID: e.Source.ID, Status: "approved", Revision: 2}, nil
}
func fixturePlan(t *testing.T) (identity.LegacyRequestMigrationPlan, sharedkernel.Scope) {
	t.Helper()
	actor := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "manager"}
	p := identity.LegacyRequestMigrationPlan{Version: 1, ActorID: "manager", Scope: identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, CreatedAt: time.Now().UTC(), Entries: []identity.LegacyRequestMigrationEntry{}}
	for _, id := range []string{"a", "b", "c"} {
		p.Entries = append(p.Entries, identity.LegacyRequestMigrationEntry{Source: identity.LegacyPermissionRequestSource{ID: id, Revision: 1, Digest: hex.EncodeToString(make([]byte, 32))}, SubjectID: "requester", Disposition: "ready"})
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	p.Digest = hex.EncodeToString(sum[:])
	if p.Validate() != nil {
		t.Fatal("fixture plan invalid")
	}
	return p, actor
}
func TestMigrationBatchReceiptsResumeWithoutSkippingFailedSource(t *testing.T) {
	p, actor := fixturePlan(t)
	f := &importFixture{}
	receipt, err := applyPlan(context.Background(), f, actor, p, "migration", "", 1)
	if err != nil || receipt.Complete || receipt.Remaining != 2 || receipt.NextAfterID != "a" || receipt.Results[0].Status != "approved" {
		t.Fatal(receipt, err)
	}
	f.fail = "b"
	receipt, err = applyPlan(context.Background(), f, actor, p, "migration", receipt.NextAfterID, 2)
	if !errors.Is(err, identity.ErrIdentityConflict) || receipt.NextAfterID != "a" || receipt.Results[0].Outcome != "source_conflict" {
		t.Fatal(receipt, err)
	}
	f.fail = ""
	receipt, err = applyPlan(context.Background(), f, actor, p, "migration", receipt.NextAfterID, 2)
	if err != nil || !receipt.Complete || receipt.Remaining != 0 || receipt.NextAfterID != "c" || len(f.calls) != 4 {
		t.Fatal(receipt, err, f.calls)
	}
	before := len(f.calls)
	p.Entries[0].Source.Revision = 2
	if _, err := applyPlan(context.Background(), f, actor, p, "migration", "", 1); err == nil || len(f.calls) != before {
		t.Fatal("tampered plan called importer")
	}
}
