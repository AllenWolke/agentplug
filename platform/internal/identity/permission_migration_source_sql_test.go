package identity

import (
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"testing"
	"time"
)

func TestSQLMigrationSourcesPreserveProtectedFactsAndDetectUnversionedChanges(t *testing.T) {
	f := newAdministratorFixture(t)
	subject := MigrationSubject{Type: PrincipalUser, ID: f.actors[2].PrincipalID}
	tenant := f.actors[2].TenantID
	expires := f.now.Add(time.Hour)
	g := Grant{ID: "migration-deny", TenantID: tenant, DepartmentID: f.actors[2].DepartmentID, ApplicationID: f.actors[2].ApplicationID, AgentInstanceID: "fixture-install", SubjectType: PrincipalUser, SubjectID: subject.ID, Action: "run", Effect: "deny", Status: "revoked", Revision: 1, ResourceType: "agent_installation", ResourceID: "fixture-install", DataScope: DataScope{Type: "explicit_set", IDs: []string{"trusted-run"}}, Validity: Validity{ExpiresAt: &expires}}
	metadata, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant(id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,permission_json,grant_key_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,clock_timestamp())`), g.ID, g.TenantID, g.DepartmentID, g.ApplicationID, g.AgentInstanceID, g.SubjectType, g.SubjectID, g.Action, g.Effect, g.Status, g.Revision, metadata, permissionHash([]byte(g.ID))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id=?`), subject.ID); err != nil {
		t.Fatal(err)
	}
	read := func() MigrationSourceBatch {
		t.Helper()
		batch, err := f.store.InspectMigrationSources(f.ctx, tenant, []MigrationSubject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return batch
	}
	first := read()
	source := first.Sources[0]
	if source.Snapshot.Principal.IsActive || source.PolicyRevision != 1 || source.PermissionEpoch != 1 || len(source.Snapshot.Grants) != 1 {
		t.Fatal("lost protected source facts", source)
	}
	got := source.Snapshot.Grants[0]
	if got.Effect != "deny" || got.Status != "revoked" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) || got.DataScope.Type != "explicit_set" || got.DataScope.IDs[0] != "trusted-run" {
		t.Fatal("lost grant metadata", got)
	}
	if next := read(); next.Digest != first.Digest {
		t.Fatal("identical snapshot digest changed")
	}
	if _, err := f.store.InspectMigrationSources(f.ctx, "foreign", []MigrationSubject{subject}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("cross-tenant baseline disclosed", err)
	}
	if _, err := f.store.InspectMigrationSources(f.ctx, tenant, []MigrationSubject{subject, subject}); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("duplicate source accepted", err)
	}
	// A source change without a revision bump must still invalidate a plan.
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_local_credential SET password_hash='secret-not-for-report',active=FALSE WHERE principal_id=?`), subject.ID); err != nil {
		t.Fatal(err)
	}
	authChanged := read()
	if authChanged.Sources[0].AuthenticationDigest == source.AuthenticationDigest || authChanged.Sources[0].SourceDigest == source.SourceDigest || authChanged.Digest == first.Digest {
		t.Fatal("credential change did not invalidate source")
	}
	raw, _ := json.Marshal(authChanged)
	if strings.Contains(string(raw), "secret-not-for-report") || strings.Contains(string(raw), "password_hash") {
		t.Fatal("credential material escaped report")
	}
	later := expires.Add(time.Hour)
	g.ExpiresAt = &later
	metadata, _ = json.Marshal(g)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET permission_json=? WHERE id=?`), metadata, g.ID); err != nil {
		t.Fatal(err)
	}
	grantChanged := read()
	if grantChanged.Sources[0].SourceDigest == authChanged.Sources[0].SourceDigest || grantChanged.Sources[0].AuthenticationDigest != authChanged.Sources[0].AuthenticationDigest {
		t.Fatal("grant metadata change not independently detected")
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET epoch=epoch+1 WHERE subject_id=?`), subject.ID); err != nil {
		t.Fatal(err)
	}
	if epochChanged := read(); epochChanged.Sources[0].SourceDigest == grantChanged.Sources[0].SourceDigest {
		t.Fatal("permission epoch change ignored")
	}
	var active bool
	var revision uint64
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT active,revision FROM platform_identity_principal WHERE id=?`), subject.ID).Scan(&active, &revision); err != nil || active || revision != source.Snapshot.Principal.Revision {
		t.Fatal("preview modified principal", active, revision, err)
	}
	var status string
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT status FROM platform_identity_grant WHERE id=?`), g.ID).Scan(&status); err != nil || status != "revoked" {
		t.Fatal("preview reactivated grant", status, err)
	}
	beforeOIDC := read()
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,created_at,revision,updated_at) VALUES(?,?,?,?,?,?,?,'disabled',clock_timestamp(),1,clock_timestamp())`), permissionHash([]byte("fixture-oidc")), "https://private-issuer.invalid", "private-oidc-subject", subject.ID, tenant, f.actors[2].DepartmentID, f.actors[2].ApplicationID); err != nil {
		t.Fatal(err)
	}
	afterOIDC := read()
	if afterOIDC.Sources[0].AuthenticationDigest == beforeOIDC.Sources[0].AuthenticationDigest {
		t.Fatal("disabled OIDC binding ignored")
	}
	raw, _ = json.Marshal(afterOIDC)
	if strings.Contains(string(raw), "private-issuer") || strings.Contains(string(raw), "private-oidc-subject") {
		t.Fatal("OIDC identity escaped report")
	}
	machine := MigrationSubject{Type: PrincipalServicePrincipal, ID: "migration-fixture-machine"}
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: machine.Type, ID: machine.ID, TenantID: tenant, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type=? AND id=?`), machine.Type, machine.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_machine_credential(tenant_id,principal_id,secret_hash,network_cidrs_json,status,revision,created_at,updated_at) VALUES(?,?,?,'["127.0.0.1/32"]','revoked',1,clock_timestamp(),clock_timestamp())`), tenant, machine.ID, permissionHash([]byte("fixture-machine-secret"))); err != nil {
		t.Fatal(err)
	}
	batch, err := f.store.InspectMigrationSources(f.ctx, tenant, []MigrationSubject{subject, machine})
	if err != nil || len(batch.Sources) != 2 || batch.Sources[0].Snapshot.Principal.Type != PrincipalServicePrincipal || batch.Sources[0].Snapshot.Principal.IsActive || batch.Sources[0].Snapshot.Mode != "legacy" {
		t.Fatal("machine facts or canonical ordering lost", batch, err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_machine_credential SET network_cidrs_json='["10.0.0.0/8"]' WHERE principal_id=?`), machine.ID); err != nil {
		t.Fatal(err)
	}
	changed, err := f.store.InspectMigrationSources(f.ctx, tenant, []MigrationSubject{machine, subject})
	if err != nil || changed.Sources[0].AuthenticationDigest == batch.Sources[0].AuthenticationDigest || changed.Sources[1].SourceDigest != batch.Sources[1].SourceDigest {
		t.Fatal("machine boundary change not detected independently", err)
	}
}
