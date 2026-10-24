package identity

import (
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLPermissionDirectoryPublicationIsAtomicImmutableAndNeverAssignsUsers(t *testing.T) {
	f := newAdministratorFixture(t)
	counts := func() []int {
		t.Helper()
		out := []int{}
		for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_principal`, `SELECT COUNT(*) FROM platform_identity_membership`, `SELECT COUNT(*) FROM platform_identity_role_binding`, `SELECT COUNT(*) FROM platform_identity_grant`} {
			var count int
			if err := f.db.QueryRowContext(f.ctx, query).Scan(&count); err != nil {
				t.Fatal(err)
			}
			out = append(out, count)
		}
		return out
	}
	before := counts()
	removeNewDefinitions := func() {
		t.Helper()
		for _, query := range []string{`DELETE FROM platform_identity_role_definition WHERE role_code='department_admin' AND role_version=2`, `DELETE FROM platform_identity_preset_definition WHERE preset_code='department_admin' AND preset_version=2`} {
			if _, err := f.db.ExecContext(f.ctx, query); err != nil {
				t.Fatal(err)
			}
		}
	}
	removeNewDefinitions()
	for i := 0; i < 2; i++ {
		if err := f.store.PublishPermissionDirectory(f.ctx); err != nil {
			t.Fatal("publication or idempotent retry", err)
		}
	}
	after := counts()
	for i := range before {
		if before[i] != after[i] {
			t.Fatal("directory publication changed user authorization", before, after)
		}
	}
	removeNewDefinitions()
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_preset_definition SET content_hash=? WHERE preset_code='operator' AND preset_version=1`), "changed-existing-definition"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.PublishPermissionDirectory(f.ctx); err == nil {
		t.Fatal("existing immutable definition overwritten")
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM platform_identity_role_definition WHERE role_code='department_admin' AND role_version=2`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed publication partially added role definitions", count, err)
	}
	if err := f.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM platform_identity_preset_definition WHERE preset_code='department_admin' AND preset_version=2`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed publication partially added preset definitions", count, err)
	}
}
