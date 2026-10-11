package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type LegacyLocalAuthenticationMigration struct {
	PrincipalID                    string `json:"principal_id"`
	TenantID                       string `json:"tenant_id"`
	DepartmentID                   string `json:"department_id"`
	ApplicationID                  string `json:"application_id"`
	DisplayName                    string `json:"display_name"`
	ExpectedSourceDigest           string `json:"expected_source_digest"`
	ConfigurationDigest            string `json:"configuration_digest"`
	ApprovalReference              string `json:"approval_reference"`
	AppointFirstSuperAdministrator bool   `json:"appoint_first_super_administrator"`
	Password                       string `json:"-"`
}

// The verifier is supplied only by a trusted maintenance command. Configuration
// evidence may preserve a disabled account; an appointment additionally requires
// a fresh successful authentication of the explicitly selected account.
type LegacyAuthenticationEvidence struct {
	PrincipalID, TenantID, DepartmentID, ApplicationID, ConfigurationDigest string
	Authenticated                                                           bool
	VerifiedAt                                                              time.Time
}
type LegacyAuthenticationVerifier func(context.Context, LegacyLocalAuthenticationMigration) (LegacyAuthenticationEvidence, error)

func validLegacyAuthenticationEvidence(r LegacyLocalAuthenticationMigration, e LegacyAuthenticationEvidence, now time.Time) bool {
	return e.PrincipalID == r.PrincipalID && e.TenantID == r.TenantID && e.DepartmentID == r.DepartmentID && e.ApplicationID == r.ApplicationID && e.ConfigurationDigest == r.ConfigurationDigest && !e.VerifiedAt.IsZero() && !e.VerifiedAt.After(now.Add(time.Second)) && now.Sub(e.VerifiedAt) <= 5*time.Minute && (!r.AppointFirstSuperAdministrator || e.Authenticated)
}

// MigrateLegacyLocalAuthentication preserves an existing principal. It never
// creates a new principal, overwrites an authentication binding, or derives an
// administrator appointment from legacy role names. It has no public HTTP route.
func (s *SQLStore) MigrateLegacyLocalAuthentication(ctx context.Context, operator sharedkernel.Scope, r LegacyLocalAuthenticationMigration, verify LegacyAuthenticationVerifier) (AuthorizationChangeReceipt, error) {
	if s == nil || s.db == nil || s.authorizationChangeRecorder == nil {
		return AuthorizationChangeReceipt{}, ErrPermissionRecorderUnavailable
	}
	if verify == nil || operator.Validate() != nil || operator.PrincipalType != "user" || operator.TenantID != r.TenantID || !validPermissionDigest(r.ExpectedSourceDigest) || !validPermissionDigest(r.ConfigurationDigest) || strings.TrimSpace(r.ApprovalReference) == "" || len(r.ApprovalReference) > 128 || len(r.Password) == 0 || len(r.Password) > 128 || r.DisplayName == "" || len(r.DisplayName) > 128 {
		return AuthorizationChangeReceipt{}, ErrInvalidResource
	}
	for _, id := range []string{r.PrincipalID, r.TenantID, r.DepartmentID, r.ApplicationID} {
		if !validPermissionResourceID(id) {
			return AuthorizationChangeReceipt{}, ErrInvalidResource
		}
	}
	evidence, err := verify(ctx, r)
	if err != nil {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	if !validLegacyAuthenticationEvidence(r, evidence, s.clock().UTC()) {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	// Password is excluded from JSON, audit, request digests and receipts.
	raw, err := json.Marshal(r)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	digest := permissionHash(raw)
	key := permissionHash([]byte("legacy-auth\x00" + r.ApprovalReference + "\x00" + r.PrincipalID))
	passwordHash, err := hashEnrollmentPassword(r.Password)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if !validLegacyAuthenticationEvidence(r, evidence, now) {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	var priorDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &saved)
	if err == nil {
		if digest != priorDigest {
			return AuthorizationChangeReceipt{}, ErrIdentityConflict
		}
		if err := authorizeMigrationWriter(ctx, tx, operator, now); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if err := verifyImportedCredential(ctx, tx, r); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		var receipt AuthorizationChangeReceipt
		if err := json.Unmarshal(saved, &receipt); err != nil {
			return receipt, err
		}
		if receipt.ActorID != operator.PrincipalID || receipt.SubjectID != r.PrincipalID {
			return receipt, ErrPermissionDenied
		}
		if err := tx.Commit(); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorizationChangeReceipt{}, err
	}
	source := MigrationSource{}
	source.Snapshot, err = loadPermissionSnapshot(ctx, tx, PrincipalUser, r.PrincipalID)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if source.Snapshot.Principal.TenantID != r.TenantID || (source.Snapshot.Mode != "legacy" && source.Snapshot.Mode != "shadow") {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,epoch FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), r.PrincipalID).Scan(&source.PolicyRevision, &source.PermissionEpoch)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AuthorizationChangeReceipt{}, err
	}
	source.AuthenticationDigest, err = migrationAuthenticationDigest(ctx, tx, MigrationSubject{Type: PrincipalUser, ID: r.PrincipalID}, r.TenantID)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	source.SourceDigest, err = migrationSourceDigest(source)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if source.SourceDigest != r.ExpectedSourceDigest {
		return AuthorizationChangeReceipt{}, ErrPermissionPlanStale
	}
	scope := ManagementScope{Type: "application", TenantID: r.TenantID, DepartmentID: r.DepartmentID, ApplicationID: r.ApplicationID}
	if err := validatePermissionScope(ctx, tx, scope); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if r.AppointFirstSuperAdministrator {
		if operator.PrincipalID != r.PrincipalID || !source.Snapshot.Principal.IsActive {
			return AuthorizationChangeReceipt{}, ErrPermissionDenied
		}
		var administrators int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_role_binding WHERE role_code='super_admin' AND status='active'`)).Scan(&administrators); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if administrators != 0 {
			return AuthorizationChangeReceipt{}, ErrIdentityConflict
		}
	} else if err := authorizeMigrationWriter(ctx, tx, operator, now); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	var credentials int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_local_credential WHERE principal_id=?`), r.PrincipalID).Scan(&credentials); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if credentials != 0 {
		if err := verifyImportedCredential(ctx, tx, r); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	if credentials == 0 {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?,?)`), r.PrincipalID, r.TenantID, r.DepartmentID, r.ApplicationID, r.DisplayName, passwordHash, source.Snapshot.Principal.IsActive, now, now); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	receipt := AuthorizationChangeReceipt{ID: "legacy-auth-" + key, ActorID: operator.PrincipalID, SubjectID: r.PrincipalID, Revision: source.Snapshot.Principal.Revision + 1, PlanDigest: digest, Reason: "Verified legacy authentication migration: " + r.ApprovalReference, OccurredAt: now, Change: AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: r.PrincipalID, ExpectedRevision: source.Snapshot.Principal.Revision, Reason: r.ApprovalReference}}
	if r.AppointFirstSuperAdministrator {
		found := false
		for _, m := range source.Snapshot.Memberships {
			if migrationEqual(m.Scope, scope) {
				if m.Status != "active" || !m.Validity.Effective(now) {
					return AuthorizationChangeReceipt{}, ErrPermissionDenied
				}
				found = true
			}
		}
		if !found {
			m := Membership{ID: "legacy-auth-member-" + key, SubjectID: r.PrincipalID, Scope: scope, Status: "active", Revision: 1}
			if err := persistMembershipMutation(ctx, tx, m, 0); err != nil {
				return AuthorizationChangeReceipt{}, err
			}
			receipt.Memberships = []Membership{m}
		}
		b := RoleBinding{ID: "legacy-auth-admin-" + key, SubjectID: r.PrincipalID, RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: r.ApprovalReference}
		if err := insertRoleBinding(ctx, tx, b); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		receipt.Change.Bindings = []RoleBinding{b}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch,batch_id,source_digest) VALUES('user',?,'v2',?,?,?,?) ON CONFLICT (principal_type,subject_id) DO UPDATE SET policy_mode='v2',revision=EXCLUDED.revision,epoch=EXCLUDED.epoch,batch_id=EXCLUDED.batch_id,source_digest=EXCLUDED.source_digest`), r.PrincipalID, source.PolicyRevision+1, source.PermissionEpoch+1, "legacy-auth:"+r.ApprovalReference, source.SourceDigest); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if err := ensurePermanentAdministrator(ctx, tx, "", "", now); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='user' AND id=? AND revision=?`), r.PrincipalID, source.Snapshot.Principal.Revision)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := migrationExactlyOne(result); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := invalidateAuthorizationStepUp(ctx, tx, PrincipalUser, r.PrincipalID); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := s.authorizationChangeRecorder(ctx, tx, operator, receipt); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if !validLegacyAuthenticationEvidence(r, evidence, s.clock().UTC()) {
		return AuthorizationChangeReceipt{}, ErrPermissionDenied
	}
	if err := authorizeMigrationWriter(ctx, tx, operator, s.clock().UTC()); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), receipt.ID, operator.PrincipalID, r.PrincipalID, key, digest, string(encoded), now); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}

func verifyImportedCredential(ctx context.Context, reader permissionReader, r LegacyLocalAuthenticationMigration) error {
	var tenant, department, application, hash string
	var active bool
	if err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id,password_hash,active FROM platform_identity_local_credential WHERE principal_id=?`), r.PrincipalID).Scan(&tenant, &department, &application, &hash, &active); err != nil {
		return err
	}
	if tenant != r.TenantID || department != r.DepartmentID || application != r.ApplicationID || (r.AppointFirstSuperAdministrator && !active) || !verifyEnrollmentPassword(hash, r.Password) {
		return ErrPermissionDenied
	}
	return nil
}
