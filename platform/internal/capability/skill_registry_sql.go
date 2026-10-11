package capability

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type SkillSQLAuthorizer func(context.Context, *sql.Tx, string, sharedkernel.Scope, string, string) error
type SQLSkillStore struct {
	db        *sql.DB
	authorize SkillSQLAuthorizer
	audit     audit.TxRecorder
	fence     SkillSQLTransactionFence
}

func NewSQLSkillStore(db *sql.DB) (*SQLSkillStore, error) {
	if db == nil {
		return nil, ErrSkillUnavailable
	}
	return &SQLSkillStore{db: db}, nil
}
func (s *SQLSkillStore) SetAuthorizer(authorize SkillSQLAuthorizer)         { s.authorize = authorize }
func (s *SQLSkillStore) SetAuditRecorder(recorder audit.TxRecorder)         { s.audit = recorder }
func (s *SQLSkillStore) SetTransactionFence(fence SkillSQLTransactionFence) { s.fence = fence }

// PublishedSkillAvailable is a narrow metadata Port used during Grant validation.
// It never discloses instructions or confers runtime access.
func (s *SQLSkillStore) PublishedSkillAvailable(ctx context.Context, scope sharedkernel.Scope, skill string) (bool, error) {
	if scope.Validate() != nil || !skillIdentifier(skill) {
		return false, ErrSkillDenied
	}
	var available bool
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_skill_release r JOIN platform_skill_version v ON v.namespace_key=r.namespace_key AND v.skill_id=r.skill_id AND (v.version_id=r.stable_version OR (r.candidate_basis_points>0 AND v.version_id=r.candidate_version)) WHERE r.namespace_key=? AND r.skill_id=? AND v.status='approved')`), skillNamespace(scope), skill).Scan(&available)
	return available, err
}

// EnsureSchema is called only by explicit deployment migration, never startup.
func (s *SQLSkillStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_skill_version (
 namespace_key VARCHAR(64) NOT NULL, skill_id VARCHAR(128) NOT NULL, version_id VARCHAR(128) NOT NULL,
 bundle_json TEXT NOT NULL CHECK(octet_length(bundle_json)<=65536), content_hash VARCHAR(64) NOT NULL,
 author_id VARCHAR(128) NOT NULL, reviewer_id VARCHAR(128) NOT NULL DEFAULT '',
 status VARCHAR(16) NOT NULL CHECK(status IN ('submitted','approved','rejected','revoked')),
 revision BIGINT NOT NULL CHECK(revision>0), created_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(namespace_key,skill_id,version_id),
 CHECK(status<>'approved' OR (reviewer_id<>'' AND reviewer_id<>author_id)));
CREATE TABLE IF NOT EXISTS platform_skill_release (
 namespace_key VARCHAR(64) NOT NULL, skill_id VARCHAR(128) NOT NULL,
 stable_version VARCHAR(128) NOT NULL, candidate_version VARCHAR(128),
 candidate_basis_points INTEGER NOT NULL CHECK(candidate_basis_points BETWEEN 0 AND 10000),
 revision BIGINT NOT NULL CHECK(revision>0),
 PRIMARY KEY(namespace_key,skill_id),
 FOREIGN KEY(namespace_key,skill_id,stable_version) REFERENCES platform_skill_version(namespace_key,skill_id,version_id),
 FOREIGN KEY(namespace_key,skill_id,candidate_version) REFERENCES platform_skill_version(namespace_key,skill_id,version_id),
 CHECK((candidate_version IS NULL AND candidate_basis_points=0) OR (candidate_version IS NOT NULL AND candidate_basis_points>0 AND candidate_version<>stable_version)));
CREATE TABLE IF NOT EXISTS platform_skill_release_history (
 namespace_key VARCHAR(64) NOT NULL, skill_id VARCHAR(128) NOT NULL, revision BIGINT NOT NULL,
 stable_version VARCHAR(128) NOT NULL, candidate_version VARCHAR(128), candidate_basis_points INTEGER NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(namespace_key,skill_id,revision));
CREATE TABLE IF NOT EXISTS platform_skill_run_pin (
 run_key VARCHAR(64) PRIMARY KEY, namespace_key VARCHAR(64) NOT NULL, skill_id VARCHAR(128) NOT NULL,
 version_id VARCHAR(128) NOT NULL, content_hash VARCHAR(64) NOT NULL, release_revision BIGINT NOT NULL CHECK(release_revision>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(namespace_key,skill_id,version_id) REFERENCES platform_skill_version(namespace_key,skill_id,version_id));`)
	return err
}
func skillNamespace(scope sharedkernel.Scope) string {
	body, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type skillSQLPermissionCheck struct{ action, skill, target string }
type skillSQLTransaction struct {
	ctx       context.Context
	tx        *sql.Tx
	store     *SQLSkillStore
	scope     sharedkernel.Scope
	namespace string
	checks    []skillSQLPermissionCheck
}

func (s *SQLSkillStore) Transact(ctx context.Context, scope sharedkernel.Scope, operation func(SkillTransaction) error) error {
	if scope.Validate() != nil || s.authorize == nil || s.audit == nil || s.fence == nil || operation == nil {
		return ErrSkillDenied
	}
	tx, borrowed, err := skillSQLTransactionFromContext(ctx, s.db, scope)
	if err != nil {
		return err
	}
	if !borrowed {
		tx, err = s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	if err = s.transactIn(ctx, tx, scope, operation); err != nil {
		return err
	}
	if borrowed {
		return nil
	}
	return tx.Commit()
}

// transactIn performs the complete skill operation and final authority pass in
// the caller's transaction. The caller remains responsible for its outcome.
func (s *SQLSkillStore) transactIn(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, operation func(SkillTransaction) error) error {
	namespace := skillNamespace(scope)
	// Acquire IAM/Run continuity before the namespace lock. This keeps standalone
	// skill transactions in the same lock order as callers that already own a
	// Run transaction and then validate model Skill dependencies.
	if err := s.fence.AcquireTransactionFence(ctx, tx, scope); err != nil {
		return err
	}
	// Serialize first creation and row transitions, including absent pin/release.
	// This is an application namespace lock, not a global cross-tenant lock.
	hash := sha256.Sum256([]byte("skill-registry/v1\x00" + namespace))
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`SELECT pg_advisory_xact_lock(?)`), int64(binary.BigEndian.Uint64(hash[:8]))); err != nil {
		return err
	}
	unit := &skillSQLTransaction{ctx: ctx, tx: tx, store: s, scope: scope, namespace: namespace}
	if err := operation(unit); err != nil {
		return err
	}
	if len(unit.checks) == 0 {
		return ErrSkillDenied
	}
	// Repeat authority checks before commit; implementations must also guard
	// active execution generation for load and lock current identity revisions.
	for _, check := range unit.checks {
		if err := s.authorize(ctx, tx, check.action, scope, check.skill, check.target); err != nil {
			return skillDenyUnlessAdmissionWait(err)
		}
	}
	return nil
}
func (u *skillSQLTransaction) Authorize(ctx context.Context, action string, scope sharedkernel.Scope, skill, target string) error {
	// Four model dependencies, each with discovery/load and up to 32 Tool
	// plus 32 Knowledge requirements. Still bounded independently of input.
	if scope != u.scope || !skillIdentifier(skill) || len(u.checks) >= 264 {
		return ErrSkillDenied
	}
	if err := u.store.authorize(ctx, u.tx, action, scope, skill, target); err != nil {
		return skillDenyUnlessAdmissionWait(err)
	}
	u.checks = append(u.checks, skillSQLPermissionCheck{action, skill, target})
	return nil
}
func (u *skillSQLTransaction) Version(skill, version string) (SkillVersion, bool, error) {
	var record SkillVersion
	var body []byte
	err := u.tx.QueryRowContext(u.ctx, sqlutil.Bind(`SELECT bundle_json,content_hash,author_id,reviewer_id,status,revision,created_at FROM platform_skill_version WHERE namespace_key=? AND skill_id=? AND version_id=? FOR UPDATE`), u.namespace, skill, version).Scan(&body, &record.Digest, &record.AuthorID, &record.ReviewerID, &record.Status, &record.Revision, &record.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if len(body) > 64<<10 {
		return SkillVersion{}, true, ErrSkillUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record.Bundle) != nil || decoder.Decode(new(any)) != io.EOF || record.Bundle.SkillID != skill || record.Bundle.VersionID != version {
		return SkillVersion{}, true, ErrSkillUnavailable
	}
	_, digest, err := freezeSkillBundle(record.Bundle)
	if err != nil || digest != record.Digest {
		return SkillVersion{}, true, ErrSkillUnavailable
	}
	return record, true, nil
}
func (u *skillSQLTransaction) InsertVersion(record SkillVersion) error {
	bundle, digest, err := freezeSkillBundle(record.Bundle)
	if err != nil || record.Digest != digest || record.Status != "submitted" || record.Revision != 1 || record.AuthorID != u.scope.PrincipalID || record.ReviewerID != "" {
		return ErrSkillDenied
	}
	body, _ := json.Marshal(bundle)
	_, err = u.tx.ExecContext(u.ctx, sqlutil.Bind(`INSERT INTO platform_skill_version(namespace_key,skill_id,version_id,bundle_json,content_hash,author_id,reviewer_id,status,revision,created_at) VALUES(?,?,?,?,?,?,'','submitted',1,?)`), u.namespace, bundle.SkillID, bundle.VersionID, string(body), digest, record.AuthorID, record.CreatedAt)
	return err
}
func (u *skillSQLTransaction) ReviewVersion(skill, version string, expected uint64, status, reviewer string) error {
	if reviewer != u.scope.PrincipalID || expected == 0 || expected >= 1<<63-1 {
		return ErrSkillDenied
	}
	result, err := u.tx.ExecContext(u.ctx, sqlutil.Bind(`UPDATE platform_skill_version SET status=?,reviewer_id=CASE WHEN ?='revoked' THEN reviewer_id ELSE ? END,revision=revision+1 WHERE namespace_key=? AND skill_id=? AND version_id=? AND revision=? AND ((?='revoked' AND status IN ('submitted','approved')) OR (? IN ('approved','rejected') AND status='submitted' AND author_id<>?))`), status, status, reviewer, u.namespace, skill, version, expected, status, status, reviewer)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSkillConflict
	}
	return nil
}
func (u *skillSQLTransaction) Release(skill string) (SkillRelease, bool, error) {
	var release SkillRelease
	var candidate sql.NullString
	err := u.tx.QueryRowContext(u.ctx, sqlutil.Bind(`SELECT stable_version,candidate_version,candidate_basis_points,revision FROM platform_skill_release WHERE namespace_key=? AND skill_id=? FOR UPDATE`), u.namespace, skill).Scan(&release.StableVersion, &candidate, &release.CandidateBasisPoints, &release.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return release, false, nil
	}
	release.CandidateVersion = candidate.String
	return release, err == nil, err
}
func (u *skillSQLTransaction) WriteRelease(skill string, expected uint64, release SkillRelease) error {
	if release.Revision != expected+1 || expected >= 1<<63-1 {
		return ErrSkillConflict
	}
	var candidate any
	if release.CandidateVersion != "" {
		candidate = release.CandidateVersion
	}
	var result sql.Result
	var err error
	if expected == 0 {
		result, err = u.tx.ExecContext(u.ctx, sqlutil.Bind(`INSERT INTO platform_skill_release(namespace_key,skill_id,stable_version,candidate_version,candidate_basis_points,revision) VALUES(?,?,?,?,?,1) ON CONFLICT DO NOTHING`), u.namespace, skill, release.StableVersion, candidate, release.CandidateBasisPoints)
	} else {
		result, err = u.tx.ExecContext(u.ctx, sqlutil.Bind(`UPDATE platform_skill_release SET stable_version=?,candidate_version=?,candidate_basis_points=?,revision=? WHERE namespace_key=? AND skill_id=? AND revision=?`), release.StableVersion, candidate, release.CandidateBasisPoints, release.Revision, u.namespace, skill, expected)
	}
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrSkillConflict
	}
	_, err = u.tx.ExecContext(u.ctx, sqlutil.Bind(`INSERT INTO platform_skill_release_history(namespace_key,skill_id,revision,stable_version,candidate_version,candidate_basis_points) VALUES(?,?,?,?,?,?)`), u.namespace, skill, release.Revision, release.StableVersion, candidate, release.CandidateBasisPoints)
	return err
}
func (u *skillSQLTransaction) Pin(scope sharedkernel.Scope, skill string) (SkillPin, bool, error) {
	if scope != u.scope || scope.ValidateTrusted() != nil {
		return SkillPin{}, false, ErrSkillDenied
	}
	var pin SkillPin
	err := u.tx.QueryRowContext(u.ctx, sqlutil.Bind(`SELECT version_id,content_hash,release_revision FROM platform_skill_run_pin WHERE run_key=? AND namespace_key=? AND skill_id=? FOR UPDATE`), skillRunKey(scope, skill), u.namespace, skill).Scan(&pin.VersionID, &pin.Digest, &pin.ReleaseRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return pin, false, nil
	}
	return pin, err == nil, err
}
func (u *skillSQLTransaction) InsertPin(scope sharedkernel.Scope, skill string, pin SkillPin) error {
	if scope != u.scope || scope.ValidateTrusted() != nil || pin.ReleaseRevision == 0 {
		return ErrSkillDenied
	}
	_, err := u.tx.ExecContext(u.ctx, sqlutil.Bind(`INSERT INTO platform_skill_run_pin(run_key,namespace_key,skill_id,version_id,content_hash,release_revision) VALUES(?,?,?,?,?,?)`), skillRunKey(scope, skill), u.namespace, skill, pin.VersionID, pin.Digest, pin.ReleaseRevision)
	return err
}
func (u *skillSQLTransaction) Audit(action string, scope sharedkernel.Scope, skill, version, digest string) error {
	if scope != u.scope || len(digest) != 64 {
		return ErrSkillDenied
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	// audit.Event uses a database timestamp via Scan below, not caller input.
	event := audit.Event{ID: "skill-" + hex.EncodeToString(nonce[:]), TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "skill", AggregateID: skill, Action: action, Outcome: "success", Summary: fmt.Sprintf("version=%s digest=%s", version, digest)}
	if err := u.tx.QueryRowContext(u.ctx, `SELECT clock_timestamp()`).Scan(&event.CreatedAt); err != nil {
		return err
	}
	return u.store.audit.RecordTx(u.tx, event)
}
