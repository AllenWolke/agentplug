package catalog

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"strings"
	"time"
)

var ErrReleaseUnavailable = errors.New("catalog release authority unavailable")
var ErrReleaseSubmissionMissing = errors.New("catalog release submission provenance unavailable")

type ReleaseDecision struct {
	Kind        string
	ID          string
	Action      string
	Actor       ControlActor
	SubmittedBy string
	Revision    uint64
	CreatedAt   time.Time
}

type ReleaseGuard func(context.Context, *sql.Tx) error
type ReleaseAuthorizer func(context.Context, ControlActor, ControlAction) error
type ReleaseRecorder func(context.Context, *sql.Tx, ReleaseDecision) error

type SubmittedReleaseStore interface {
	CreateSubmittedDefinition(context.Context, Definition, ControlActor) error
	CreateSubmittedVersion(context.Context, Version, ControlActor) error
	PublishSubmittedObject(context.Context, string, string, uint64, ControlActor) error
}

func releaseActorFromRequest(r *http.Request) ControlActor {
	return ControlActor{TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")), DepartmentID: strings.TrimSpace(r.Header.Get("X-Department-ID")), ApplicationID: strings.TrimSpace(r.Header.Get("X-Application-ID")), PrincipalType: strings.TrimSpace(r.Header.Get("X-Principal-Type")), PrincipalID: strings.TrimSpace(r.Header.Get("X-Principal-ID")), TraceID: strings.TrimSpace(r.Header.Get("X-Trace-ID"))}
}

func (s *SQLStore) SetReleasePorts(guard ReleaseGuard, authorize ReleaseAuthorizer, recorder ReleaseRecorder) {
	s.releaseGuard, s.releaseAuthorize, s.releaseRecord = guard, authorize, recorder
}

func (s *SQLStore) EnsureReleaseSubmissionSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_catalog_submission (
		object_kind VARCHAR(32) NOT NULL,
		object_id VARCHAR(128) NOT NULL,
		tenant_id VARCHAR(128) NOT NULL,
		department_id VARCHAR(128) NOT NULL,
		application_id VARCHAR(128) NOT NULL,
		submitted_by VARCHAR(128) NOT NULL,
		submitted_at TIMESTAMPTZ(6) NOT NULL,
		approved_by VARCHAR(128) NOT NULL DEFAULT '',
		approved_at TIMESTAMPTZ(6) NULL,
		approved_revision NUMERIC(20,0) CHECK (approved_revision>=0 AND approved_revision<=18446744073709551615) NOT NULL DEFAULT 0,
		PRIMARY KEY(object_kind,object_id)
	);
`))
	return err
}

func validReleaseActor(actor ControlActor) bool {
	if actor.PrincipalType != "user" {
		return false
	}
	for _, value := range []string{actor.PrincipalID, actor.TenantID, actor.DepartmentID, actor.ApplicationID} {
		if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	return true
}

func (s *SQLStore) beginRelease(ctx context.Context, tx *sql.Tx, actor ControlActor, action ControlAction) error {
	if s.releaseGuard == nil || s.releaseAuthorize == nil || s.releaseRecord == nil {
		return ErrReleaseUnavailable
	}
	if !validReleaseActor(actor) {
		return ErrCatalogForbidden
	}
	if err := s.releaseGuard(ctx, tx); err != nil {
		return err
	}
	return s.releaseAuthorize(ctx, actor, action)
}

func (s *SQLStore) recordSubmission(ctx context.Context, tx *sql.Tx, kind, id string, actor ControlActor, now time.Time) error {
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_submission (object_kind,object_id,tenant_id,department_id,application_id,submitted_by,submitted_at) VALUES (?,?,?,?,?,?,?)`), kind, id, actor.TenantID, actor.DepartmentID, actor.ApplicationID, actor.PrincipalID, now); err != nil {
		return err
	}
	if err := s.releaseRecord(ctx, tx, ReleaseDecision{Kind: kind, ID: id, Action: "submitted", Actor: actor, SubmittedBy: actor.PrincipalID, Revision: 1, CreatedAt: now}); err != nil {
		return err
	}
	return s.releaseAuthorize(ctx, actor, ControlSubmit)
}

func (s *SQLStore) CreateSubmittedDefinition(ctx context.Context, definition Definition, actor ControlActor) error {
	return s.createDefinition(ctx, definition, &actor)
}
func (s *SQLStore) CreateSubmittedVersion(ctx context.Context, version Version, actor ControlActor) error {
	return s.createVersion(ctx, version, &actor)
}

func (s *SQLStore) PublishSubmittedObject(ctx context.Context, kind, id string, expected uint64, actor ControlActor) error {
	if (kind != "definition" && kind != "version") || id == "" || len(id) > 128 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\x00\r\n") || expected == 0 {
		return ErrRevisionConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.beginRelease(ctx, tx, actor, ControlApprove); err != nil {
		return err
	}
	var submittedBy, approvedBy string
	var approvedRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT submitted_by,approved_by,approved_revision FROM platform_catalog_submission WHERE object_kind=? AND object_id=? FOR UPDATE`), kind, id).Scan(&submittedBy, &approvedBy, &approvedRevision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrReleaseSubmissionMissing
		}
		return err
	}
	if submittedBy == "" || actor.PrincipalID == submittedBy {
		return ErrCatalogForbidden
	}
	var status DefinitionStatus
	var revision uint64
	if kind == "definition" {
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT d.status,d.revision FROM platform_catalog_definition d JOIN platform_catalog_definition_metadata m ON m.definition_id=d.id WHERE d.id=? FOR UPDATE`), id).Scan(&status, &revision)
	} else {
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT v.status,v.revision FROM platform_catalog_version v JOIN platform_catalog_version_artifact a ON a.version_id=v.id WHERE v.id=? FOR UPDATE`), id).Scan(&status, &revision)
	}
	if err != nil {
		return err
	}
	if status == DefinitionPublished && revision == expected+1 && approvedRevision == revision && approvedBy == actor.PrincipalID {
		if err := s.releaseAuthorize(ctx, actor, ControlApprove); err != nil {
			return err
		}
		return tx.Commit()
	}
	if status != DefinitionEvaluated || revision != expected || approvedBy != "" {
		return ErrRevisionConflict
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if kind == "definition" {
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_definition SET status=?,revision=revision+1,updated_at=? WHERE id=? AND status=? AND revision=?`), DefinitionPublished, now, id, DefinitionEvaluated, expected)
	} else {
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_version SET status=?,revision=revision+1,published_at=? WHERE id=? AND status=? AND revision=?`), DefinitionPublished, now, id, DefinitionEvaluated, expected)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_submission SET approved_by=?,approved_at=?,approved_revision=? WHERE object_kind=? AND object_id=?`), actor.PrincipalID, now, expected+1, kind, id); err != nil {
		return err
	}
	if err := s.releaseRecord(ctx, tx, ReleaseDecision{Kind: kind, ID: id, Action: "approved", Actor: actor, SubmittedBy: submittedBy, Revision: expected + 1, CreatedAt: now}); err != nil {
		return err
	}
	if err := s.releaseAuthorize(ctx, actor, ControlApprove); err != nil {
		return err
	}
	return tx.Commit()
}
