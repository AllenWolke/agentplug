package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"slices"
	"strings"
	"time"
)

// MigrationSource is an IAM baseline, not an appointment or authorization.
// Authentication digests include revoked bindings and credential changes without
// publishing password hashes, machine secret hashes, issuers or OIDC subjects.
type MigrationSource struct {
	Snapshot             PermissionSnapshot `json:"snapshot"`
	PolicyRevision       uint64             `json:"policy_revision"`
	PermissionEpoch      uint64             `json:"permission_epoch"`
	AuthenticationDigest string             `json:"authentication_digest"`
	SourceDigest         string             `json:"source_digest"`
}

type MigrationSubject struct {
	Type PrincipalType `json:"principal_type"`
	ID   string        `json:"subject_id"`
}

type MigrationSourceBatch struct {
	ReadAt   time.Time         `json:"read_at"`
	TenantID string            `json:"tenant_id"`
	Sources  []MigrationSource `json:"sources"`
	Digest   string            `json:"digest"`
}

// InspectMigrationSources is for maintenance tooling against an explicitly
// migrated database copy. It performs SELECT only, never installs a schema,
// changes credentials, enables a subject, or infers administrator appointments.
// All selected subjects, authorization and authentication facts share one
// repeatable-read snapshot. This method is not exposed as a browser API.
func (s *SQLStore) InspectMigrationSources(ctx context.Context, tenant string, subjects []MigrationSubject) (MigrationSourceBatch, error) {
	result := MigrationSourceBatch{TenantID: tenant, Sources: []MigrationSource{}}
	if s == nil || s.db == nil {
		return result, errors.New("identity database is required")
	}
	if tenant == "" || strings.TrimSpace(tenant) != tenant || strings.ContainsAny(tenant, "*\x00\r\n") || len(subjects) == 0 || len(subjects) > 1000 {
		return result, ErrInvalidResource
	}
	selected := slices.Clone(subjects)
	slices.SortFunc(selected, func(a, b MigrationSubject) int {
		if c := strings.Compare(string(a.Type), string(b.Type)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	for i, subject := range selected {
		if (subject.Type != PrincipalUser && subject.Type != PrincipalServicePrincipal) || subject.ID == "" || len(subject.ID) > 128 || strings.TrimSpace(subject.ID) != subject.ID || strings.ContainsAny(subject.ID, "*\x00\r\n") || (i > 0 && selected[i-1] == subject) {
			return result, ErrInvalidResource
		}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	result.ReadAt = s.clock().UTC()
	for _, subject := range selected {
		source := MigrationSource{}
		source.Snapshot, err = loadPermissionSnapshot(ctx, tx, subject.Type, subject.ID)
		if err != nil {
			return MigrationSourceBatch{}, err
		}
		if source.Snapshot.Principal.TenantID != tenant {
			return MigrationSourceBatch{}, ErrPermissionDenied
		}
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,epoch FROM platform_identity_policy_migration WHERE principal_type=? AND subject_id=?`), subject.Type, subject.ID).Scan(&source.PolicyRevision, &source.PermissionEpoch)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return MigrationSourceBatch{}, err
		}
		source.AuthenticationDigest, err = migrationAuthenticationDigest(ctx, tx, subject, tenant)
		if err != nil {
			return MigrationSourceBatch{}, err
		}
		source.SourceDigest, err = migrationSourceDigest(source)
		if err != nil {
			return MigrationSourceBatch{}, err
		}
		result.Sources = append(result.Sources, source)
	}
	raw, err := json.Marshal(struct {
		Tenant  string            `json:"tenant_id"`
		Sources []MigrationSource `json:"sources"`
	}{tenant, result.Sources})
	if err != nil {
		return MigrationSourceBatch{}, err
	}
	result.Digest = permissionHash(raw)
	if err := tx.Commit(); err != nil {
		return MigrationSourceBatch{}, err
	}
	return result, nil
}

func migrationSourceDigest(source MigrationSource) (string, error) {
	source.SourceDigest = ""
	raw, err := json.Marshal(source)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func migrationAuthenticationDigest(ctx context.Context, reader permissionReader, subject MigrationSubject, tenant string) (string, error) {
	// This projection is retained only long enough to hash it; exported reports
	// receive one opaque digest. Table and column boundaries are included.
	facts := [][][]string{}
	queries := []struct {
		sql     string
		columns int
	}{}
	if subject.Type == PrincipalUser {
		queries = append(queries,
			struct {
				sql     string
				columns int
			}{`SELECT tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active FROM platform_identity_local_credential WHERE principal_id=? AND tenant_id=?`, 7},
			struct {
				sql     string
				columns int
			}{`SELECT identity_key,issuer,subject,tenant_id,department_id,application_id,status,revision FROM platform_identity_oidc_binding WHERE principal_id=? AND tenant_id=? ORDER BY identity_key COLLATE "C"`, 8})
	} else {
		queries = append(queries, struct {
			sql     string
			columns int
		}{`SELECT tenant_id,secret_hash,network_cidrs_json,status,revision FROM platform_identity_machine_credential WHERE principal_id=? AND tenant_id=?`, 5})
	}
	for _, query := range queries {
		rows, err := reader.QueryContext(ctx, sqlutil.Bind(query.sql), subject.ID, tenant)
		if err != nil {
			return "", err
		}
		group := [][]string{}
		for rows.Next() {
			values := make([]string, query.columns)
			dest := make([]any, query.columns)
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return "", err
			}
			group = append(group, values)
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		facts = append(facts, group)
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}
