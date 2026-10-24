package identity

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/sqlutil"
)

// PrincipalPolicyFacts is authentication metadata, not permission to access a
// resource. Resource authorization must still load and evaluate current grants.
type PrincipalPolicyFacts struct {
	ID       string
	Type     PrincipalType
	TenantID string
	IsActive bool
	Revision uint64
	Mode     string
}

// Read only the facts used by workload authentication in one current MVCC
// statement. No principal, mode, credential or permission decision is cached.
func (s *SQLStore) PrincipalPolicyFacts(ctx context.Context, kind PrincipalType, id string) (PrincipalPolicyFacts, error) {
	if s == nil || s.db == nil {
		return PrincipalPolicyFacts{}, ErrInvalidPrincipal
	}
	reader, err := sqlutil.ContinuityReader(ctx, s.db)
	if err != nil {
		return PrincipalPolicyFacts{}, err
	}
	return readPrincipalPolicyFacts(ctx, reader, kind, id)
}

// Join a caller-owned IAM fence without opening another database connection.
func (s *SQLStore) PrincipalPolicyFactsTx(ctx context.Context, tx *sql.Tx, kind PrincipalType, id string) (PrincipalPolicyFacts, error) {
	if s == nil || s.db == nil || tx == nil {
		return PrincipalPolicyFacts{}, ErrInvalidPrincipal
	}
	return readPrincipalPolicyFacts(ctx, tx, kind, id)
}

func readPrincipalPolicyFacts(ctx context.Context, reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, kind PrincipalType, id string) (PrincipalPolicyFacts, error) {
	var facts PrincipalPolicyFacts
	if id == "" || (kind != PrincipalUser && kind != PrincipalServicePrincipal) {
		return facts, ErrInvalidPrincipal
	}
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT p.id,p.principal_type,p.tenant_id,p.active,p.revision,
 COALESCE(m.policy_mode,'legacy') FROM platform_identity_principal p
 LEFT JOIN platform_identity_policy_migration m ON m.principal_type=p.principal_type AND m.subject_id=p.id
 WHERE p.principal_type=? AND p.id=?`), kind, id).Scan(
		&facts.ID, &facts.Type, &facts.TenantID, &facts.IsActive, &facts.Revision, &facts.Mode)
	if errors.Is(err, sql.ErrNoRows) {
		return facts, ErrPrincipalNotFound
	}
	if err != nil {
		return facts, err
	}
	if facts.Mode != "legacy" && facts.Mode != "shadow" && facts.Mode != "v2" {
		return PrincipalPolicyFacts{}, ErrInvalidResource
	}
	return facts, nil
}
