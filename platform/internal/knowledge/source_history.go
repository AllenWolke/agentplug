package knowledge

import (
	"context"
	"database/sql"
	"errors"
)

// SnapshotAt is an internal recovery port. Historical facts never authorize a
// query/cache hit: those must use current source facts and live Identity. A
// resumed index job can rebuild its original snapshot, but publication still
// compares the captured revision with the current source head.
func (p PostgresSource) SnapshotAt(ctx context.Context, scope ProjectionScope, revision int64, maximum int) (SourceSnapshot, error) {
	result := SourceSnapshot{Revision: revision, Documents: []SourceDocument{}}
	if p.DB == nil || !scope.valid() || revision < 0 || maximum < 1 || maximum > 100000 {
		return SourceSnapshot{}, ErrInvalidProjection
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return SourceSnapshot{}, err
	}
	defer tx.Rollback()
	var head int64
	err = tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, scope.args()...).Scan(&head)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SourceSnapshot{}, err
	}
	if revision > head {
		return SourceSnapshot{}, ErrSourceCorrupt
	}
	// A count alone cannot mask gaps: primary key uniqueness, lower/upper bounds,
	// exact count and min/max together prove the integer prefix 1..revision.
	var count, min, max int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(source_revision),0),COALESCE(MAX(source_revision),0) FROM platform_knowledge_source_event WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND source_revision<=$5`, append(scope.args(), revision)...).Scan(&count, &min, &max); err != nil {
		return SourceSnapshot{}, err
	}
	if count != revision || max != revision || (revision > 0 && min != 1) {
		return SourceSnapshot{}, ErrSourceCorrupt
	}
	// Events must describe their actual immutable version, not forged receipts.
	var invalid int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_knowledge_source_event e JOIN platform_knowledge_document_version v USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) WHERE e.tenant_id=$1 AND e.department_id=$2 AND e.application_id=$3 AND e.knowledge_id=$4 AND e.source_revision<=$5 AND (COALESCE(e.receipt->>'actor_principal_id','')='' OR e.source_revision<>v.source_revision OR COALESCE(e.receipt->>'source_revision'=e.source_revision::text,false)=false OR COALESCE(e.receipt->>'document_id'=e.document_id,false)=false OR COALESCE(e.receipt->>'document_version'=e.document_version::text,false)=false OR COALESCE(e.receipt->>'acl_revision'=v.acl_revision::text,false)=false OR COALESCE(e.receipt->>'content_digest'=v.content_digest,false)=false OR COALESCE(e.receipt->>'deleted'=v.deleted::text,false)=false)`, append(scope.args(), revision)...).Scan(&invalid); err != nil {
		return SourceSnapshot{}, err
	}
	if invalid != 0 {
		return SourceSnapshot{}, ErrSourceCorrupt
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT ON(v.document_id) v.document_id,v.document_version,v.source_revision,v.acl_revision,v.deleted,v.content_digest,v.payload FROM platform_knowledge_document_version v JOIN platform_knowledge_source_event e USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) WHERE v.tenant_id=$1 AND v.department_id=$2 AND v.application_id=$3 AND v.knowledge_id=$4 AND v.source_revision<=$5 AND e.source_revision=v.source_revision ORDER BY v.document_id,v.document_version DESC LIMIT $6`, append(scope.args(), revision, maximum+1)...)
	if err != nil {
		return SourceSnapshot{}, err
	}
	for rows.Next() {
		document, err := scanSourceDocument(rows)
		if err != nil {
			rows.Close()
			return SourceSnapshot{}, err
		}
		result.Documents = append(result.Documents, document)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return SourceSnapshot{}, readErr
	}
	if closeErr != nil {
		return SourceSnapshot{}, closeErr
	}
	if len(result.Documents) > maximum {
		return SourceSnapshot{}, ErrCorpusLimit
	}
	return result, tx.Commit()
}
