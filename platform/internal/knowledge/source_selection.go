package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/lexagent/platform/internal/sqlutil"
)

// SnapshotDocuments reads only requested current source heads, in one captured
// revision. IDs must come from platform authorization, not an Agent allowlist.
// Returned bodies are internal integrity material; callers expose facts only.
func (p PostgresSource) SnapshotDocuments(ctx context.Context, scope ProjectionScope, ids []string) (SourceSnapshot, error) {
	empty := SourceSnapshot{Documents: []SourceDocument{}}
	if p.DB == nil || !scope.valid() || len(ids) < 1 || len(ids) > 512 {
		return empty, ErrInvalidProjection
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || !utf8.ValidString(id) || seen[id] {
			return empty, ErrInvalidProjection
		}
		seen[id] = true
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return empty, err
	}
	if tx, joined, err := sqlutil.ContinuityTransaction(ctx, p.DB); joined {
		if err != nil {
			return empty, err
		}
		// The source writer locks this collection head before changing any
		// document. Join the owner rather than acquiring another connection
		// while it holds IAM continuity; never commit its transaction here.
		return selectedSourceDocumentsTx(ctx, tx, scope, seen, raw, true)
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	result, err := selectedSourceDocumentsTx(ctx, tx, scope, seen, raw, false)
	if err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return result, nil
}

func selectedSourceDocumentsTx(ctx context.Context, tx *sql.Tx, scope ProjectionScope, seen map[string]bool, raw []byte, fenced bool) (SourceSnapshot, error) {
	empty := SourceSnapshot{Documents: []SourceDocument{}}
	result := empty
	query := `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`
	if fenced {
		query += " FOR SHARE"
	}
	err := tx.QueryRowContext(ctx, query, scope.args()...).Scan(&result.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	rows, err := tx.QueryContext(ctx, `WITH requested AS (SELECT jsonb_array_elements_text($5::jsonb) AS document_id)
 SELECT v.document_id,v.document_version,v.source_revision,v.acl_revision,v.deleted,v.content_digest,v.payload
 FROM platform_knowledge_document_head h JOIN platform_knowledge_document_version v USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version)
 JOIN requested r USING(document_id)
 WHERE h.tenant_id=$1 AND h.department_id=$2 AND h.application_id=$3 AND h.knowledge_id=$4 ORDER BY h.document_id`, append(scope.args(), string(raw))...)
	if err != nil {
		return empty, err
	}
	for rows.Next() {
		document, err := scanSourceDocument(rows)
		if err != nil {
			rows.Close()
			return empty, err
		}
		if !seen[document.ID] || document.SourceRevision > result.Revision {
			rows.Close()
			return empty, ErrSourceCorrupt
		}
		result.Documents = append(result.Documents, document)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return empty, readErr
	}
	if closeErr != nil {
		return empty, closeErr
	}
	return result, nil
}
