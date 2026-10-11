package knowledge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"
)

//go:embed source_schema.sql
var SourceSchema string

var ErrSourceConflict = errors.New("knowledge source revision conflict")
var ErrSourceCorrupt = errors.New("knowledge source continuity unavailable")
var ErrSourceRecorderUnavailable = errors.New("knowledge source transactional recorder unavailable")

// ACL is authoritative source metadata, not a replacement for live Identity
// grants. Composition must intersect it with caller AND workload permissions.
type DocumentACL struct {
	OwnerPrincipalID   string   `json:"owner_principal_id"`
	ApplicationVisible bool     `json:"application_visible"`
	Readers            []string `json:"readers,omitempty"`
}

type SourceDocument struct {
	ID             string            `json:"id"`
	Version        int64             `json:"version"`
	SourceRevision int64             `json:"source_revision"`
	ACLRevision    int64             `json:"acl_revision"`
	Body           string            `json:"body"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ACL            DocumentACL       `json:"acl"`
	Deleted        bool              `json:"deleted"`
	ContentDigest  string            `json:"content_digest"`
}

func (d SourceDocument) Fact() DocumentFact {
	return DocumentFact{ID: d.ID, Version: strconv.FormatInt(d.Version, 10), ACLRevision: strconv.FormatInt(d.ACLRevision, 10)}
}

type SourceChange struct {
	DocumentID              string            `json:"document_id"`
	ActorPrincipalID        string            `json:"actor_principal_id"`
	ExpectedSourceRevision  int64             `json:"expected_source_revision"`
	ExpectedDocumentVersion int64             `json:"expected_document_version"`
	IdempotencyKey          string            `json:"idempotency_key"`
	Body                    string            `json:"body"`
	Metadata                map[string]string `json:"metadata,omitempty"`
	ACL                     DocumentACL       `json:"acl"`
	Deleted                 bool              `json:"deleted"`
}

type SourceReceipt struct {
	ActorPrincipalID string `json:"actor_principal_id"`
	DocumentID       string `json:"document_id"`
	DocumentVersion  int64  `json:"document_version"`
	SourceRevision   int64  `json:"source_revision"`
	ACLRevision      int64  `json:"acl_revision"`
	Deleted          bool   `json:"deleted"`
	ContentDigest    string `json:"content_digest"`
}

// This internal repository is not exposed to Agents. The public service must
// validate current management authority before calling it, including replay.
// RecordChange must write audit/notification records through this same tx.
// Source events themselves form the durable, ordered indexing Outbox.
type PostgresSource struct {
	DB *sql.DB
	// Composition checks current authority before any write or replay lookup.
	GuardChangeTx func(context.Context, *sql.Tx, ProjectionScope, SourceChange) error
	RecordChange  func(context.Context, *sql.Tx, ProjectionScope, SourceReceipt) error
}

type sourceRowScanner interface{ Scan(...any) error }

func scanSourceDocument(row sourceRowScanner) (SourceDocument, error) {
	var indexed SourceDocument
	var document SourceDocument
	var raw []byte
	if err := row.Scan(&indexed.ID, &indexed.Version, &indexed.SourceRevision, &indexed.ACLRevision, &indexed.Deleted, &indexed.ContentDigest, &raw); err != nil {
		return document, err
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return SourceDocument{}, ErrSourceCorrupt
	}
	digest, err := sourceDigest(struct {
		Body     string
		Metadata map[string]string `json:"metadata,omitempty"`
	}{document.Body, document.Metadata})
	if err != nil || document.ID != indexed.ID || document.Version != indexed.Version || document.SourceRevision != indexed.SourceRevision || document.ACLRevision != indexed.ACLRevision || document.Deleted != indexed.Deleted || document.ContentDigest != indexed.ContentDigest || digest != document.ContentDigest || document.Version < 1 || document.SourceRevision < 1 || document.ACLRevision < 1 || (document.Deleted && document.Body != "") {
		return SourceDocument{}, ErrSourceCorrupt
	}
	return document, nil
}

// ReadVersion is an internal indexing port. Its immutable version must come
// from a committed snapshot/event, never from an Agent's claimed authority.
func (p PostgresSource) ReadVersion(ctx context.Context, scope ProjectionScope, id string, version int64) (SourceDocument, error) {
	if p.DB == nil || !scope.valid() || id == "" || len(id) > 256 || version < 1 {
		return SourceDocument{}, ErrInvalidProjection
	}
	return scanSourceDocument(p.DB.QueryRowContext(ctx, `SELECT document_id,document_version,source_revision,acl_revision,deleted,content_digest,payload FROM platform_knowledge_document_version WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND document_id=$5 AND document_version=$6`, append(scope.args(), id, version)...))
}

func sourceDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func normalizeSourceChange(c SourceChange) (SourceChange, error) {
	if c.DocumentID == "" || !utf8.ValidString(c.DocumentID) || len(c.DocumentID) > 256 || c.ActorPrincipalID == "" || !utf8.ValidString(c.ActorPrincipalID) || len(c.ActorPrincipalID) > 256 || c.IdempotencyKey == "" || !utf8.ValidString(c.IdempotencyKey) || len(c.IdempotencyKey) > 256 || c.ExpectedSourceRevision < 0 || c.ExpectedSourceRevision == math.MaxInt64 || c.ExpectedDocumentVersion < 0 || c.ExpectedDocumentVersion == math.MaxInt64 {
		return c, ErrInvalidProjection
	}
	if c.Deleted {
		if c.Body != "" || len(c.Metadata) != 0 || c.ACL.OwnerPrincipalID != "" || c.ACL.ApplicationVisible || len(c.ACL.Readers) != 0 || c.ExpectedDocumentVersion == 0 {
			return c, ErrInvalidProjection
		}
		return c, nil
	}
	if len(c.Body) == 0 || len(c.Body) > 1048576 || !utf8.ValidString(c.Body) || c.ACL.OwnerPrincipalID == "" || !utf8.ValidString(c.ACL.OwnerPrincipalID) || len(c.ACL.OwnerPrincipalID) > 256 || len(c.ACL.Readers) > 1000 || len(c.Metadata) > 32 {
		return c, ErrInvalidProjection
	}
	readers := append([]string(nil), c.ACL.Readers...)
	sort.Strings(readers)
	for i, r := range readers {
		if r == "" || !utf8.ValidString(r) || len(r) > 256 || (i > 0 && r == readers[i-1]) {
			return c, ErrInvalidProjection
		}
	}
	c.ACL.Readers = readers
	metadata := make(map[string]string, len(c.Metadata))
	for k, v := range c.Metadata {
		if k == "" || len(k) > 64 || len(v) > 1024 || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return c, ErrInvalidProjection
		}
		metadata[k] = v
	}
	c.Metadata = metadata
	return c, nil
}

// Change holds the per-knowledge head lock until COMMIT. Therefore revision N+1
// cannot commit before N. An event cursor is not based on an auto-increment ID
// allocated before commit; rolled-back changes consume no revision.
func (p PostgresSource) Change(ctx context.Context, scope ProjectionScope, command SourceChange) (SourceReceipt, error) {
	var receipt SourceReceipt
	if p.DB == nil || !scope.valid() {
		return receipt, ErrInvalidProjection
	}
	if p.RecordChange == nil {
		return receipt, ErrSourceRecorderUnavailable
	}
	command, err := normalizeSourceChange(command)
	if err != nil {
		return receipt, err
	}
	digest, err := sourceDigest(command)
	if err != nil {
		return receipt, err
	}
	retryHash, _ := sourceDigest(command.IdempotencyKey)
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	if p.GuardChangeTx != nil {
		if err := p.GuardChangeTx(ctx, tx, scope, command); err != nil {
			return SourceReceipt{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_knowledge_source_head(tenant_id,department_id,application_id,knowledge_id,source_revision) VALUES($1,$2,$3,$4,0) ON CONFLICT DO NOTHING`, scope.args()...); err != nil {
		return receipt, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR UPDATE`, scope.args()...).Scan(&revision); err != nil {
		return receipt, err
	}
	var priorDigest string
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT request_digest,receipt FROM platform_knowledge_source_event WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND idempotency_hash=$5`, append(scope.args(), retryHash)...).Scan(&priorDigest, &raw)
	if err == nil {
		if priorDigest != digest {
			return receipt, ErrSourceConflict
		}
		if err = json.Unmarshal(raw, &receipt); err != nil {
			return SourceReceipt{}, ErrSourceCorrupt
		}
		if receipt.ActorPrincipalID != command.ActorPrincipalID || receipt.DocumentID != command.DocumentID || receipt.DocumentVersion != command.ExpectedDocumentVersion+1 || receipt.SourceRevision != command.ExpectedSourceRevision+1 || receipt.Deleted != command.Deleted || receipt.SourceRevision > revision {
			return SourceReceipt{}, ErrSourceCorrupt
		}
		stored, err := scanSourceDocument(tx.QueryRowContext(ctx, `SELECT document_id,document_version,source_revision,acl_revision,deleted,content_digest,payload FROM platform_knowledge_document_version WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND document_id=$5 AND document_version=$6`, append(scope.args(), receipt.DocumentID, receipt.DocumentVersion)...))
		if err != nil || stored.SourceRevision != receipt.SourceRevision || stored.ACLRevision != receipt.ACLRevision || stored.Deleted != receipt.Deleted || stored.ContentDigest != receipt.ContentDigest {
			return SourceReceipt{}, ErrSourceCorrupt
		}
		return receipt, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return receipt, err
	}
	if revision != command.ExpectedSourceRevision {
		return receipt, ErrSourceConflict
	}
	previous, err := scanSourceDocument(tx.QueryRowContext(ctx, `SELECT v.document_id,v.document_version,v.source_revision,v.acl_revision,v.deleted,v.content_digest,v.payload FROM platform_knowledge_document_head h JOIN platform_knowledge_document_version v USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) WHERE h.tenant_id=$1 AND h.department_id=$2 AND h.application_id=$3 AND h.knowledge_id=$4 AND h.document_id=$5`, append(scope.args(), command.DocumentID)...))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return receipt, err
	}
	if previous.Version != command.ExpectedDocumentVersion || (command.Deleted && previous.Deleted) {
		return receipt, ErrSourceConflict
	}
	document := SourceDocument{ID: command.DocumentID, Version: previous.Version + 1, SourceRevision: revision + 1, ACLRevision: previous.ACLRevision, Body: command.Body, Metadata: command.Metadata, ACL: command.ACL, Deleted: command.Deleted}
	if document.Deleted {
		document.ACL = previous.ACL
		document.Metadata = previous.Metadata
	}
	aclDigest, _ := sourceDigest(document.ACL)
	oldACLDigest, _ := sourceDigest(previous.ACL)
	if document.ACLRevision == 0 || aclDigest != oldACLDigest {
		document.ACLRevision++
	}
	document.ContentDigest, _ = sourceDigest(struct {
		Body     string
		Metadata map[string]string `json:"metadata,omitempty"`
	}{document.Body, document.Metadata})
	raw, err = json.Marshal(document)
	if err != nil {
		return receipt, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_knowledge_document_version(tenant_id,department_id,application_id,knowledge_id,document_id,document_version,source_revision,acl_revision,deleted,content_digest,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, append(scope.args(), document.ID, document.Version, document.SourceRevision, document.ACLRevision, document.Deleted, document.ContentDigest, string(raw))...); err != nil {
		return receipt, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_knowledge_document_head(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,department_id,application_id,knowledge_id,document_id) DO UPDATE SET document_version=EXCLUDED.document_version`, append(scope.args(), document.ID, document.Version)...); err != nil {
		return receipt, err
	}
	receipt = SourceReceipt{ActorPrincipalID: command.ActorPrincipalID, DocumentID: document.ID, DocumentVersion: document.Version, SourceRevision: document.SourceRevision, ACLRevision: document.ACLRevision, Deleted: document.Deleted, ContentDigest: document.ContentDigest}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return SourceReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO platform_knowledge_source_event(tenant_id,department_id,application_id,knowledge_id,source_revision,document_id,document_version,idempotency_hash,request_digest,receipt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`, append(scope.args(), receipt.SourceRevision, receipt.DocumentID, receipt.DocumentVersion, retryHash, digest, string(raw))...); err != nil {
		return SourceReceipt{}, err
	}
	if err := p.RecordChange(ctx, tx, scope, receipt); err != nil {
		return SourceReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE platform_knowledge_source_head SET source_revision=$5 WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 AND source_revision=$6`, append(scope.args(), revision+1, revision)...)
	if err != nil {
		return SourceReceipt{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return SourceReceipt{}, err
	}
	if changed != 1 {
		return SourceReceipt{}, ErrSourceConflict
	}
	return receipt, tx.Commit()
}

type SourceSnapshot struct {
	Revision  int64
	Documents []SourceDocument
}

// Snapshot pins the head and current document versions in one repeatable-read
// snapshot. Tombstones are included for full/incremental reconciliation.
func (p PostgresSource) Snapshot(ctx context.Context, scope ProjectionScope, maximum int) (SourceSnapshot, error) {
	result := SourceSnapshot{Documents: []SourceDocument{}}
	if p.DB == nil || !scope.valid() || maximum < 1 || maximum > 100000 {
		return result, ErrInvalidProjection
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, scope.args()...).Scan(&result.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return result, tx.Commit()
	}
	if err != nil {
		return result, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT v.document_id,v.document_version,v.source_revision,v.acl_revision,v.deleted,v.content_digest,v.payload FROM platform_knowledge_document_head h JOIN platform_knowledge_document_version v USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) WHERE h.tenant_id=$1 AND h.department_id=$2 AND h.application_id=$3 AND h.knowledge_id=$4 ORDER BY h.document_id LIMIT $5`, append(scope.args(), maximum+1)...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		document, err := scanSourceDocument(rows)
		if err != nil {
			rows.Close()
			return SourceSnapshot{}, err
		}
		if document.SourceRevision > result.Revision {
			rows.Close()
			return SourceSnapshot{}, ErrSourceCorrupt
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

type SourceEventPage struct {
	HeadRevision int64
	Events       []SourceReceipt
}

// EventsAfter returns a contiguous committed prefix. Missing events and an
// ahead-of-source cursor fail closed instead of silently advancing past gaps.
func (p PostgresSource) EventsAfter(ctx context.Context, scope ProjectionScope, after int64, limit int) (SourceEventPage, error) {
	result := SourceEventPage{Events: []SourceReceipt{}}
	if p.DB == nil || !scope.valid() || after < 0 || limit < 1 || limit > 1000 {
		return result, ErrInvalidProjection
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4`, scope.args()...).Scan(&result.HeadRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if after > result.HeadRevision {
		return SourceEventPage{}, ErrSourceCorrupt
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.source_revision,v.source_revision,e.document_id,e.document_version,v.acl_revision,v.deleted,v.content_digest,e.receipt FROM platform_knowledge_source_event e JOIN platform_knowledge_document_version v USING(tenant_id,department_id,application_id,knowledge_id,document_id,document_version) WHERE e.tenant_id=$1 AND e.department_id=$2 AND e.application_id=$3 AND e.knowledge_id=$4 AND e.source_revision>$5 AND e.source_revision<=$6 ORDER BY e.source_revision LIMIT $7`, append(scope.args(), after, result.HeadRevision, limit)...)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var indexed SourceReceipt
		var versionRevision int64
		var raw []byte
		var event SourceReceipt
		if err := rows.Scan(&indexed.SourceRevision, &versionRevision, &indexed.DocumentID, &indexed.DocumentVersion, &indexed.ACLRevision, &indexed.Deleted, &indexed.ContentDigest, &raw); err != nil {
			rows.Close()
			return SourceEventPage{}, err
		}
		if err := json.Unmarshal(raw, &event); err != nil || versionRevision != indexed.SourceRevision || event.ActorPrincipalID == "" || event.DocumentID != indexed.DocumentID || event.DocumentVersion != indexed.DocumentVersion || event.ACLRevision != indexed.ACLRevision || event.Deleted != indexed.Deleted || event.ContentDigest != indexed.ContentDigest || event.SourceRevision != indexed.SourceRevision || indexed.SourceRevision != after+int64(len(result.Events))+1 {
			rows.Close()
			return SourceEventPage{}, ErrSourceCorrupt
		}
		result.Events = append(result.Events, event)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return SourceEventPage{}, readErr
	}
	if closeErr != nil {
		return SourceEventPage{}, closeErr
	}
	expected := result.HeadRevision - after
	if expected > int64(limit) {
		expected = int64(limit)
	}
	if int64(len(result.Events)) != expected {
		return SourceEventPage{}, ErrSourceCorrupt
	}
	return result, tx.Commit()
}
