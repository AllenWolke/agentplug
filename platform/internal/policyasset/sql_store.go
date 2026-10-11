package policyasset

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// SQLStore owns the versioned management records and publishes effective
// snapshots into the read-only table consumed by SQLResolver.
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("policy asset database is required")
	}
	if err := NewSQLResolver(s.db).EnsureSchema(ctx); err != nil {
		return err
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_policy_asset_head (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			agent_id VARCHAR(128) NOT NULL,
			agent_version_id VARCHAR(128) NOT NULL,
			asset_type VARCHAR(24) NOT NULL,
			asset_id VARCHAR(128) COLLATE "C" NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			status VARCHAR(24) NOT NULL,
			PRIMARY KEY (tenant_id, department_id, application_id, agent_id, agent_version_id, asset_type, asset_id)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_policy_asset_version (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			agent_id VARCHAR(128) NOT NULL,
			agent_version_id VARCHAR(128) NOT NULL,
			asset_type VARCHAR(24) NOT NULL,
			asset_id VARCHAR(128) COLLATE "C" NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			status VARCHAR(24) NOT NULL,
			content_json JSON NOT NULL,
			content_hash VARCHAR(64) NOT NULL,
			created_by VARCHAR(128) NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id, department_id, application_id, agent_id, agent_version_id, asset_type, asset_id, revision));
CREATE INDEX IF NOT EXISTS idx_policy_asset_scope_type ON platform_policy_asset_version (tenant_id, department_id, application_id, agent_id, agent_version_id, asset_type, created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_policy_snapshot_revision (
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			agent_id VARCHAR(128) NOT NULL,
			agent_version_id VARCHAR(128) NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			snapshot_hash VARCHAR(64) NOT NULL,
			snapshot_json JSON NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			PRIMARY KEY (tenant_id, department_id, application_id, agent_id, agent_version_id, revision)
		);
`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("policy asset schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("policy asset database is required")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLStore) CreateAsset(ctx context.Context, asset Asset) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy asset create: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_policy_asset_head
		(tenant_id,department_id,application_id,agent_id,agent_version_id,asset_type,asset_id,revision,status)
		VALUES (?,?,?,?,?,?,?,?,?)`), scopeArgs(asset.Scope, asset.Type, asset.ID, asset.Revision, asset.Status)...)
	if err != nil {
		if duplicateKey(err) {
			return ErrAssetConflict
		}
		return fmt.Errorf("insert policy asset head: %w", err)
	}
	if err := insertAssetVersion(ctx, tx, asset); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		if duplicateKey(err) {
			return ErrAssetConflict
		}
		return fmt.Errorf("commit policy asset create: %w", err)
	}
	return nil
}

func (s *SQLStore) GetAsset(ctx context.Context, scope Scope, typ AssetType, id string, revision uint64) (Asset, error) {
	if err := scope.validate(); err != nil {
		return Asset{}, err
	}
	if revision == 0 {
		var current uint64
		err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_policy_asset_head WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			return Asset{}, ErrAssetNotFound
		}
		if err != nil {
			return Asset{}, fmt.Errorf("get policy asset head: %w", err)
		}
		revision = current
	}
	return scanAsset(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT asset_id,asset_type,tenant_id,department_id,application_id,agent_id,agent_version_id,revision,status,content_json,content_hash,created_by,created_at
		FROM platform_policy_asset_version WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=? AND revision=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id, revision))
}

func (s *SQLStore) ListAssets(ctx context.Context, scope Scope, typ AssetType, limit int) ([]Asset, error) {
	if err := scope.validate(); err != nil || limit < 1 || limit > 100 || (typ != "" && !validAssetType(typ)) {
		return nil, ErrInvalidAsset
	}
	query := `SELECT v.asset_id,v.asset_type,v.tenant_id,v.department_id,v.application_id,v.agent_id,v.agent_version_id,v.revision,v.status,v.content_json,v.content_hash,v.created_by,v.created_at
		FROM platform_policy_asset_head h JOIN platform_policy_asset_version v
		ON v.tenant_id=h.tenant_id AND v.department_id=h.department_id AND v.application_id=h.application_id AND v.agent_id=h.agent_id AND v.agent_version_id=h.agent_version_id AND v.asset_type=h.asset_type AND v.asset_id=h.asset_id AND v.revision=h.revision
		WHERE h.tenant_id=? AND h.department_id=? AND h.application_id=? AND h.agent_id=? AND h.agent_version_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID}
	if typ != "" {
		query += ` AND h.asset_type=?`
		args = append(args, typ)
	}
	query += ` ORDER BY h.asset_type,h.asset_id LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("list policy assets: %w", err)
	}
	defer rows.Close()
	items := make([]Asset, 0)
	for rows.Next() {
		item, err := scanAssetRows(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read policy assets: %w", err)
	}
	return items, nil
}

func (s *SQLStore) GetSnapshot(ctx context.Context, scope Scope) (Snapshot, error) {
	if err := scope.validate(); err != nil {
		return Snapshot{}, err
	}
	trustedScope := sharedkernel.Scope{
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		PrincipalID: "policyasset-control-plane", PrincipalType: "user",
	}
	return NewSQLResolver(s.db).Resolve(ctx, trustedScope, scope.AgentVersionID)
}

func (s *SQLStore) UpdateAsset(ctx context.Context, scope Scope, typ AssetType, id string, expected uint64, content json.RawMessage) (Asset, error) {
	canonical, hash, err := canonicalContent(typ, content)
	if err != nil || scope.validate() != nil || !validID(id) || expected == 0 {
		return Asset{}, ErrInvalidAsset
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Asset{}, fmt.Errorf("begin policy asset update: %w", err)
	}
	defer tx.Rollback()
	current, err := lockAssetHead(ctx, tx, scope, typ, id)
	if err != nil {
		return Asset{}, err
	}
	if current.Revision != expected {
		return Asset{}, ErrAssetConflict
	}
	next := Asset{ID: id, Type: typ, Scope: scope, Revision: expected + 1, Status: AssetDraft, Content: canonical, Hash: hash, CreatedBy: current.CreatedBy, CreatedAt: time.Now().UTC()}
	if err := insertAssetVersion(ctx, tx, next); err != nil {
		return Asset{}, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_policy_asset_head SET revision=?,status=? WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=? AND revision=?`), next.Revision, next.Status, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id, expected)
	if err != nil {
		return Asset{}, fmt.Errorf("advance policy asset revision: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Asset{}, ErrAssetConflict
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, fmt.Errorf("commit policy asset update: %w", err)
	}
	return next, nil
}

func (s *SQLStore) PublishAsset(ctx context.Context, scope Scope, typ AssetType, id string, expected uint64) (Asset, error) {
	if scope.validate() != nil || !validAssetType(typ) || !validID(id) || expected == 0 {
		return Asset{}, ErrInvalidAsset
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Asset{}, fmt.Errorf("begin policy asset publish: %w", err)
	}
	defer tx.Rollback()
	current, err := lockAssetHead(ctx, tx, scope, typ, id)
	if err != nil {
		return Asset{}, err
	}
	if current.Revision != expected {
		return Asset{}, ErrAssetConflict
	}
	if current.Status != AssetDraft {
		return Asset{}, ErrAssetConflict
	}
	next := current
	next.Revision++
	next.Status = AssetPublished
	next.CreatedAt = time.Now().UTC()
	if err := insertAssetVersion(ctx, tx, next); err != nil {
		return Asset{}, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_policy_asset_head SET revision=?,status=? WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=? AND revision=? AND status=?`), next.Revision, next.Status, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id, expected, AssetDraft)
	if err != nil {
		return Asset{}, fmt.Errorf("publish policy asset head: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Asset{}, ErrAssetConflict
	}
	if err := tx.Commit(); err != nil {
		return Asset{}, fmt.Errorf("commit policy asset publish: %w", err)
	}
	return next, nil
}

func (s *SQLStore) PublishSnapshot(ctx context.Context, req PublishSnapshotRequest) (Snapshot, error) {
	if req.Scope.validate() != nil || req.ExpectedRevision > 1_000_000_000 || len(req.Assets) != 6 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("begin policy snapshot publish: %w", err)
	}
	defer tx.Rollback()
	assets := make(map[AssetType]Asset, 6)
	for _, typ := range []AssetType{AssetModel, AssetPrompt, AssetTool, AssetMemory, AssetKnowledge, AssetRuntime} {
		ref, ok := req.Assets[typ]
		if !ok || !validID(ref.ID) || ref.Revision == 0 {
			return Snapshot{}, ErrInvalidSnapshot
		}
		asset, err := scanAsset(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT asset_id,asset_type,tenant_id,department_id,application_id,agent_id,agent_version_id,revision,status,content_json,content_hash,created_by,created_at
			FROM platform_policy_asset_version WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=? AND revision=?`), req.Scope.TenantID, req.Scope.DepartmentID, req.Scope.ApplicationID, req.Scope.AgentID, req.Scope.AgentVersionID, typ, ref.ID, ref.Revision))
		if err != nil {
			return Snapshot{}, err
		}
		if asset.Status != AssetPublished {
			return Snapshot{}, ErrInvalidSnapshot
		}
		assets[typ] = asset
	}
	snapshot, err := snapshotFromAssets(req, assets)
	if err != nil {
		return Snapshot{}, err
	}
	currentRevision, err := lockSnapshotRevision(ctx, tx, req.Scope)
	if err != nil {
		return Snapshot{}, err
	}
	if currentRevision != req.ExpectedRevision {
		return Snapshot{}, ErrAssetConflict
	}
	snapshot.Revision = currentRevision + 1
	hashInput, err := json.Marshal(struct {
		Snapshot Snapshot               `json:"snapshot"`
		Assets   map[AssetType]AssetRef `json:"assets"`
	}{snapshot, req.Assets})
	if err != nil {
		return Snapshot{}, fmt.Errorf("hash policy snapshot: %w", err)
	}
	checksum := sha256.Sum256(hashInput)
	snapshot.Hash = hex.EncodeToString(checksum[:])
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if err := snapshot.ValidateDetails(); err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return Snapshot{}, fmt.Errorf("encode policy snapshot revision: %w", err)
	}
	if err := insertSnapshotRevision(ctx, tx, req.Scope, snapshot, snapshotJSON); err != nil {
		return Snapshot{}, err
	}
	if err := writeResolverSnapshot(ctx, tx, req.Scope, snapshot, currentRevision); err != nil {
		return Snapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		if duplicateKey(err) {
			return Snapshot{}, ErrAssetConflict
		}
		return Snapshot{}, fmt.Errorf("commit policy snapshot publish: %w", err)
	}
	return snapshot, nil
}

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func scopeArgs(scope Scope, typ AssetType, id string, revision uint64, status AssetStatus) []any {
	return []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id, revision, status}
}

func insertAssetVersion(ctx context.Context, exec sqlExecer, asset Asset) error {
	_, err := exec.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_policy_asset_version
		(tenant_id,department_id,application_id,agent_id,agent_version_id,asset_type,asset_id,revision,status,content_json,content_hash,created_by,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`), asset.Scope.TenantID, asset.Scope.DepartmentID, asset.Scope.ApplicationID, asset.Scope.AgentID, asset.Scope.AgentVersionID, asset.Type, asset.ID, asset.Revision, asset.Status, asset.Content, asset.Hash, asset.CreatedBy)
	if err != nil {
		if duplicateKey(err) {
			return ErrAssetConflict
		}
		return fmt.Errorf("insert policy asset version: %w", err)
	}
	return nil
}

func lockAssetHead(ctx context.Context, tx *sql.Tx, scope Scope, typ AssetType, id string) (Asset, error) {
	var current Asset
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,status FROM platform_policy_asset_head WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id).Scan(&current.Revision, &current.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrAssetNotFound
	}
	if err != nil {
		return Asset{}, fmt.Errorf("lock policy asset head: %w", err)
	}
	current, err = scanAsset(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT asset_id,asset_type,tenant_id,department_id,application_id,agent_id,agent_version_id,revision,status,content_json,content_hash,created_by,created_at FROM platform_policy_asset_version WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND asset_type=? AND asset_id=? AND revision=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, typ, id, current.Revision))
	return current, err
}

type rowScanner interface{ Scan(...any) error }

func scanAsset(row rowScanner) (Asset, error) {
	var a Asset
	var content []byte
	err := row.Scan(&a.ID, &a.Type, &a.Scope.TenantID, &a.Scope.DepartmentID, &a.Scope.ApplicationID, &a.Scope.AgentID, &a.Scope.AgentVersionID, &a.Revision, &a.Status, &content, &a.Hash, &a.CreatedBy, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrAssetNotFound
	}
	if err != nil {
		return Asset{}, fmt.Errorf("scan policy asset: %w", err)
	}
	a.Content = append(json.RawMessage(nil), content...)
	return a, nil
}

func scanAssetRows(rows *sql.Rows) (Asset, error) { return scanAsset(rows) }

func lockSnapshotRevision(ctx context.Context, tx *sql.Tx, scope Scope) (uint64, error) {
	var revision uint64
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_policy_snapshot WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("lock active policy snapshot: %w", err)
	}
	return revision, nil
}

func insertSnapshotRevision(ctx context.Context, tx *sql.Tx, scope Scope, snapshot Snapshot, encoded []byte) error {
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_policy_snapshot_revision
		(tenant_id,department_id,application_id,agent_id,agent_version_id,revision,snapshot_hash,snapshot_json,created_at)
		VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, snapshot.Revision, snapshot.Hash, encoded)
	if err != nil {
		if duplicateKey(err) {
			return ErrAssetConflict
		}
		return fmt.Errorf("insert policy snapshot history: %w", err)
	}
	return nil
}

func writeResolverSnapshot(ctx context.Context, tx *sql.Tx, scope Scope, snapshot Snapshot, expected uint64) error {
	modelJSON, _ := json.Marshal(snapshot.Model)
	promptJSON, _ := json.Marshal(snapshot.Prompt)
	toolJSON, _ := json.Marshal(snapshot.Tool)
	memoryJSON, _ := json.Marshal(snapshot.Memory)
	knowledgeJSON, _ := json.Marshal(snapshot.Knowledge)
	runtimeJSON, _ := json.Marshal(snapshot.Runtime)
	ruleJSON, _ := json.Marshal(snapshot.Rule)
	if expected == 0 {
		_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_policy_snapshot
			(tenant_id,department_id,application_id,agent_id,agent_version_id,revision,snapshot_hash,model_profile_id,prompt_version_id,tool_policy_id,memory_policy_id,knowledge_policy_id,runtime_policy_id,model_policy_json,prompt_policy_json,tool_policy_json,memory_policy_json,knowledge_policy_json,runtime_policy_json,rule_policy_json,created_at,updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, snapshot.Revision, snapshot.Hash, snapshot.ModelProfileID, snapshot.PromptVersionID, snapshot.ToolPolicyID, snapshot.MemoryPolicyID, snapshot.KnowledgePolicyID, snapshot.RuntimePolicyID, modelJSON, promptJSON, toolJSON, memoryJSON, knowledgeJSON, runtimeJSON, ruleJSON)
		if err != nil {
			if duplicateKey(err) {
				return ErrAssetConflict
			}
			return fmt.Errorf("insert active policy snapshot: %w", err)
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_policy_snapshot SET revision=?,snapshot_hash=?,model_profile_id=?,prompt_version_id=?,tool_policy_id=?,memory_policy_id=?,knowledge_policy_id=?,runtime_policy_id=?,model_policy_json=?,prompt_policy_json=?,tool_policy_json=?,memory_policy_json=?,knowledge_policy_json=?,runtime_policy_json=?,rule_policy_json=?,updated_at=CURRENT_TIMESTAMP
		WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND revision=?`), snapshot.Revision, snapshot.Hash, snapshot.ModelProfileID, snapshot.PromptVersionID, snapshot.ToolPolicyID, snapshot.MemoryPolicyID, snapshot.KnowledgePolicyID, snapshot.RuntimePolicyID, modelJSON, promptJSON, toolJSON, memoryJSON, knowledgeJSON, runtimeJSON, ruleJSON, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID, expected)
	if err != nil {
		return fmt.Errorf("advance active policy snapshot: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrAssetConflict
	}
	return nil
}

func duplicateKey(err error) bool {
	if err == nil {
		return false
	}
	return sqlutil.IsUniqueViolation(err)
}

var _ Store = (*SQLStore)(nil)
