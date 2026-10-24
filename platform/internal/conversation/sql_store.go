package conversation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// SQLStore owns only the platform conversation projection.  It intentionally
// uses database/sql rather than exposing an ORM model across module boundaries.
// SQLStore 只拥有平台会话投影表；故意使用 database/sql，避免 ORM 模型穿透模块边界。
type SQLStore struct {
	db                *sql.DB
	clock             func() time.Time
	publicShareAccess AccessControl
	deletionGuard     func(context.Context, *sql.Tx) error
	deletionRecorder  DeletionApprovalRecorder
	deletionReplay    DeletionApprovalReplayChecker
	erasureAuthorize  ErasureAuthorization
	erasureQuiescent  ErasureQuiescence
	erasureRecorder   ErasureRecorder
}

func (s *SQLStore) SetPublicShareAccessControl(control AccessControl) { s.publicShareAccess = control }

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *SQLStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("conversation database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_conversation_session (
			id VARCHAR(128) PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			owner_id VARCHAR(128) NOT NULL,
			kind VARCHAR(16) NOT NULL,
			agent_id VARCHAR(128) NOT NULL,
			agent_version_id VARCHAR(128) NOT NULL,
			installation_id VARCHAR(128) NOT NULL DEFAULT '',
			title VARCHAR(512) NOT NULL,
			preview TEXT NOT NULL,
			status VARCHAR(32) NOT NULL,
			message_count INT NOT NULL,
			can_continue BOOLEAN NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_conversation_scope ON platform_conversation_session (tenant_id,department_id,application_id,principal_type,owner_id,kind,updated_at);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_message (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			role VARCHAR(16) NOT NULL,
			content TEXT NOT NULL,
			intent_code VARCHAR(64) NOT NULL,
			knowledge_scope VARCHAR(64) NOT NULL,
			metadata_json TEXT NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_conversation_message_scope ON platform_conversation_message (session_id,tenant_id,department_id,application_id,created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_revision (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			message_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			owner_id VARCHAR(128) NOT NULL,
			role VARCHAR(16) NOT NULL,
			content TEXT NOT NULL,
			reason VARCHAR(512) NOT NULL,
			revision_no NUMERIC(20,0) CHECK (revision_no>=0 AND revision_no<=18446744073709551615) NOT NULL,
			is_current BOOLEAN NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_conversation_revision UNIQUE (session_id,message_id,revision_no));
CREATE INDEX IF NOT EXISTS idx_platform_conversation_revision_scope ON platform_conversation_revision (tenant_id,department_id,application_id,owner_id,session_id,message_id);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_regeneration (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			message_id VARCHAR(128) NOT NULL,
			branch_session_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			owner_id VARCHAR(128) NOT NULL,
			version_mode VARCHAR(32) NOT NULL,
			status VARCHAR(32) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_conversation_regeneration UNIQUE (session_id,message_id,version_mode,owner_id));
CREATE INDEX IF NOT EXISTS idx_platform_conversation_regeneration_scope ON platform_conversation_regeneration (tenant_id,department_id,application_id,owner_id,status);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_share (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			owner_id VARCHAR(128) NOT NULL,
			token_hash VARCHAR(64) NOT NULL,
			status VARCHAR(32) NOT NULL,
			expires_at TIMESTAMPTZ(6) NOT NULL,
			include_refs BOOLEAN NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_conversation_share_scope ON platform_conversation_share (tenant_id,department_id,application_id,owner_id,status);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_export (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			owner_id VARCHAR(128) NOT NULL,
			status VARCHAR(32) NOT NULL,
			payload_json TEXT NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			approved_at TIMESTAMPTZ(6) NULL);
CREATE INDEX IF NOT EXISTS idx_platform_conversation_export_scope ON platform_conversation_export (tenant_id,department_id,application_id,owner_id,status);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_deletion (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			principal_type VARCHAR(32) NOT NULL,
			owner_id VARCHAR(128) NOT NULL,
			reason VARCHAR(512) NOT NULL,
			status VARCHAR(32) NOT NULL,
			requested_at TIMESTAMPTZ(6) NOT NULL,
			approved_at TIMESTAMPTZ(6) NULL);
CREATE INDEX IF NOT EXISTS idx_platform_conversation_deletion_scope ON platform_conversation_deletion (tenant_id,department_id,application_id,status,requested_at);`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_retention_policy (
			id VARCHAR(128) PRIMARY KEY,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			kind VARCHAR(16) NOT NULL,
			retention_days INT NOT NULL,
			enabled BOOLEAN NOT NULL,
			revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			updated_by VARCHAR(128) NOT NULL,
			updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_platform_conversation_retention_scope UNIQUE (tenant_id,department_id,application_id,kind)
		);
`,
		`CREATE TABLE IF NOT EXISTS platform_conversation_legal_hold (
			id VARCHAR(128) PRIMARY KEY,
			session_id VARCHAR(128) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL,
			application_id VARCHAR(128) NOT NULL,
			reason VARCHAR(512) NOT NULL,
			status VARCHAR(24) NOT NULL,
			placed_by VARCHAR(128) NOT NULL,
			released_by VARCHAR(128) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL,
			released_at TIMESTAMPTZ(6) NULL);
CREATE INDEX IF NOT EXISTS idx_platform_conversation_hold_scope ON platform_conversation_legal_hold (tenant_id,department_id,application_id,session_id,status);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("conversation schema: %w", err)
		}
	}
	// The public PostgreSQL database uses a fresh schema lineage.
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE INDEX IF NOT EXISTS idx_platform_conversation_share_token ON platform_conversation_share (token_hash)`)); err != nil {
		return err
	}
	return s.EnsureErasureSchema(ctx)
}

func (s *SQLStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("conversation database is required")
	}
	return s.db.PingContext(ctx)
}

func (s *SQLStore) CreateSession(ctx context.Context, scope Scope, session Session) error {
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("%w: scope", ErrInvalidQuery)
	}
	if strings.TrimSpace(session.ID) == "" {
		return fmt.Errorf("%w: session_id", ErrInvalidQuery)
	}
	if strings.TrimSpace(session.Kind) == "" || (session.Kind != "qa" && session.Kind != "check") {
		return fmt.Errorf("%w: kind", ErrInvalidQuery)
	}
	if strings.TrimSpace(session.AgentID) == "" {
		return fmt.Errorf("%w: agent_id", ErrInvalidQuery)
	}
	if strings.TrimSpace(session.AgentVersionID) == "" {
		return fmt.Errorf("%w: agent_version_id", ErrInvalidQuery)
	}
	if strings.TrimSpace(session.Title) == "" {
		return fmt.Errorf("%w: title", ErrInvalidQuery)
	}
	now := s.clock()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = session.CreatedAt
	}
	if session.Revision == 0 {
		session.Revision = 1
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_session
		(id,tenant_id,department_id,application_id,principal_type,owner_id,kind,agent_id,agent_version_id,installation_id,title,preview,status,message_count,can_continue,revision,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), session.ID, scope.TenantID, scope.DepartmentID, scope.ApplicationID,
		scope.PrincipalType, scope.PrincipalID, session.Kind, session.AgentID, session.AgentVersionID, session.InstallationID, session.Title,
		session.Preview, session.Status, session.MessageCount, session.CanContinue, session.Revision, session.CreatedAt, session.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create conversation session: %w", err)
	}
	return nil
}

func (s *SQLStore) AppendMessage(ctx context.Context, scope Scope, message Message) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(message.ID) == "" || strings.TrimSpace(message.SessionID) == "" ||
		(message.Role != "user" && message.Role != "assistant" && message.Role != "system") {
		return ErrInvalidQuery
	}
	if strings.TrimSpace(message.Content) == "" {
		return ErrInvalidQuery
	}
	now := message.CreatedAt
	if now.IsZero() {
		now = s.clock()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin conversation message: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var status string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=? FOR UPDATE`), message.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lock conversation session: %w", err)
	}
	if status == "deleted" {
		return ErrNotFound
	}
	metadata := "{}"
	if message.Metadata != nil {
		encoded, marshalErr := json.Marshal(message.Metadata)
		if marshalErr != nil || len(encoded) > 1<<20 {
			return errors.New("conversation message metadata is invalid or too large")
		}
		metadata = string(encoded)
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_message(id,session_id,tenant_id,department_id,application_id,principal_type,role,content,intent_code,knowledge_scope,metadata_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`), message.ID, message.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, message.Role, message.Content, message.IntentCode, message.KnowledgeScope, metadata, now); err != nil {
		return fmt.Errorf("append conversation message: %w", err)
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET preview=?,message_count=message_count+1,updated_at=?,revision=revision+1 WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=?`), truncate(message.Content, 2048), now, message.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID); err != nil {
		return fmt.Errorf("update conversation summary: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit conversation message: %w", err)
	}
	return nil
}

// RecordRun projects the user input of a platform Run into the product
// history.  It is deliberately a narrow projection hook: the execution
// module does not import conversation tables or SQL, and a remote service can
// replace this implementation later.
// RecordRun 将平台 Run 的用户输入投影到产品历史；Execution 模块不依赖会话表
// 或 SQL，未来可以替换成远程 Conversation Service。
func (s *SQLStore) RecordRun(ctx context.Context, runScope sharedkernel.Scope, requestJSON []byte) error {
	return s.RecordRunWithMessage(ctx, runScope, requestJSON, "")
}

// RecordRunWithMessage projects a Run using a user message that was already
// appended by the conversation command. The optional ID is only accepted
// inside the same owner-scoped session; machine callers without it retain the
// deterministic run-derived message behavior.
// RecordRunWithMessage 在会话命令已追加用户消息时复用该消息；ID 只能在同一
// 所有者会话内使用，无 ID 的机器调用继续使用运行派生的确定性消息。
func (s *SQLStore) RecordRunWithMessage(ctx context.Context, runScope sharedkernel.Scope, requestJSON []byte, existingMessageID string) error {
	if strings.TrimSpace(runScope.SessionID) == "" {
		return nil
	}
	scope := Scope{TenantID: runScope.TenantID, DepartmentID: runScope.DepartmentID, ApplicationID: runScope.ApplicationID, PrincipalType: runScope.PrincipalType, PrincipalID: runScope.PrincipalID, TraceID: runScope.TraceID}
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("run conversation scope: %w", err)
	}
	var envelope struct {
		Input struct {
			Question       string `json:"question"`
			Query          string `json:"query"`
			BatchID        string `json:"batch_id"`
			IntentHint     string `json:"intent_hint"`
			KnowledgeScope string `json:"knowledge_scope"`
		} `json:"input"`
	}
	if len(requestJSON) > 0 {
		if err := json.Unmarshal(requestJSON, &envelope); err != nil {
			return fmt.Errorf("decode run conversation input: %w", err)
		}
	}
	kind := "qa"
	if strings.Contains(strings.ToLower(runScope.AgentID), "check") || envelope.Input.BatchID != "" {
		kind = "check"
	}
	title := strings.TrimSpace(envelope.Input.Question)
	if title == "" {
		title = strings.TrimSpace(envelope.Input.Query)
	}
	if title == "" && strings.TrimSpace(envelope.Input.BatchID) != "" {
		title = "校验批次 " + strings.TrimSpace(envelope.Input.BatchID)
	}
	if title == "" {
		title = "Agent Run " + runScope.RunID
	}
	existingSession, err := s.Detail(ctx, scope, runScope.SessionID)
	if errors.Is(err, ErrNotFound) {
		if err := s.CreateSession(ctx, scope, Session{Summary: Summary{ID: runScope.SessionID, Kind: kind, AgentID: runScope.AgentID, AgentVersionID: runScope.AgentVersionID, InstallationID: runScope.InstallationID, Title: truncate(title, 512), Status: "active", CanContinue: true}}); err != nil {
			return fmt.Errorf("create run conversation session: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("lookup run conversation session: %w", err)
	} else if err := validateRunSessionBinding(existingSession, runScope); err != nil {
		return err
	}
	content := title
	if existingMessageID = strings.TrimSpace(existingMessageID); existingMessageID != "" {
		var existing string
		where, args := ownedMessageWhere(scope, runScope.SessionID, existingMessageID)
		err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT m.content FROM platform_conversation_message m
			JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
			WHERE `+where), args...).Scan(&existing)
		if err == nil {
			if existing != content {
				return errors.New("conversation run message idempotency conflict")
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check existing run conversation message: %w", err)
		}
		return s.AppendMessage(ctx, scope, Message{ID: existingMessageID, SessionID: runScope.SessionID, Role: "user", Content: content, IntentCode: envelope.Input.IntentHint, KnowledgeScope: envelope.Input.KnowledgeScope})
	}
	messageID := conversationID("run-message", scope, runScope.RunID)
	var exists string
	where, args := ownedMessageWhere(scope, runScope.SessionID, messageID)
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT m.content FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE `+where), args...).Scan(&exists)
	if err == nil {
		if exists != content {
			return errors.New("conversation run message idempotency conflict")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check run conversation message: %w", err)
	}
	return s.AppendMessage(ctx, scope, Message{ID: messageID, SessionID: runScope.SessionID, Role: "user", Content: content, IntentCode: envelope.Input.IntentHint, KnowledgeScope: envelope.Input.KnowledgeScope})
}

// RecordRunResult projects the terminal Agent answer into the same scoped
// conversation. The deterministic run-derived message ID makes dispatcher
// retries and process restarts idempotent.
// RecordRunResult 将终态 Agent 答案投影到同一作用域会话；由 Run 派生的稳定消息
// ID 让重试和进程重启保持幂等。
func (s *SQLStore) RecordRunResult(ctx context.Context, runScope sharedkernel.Scope, runID string, output map[string]any) error {
	if strings.TrimSpace(runScope.SessionID) == "" || strings.TrimSpace(runID) == "" {
		return nil
	}
	scope := Scope{TenantID: runScope.TenantID, DepartmentID: runScope.DepartmentID, ApplicationID: runScope.ApplicationID, PrincipalType: runScope.PrincipalType, PrincipalID: runScope.PrincipalID, TraceID: runScope.TraceID}
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("result conversation scope: %w", err)
	}
	existingSession, err := s.Detail(ctx, scope, runScope.SessionID)
	if err != nil {
		return fmt.Errorf("result conversation session: %w", err)
	}
	if err := validateRunSessionBinding(existingSession, runScope); err != nil {
		return err
	}
	content, metadata, err := projectRunResult(output)
	if err != nil {
		return err
	}
	// Compare exactly the representation persisted by the first delivery.
	// 重放比较必须使用首次持久化的规范化正文，不能用未截断原文比较。
	content = truncate(content, 32768)
	messageID := conversationID("run-answer", scope, runID)
	var exists string
	where, args := ownedMessageWhere(scope, runScope.SessionID, messageID)
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT m.content FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE `+where), args...).Scan(&exists)
	if err == nil {
		if exists != content {
			return errors.New("conversation run result idempotency conflict")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check run conversation result: %w", err)
	}
	return s.AppendMessage(ctx, scope, Message{ID: messageID, SessionID: runScope.SessionID, Role: "assistant", Content: content, Metadata: metadata})
}

// A rejected review is an execution result, never a publishable answer. Do
// not fall back to serializing the full Agent output into conversation text.
// 审核拒绝属于执行结果，绝不是可发布答案；不能把整个Agent输出JSON回退为正文。
func projectRunResult(output map[string]any) (string, map[string]any, error) {
	approval, _ := output["approval_status"].(string)
	if approval == "rejected" {
		return "人工审核已拒绝，答案未发布。", map[string]any{
			"status": "rejected", "approval_status": "rejected",
		}, nil
	}
	if approval == "request_changes" || approval == "pending_review" {
		return "人工审核尚未批准，答案未发布。", map[string]any{
			"status": "waiting_review", "approval_status": approval,
		}, nil
	}
	metadata := make(map[string]any, len(output))
	for key, value := range output {
		metadata[key] = value
	}
	if value, ok := output["answer"].(string); ok && strings.TrimSpace(value) != "" {
		return value, metadata, nil
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return "", nil, fmt.Errorf("encode run conversation result: %w", err)
	}
	return string(encoded), metadata, nil
}

func (s *SQLStore) List(ctx context.Context, scope Scope, query Query) (Page, error) {
	query, err := (AccessPolicy{}).Normalize(scope, query)
	if err != nil {
		return Page{}, err
	}
	where := `tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND status <> 'deleted'`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType}
	if query.View == "mine" {
		where += ` AND owner_id=?`
		args = append(args, scope.PrincipalID)
	}
	if query.Kind != "" {
		where += ` AND kind=?`
		args = append(args, query.Kind)
	}
	if query.Text != "" {
		where += ` AND (title LIKE ? OR preview LIKE ?)`
		pattern := "%" + query.Text + "%"
		args = append(args, pattern, pattern)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_session WHERE `+where), args...).Scan(&total); err != nil {
		return Page{}, fmt.Errorf("count conversations: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,kind,agent_id,agent_version_id,installation_id,title,preview,owner_id,status,message_count,can_continue,updated_at FROM platform_conversation_session WHERE `+where+` ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?`), append(args, query.PageSize, (query.Page-1)*query.PageSize)...)
	if err != nil {
		return Page{}, fmt.Errorf("list conversations: %w", err)
	}
	defer rows.Close()
	items := make([]Summary, 0)
	for rows.Next() {
		var item Summary
		if err := rows.Scan(&item.ID, &item.Kind, &item.AgentID, &item.AgentVersionID, &item.InstallationID, &item.Title, &item.Preview, &item.OwnerID, &item.Status, &item.MessageCount, &item.CanContinue, &item.UpdatedAt); err != nil {
			return Page{}, fmt.Errorf("scan conversation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate conversations: %w", err)
	}
	return Page{Items: items, Total: total, Page: query.Page, Size: query.PageSize}, nil
}

// SearchManaged provides a privileged, bounded read across owners. Scope
// authorization is deliberately performed by Module before this port is
// called; this adapter only applies the already-authorized tenant/application
// filters and never accepts identity or role data from SQL query parameters.
// SearchManaged 提供跨会话所有者的特权有界读取。权限由 Module 在调用 Port 前完成；
// SQL Adapter 只应用已授权的租户/应用过滤条件，不从查询参数读取身份或角色。
func (s *SQLStore) SearchManaged(ctx context.Context, query ManagedSearchQuery) (Page, error) {
	query, err := normalizeManagedSearchQuery(query)
	if err != nil {
		return Page{}, err
	}
	where := `kind=? AND status <> 'deleted'`
	args := []any{query.Kind}
	if query.TenantID != "" {
		where += ` AND tenant_id=?`
		args = append(args, query.TenantID)
	}
	if query.ApplicationID != "" {
		where += ` AND application_id=?`
		args = append(args, query.ApplicationID)
	}
	if query.Text != "" {
		where += ` AND (title LIKE ? OR preview LIKE ?)`
		pattern := "%" + query.Text + "%"
		args = append(args, pattern, pattern)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_session WHERE `+where), args...).Scan(&total); err != nil {
		return Page{}, fmt.Errorf("count managed conversations: %w", err)
	}
	pageArgs := append(append([]any(nil), args...), query.PageSize, (query.Page-1)*query.PageSize)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,kind,agent_id,agent_version_id,installation_id,title,preview,owner_id,status,message_count,can_continue,updated_at
		FROM platform_conversation_session WHERE `+where+` ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?`), pageArgs...)
	if err != nil {
		return Page{}, fmt.Errorf("search managed conversations: %w", err)
	}
	defer rows.Close()
	items := make([]Summary, 0)
	for rows.Next() {
		var item Summary
		if err := rows.Scan(&item.ID, &item.Kind, &item.AgentID, &item.AgentVersionID, &item.InstallationID, &item.Title, &item.Preview, &item.OwnerID, &item.Status, &item.MessageCount, &item.CanContinue, &item.UpdatedAt); err != nil {
			return Page{}, fmt.Errorf("scan managed conversation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate managed conversations: %w", err)
	}
	return Page{Items: items, Total: total, Page: query.Page, Size: query.PageSize}, nil
}

func (s *SQLStore) ListChecks(ctx context.Context, scope Scope, query Query) (Page, error) {
	query.Kind = "check"
	return s.List(ctx, scope, query)
}

func (s *SQLStore) ListQA(ctx context.Context, scope Scope, query Query) (Page, error) {
	query.Kind = "qa"
	return s.List(ctx, scope, query)
}

func (s *SQLStore) Detail(ctx context.Context, scope Scope, id string) (Summary, error) {
	return conversationDetail(ctx, s.db, scope, id)
}

type conversationRowReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func conversationDetail(ctx context.Context, reader conversationRowReader, scope Scope, id string) (Summary, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(id) == "" {
		return Summary{}, ErrInvalidQuery
	}
	var item Summary
	err := reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,kind,agent_id,agent_version_id,installation_id,title,preview,owner_id,status,message_count,can_continue,updated_at FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=? AND status <> 'deleted'`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.historyOwner()).Scan(&item.ID, &item.Kind, &item.AgentID, &item.AgentVersionID, &item.InstallationID, &item.Title, &item.Preview, &item.OwnerID, &item.Status, &item.MessageCount, &item.CanContinue, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Summary{}, ErrNotFound
	}
	if err != nil {
		return Summary{}, fmt.Errorf("get conversation: %w", err)
	}
	return item, nil
}

func (s *SQLStore) Resume(ctx context.Context, scope Scope, id string) (Summary, error) {
	item, err := s.Detail(ctx, scope, id)
	if err != nil {
		return Summary{}, err
	}
	if !item.CanContinue {
		return Summary{}, ErrForbidden
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET status=?,revision=revision+1,updated_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=? AND status <> 'deleted' AND can_continue=TRUE`), "active", s.clock(), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID)
	if err != nil {
		return Summary{}, fmt.Errorf("resume conversation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Summary{}, fmt.Errorf("confirm conversation resume: %w", err)
	}
	if affected != 1 {
		return Summary{}, ErrNotFound
	}
	item.Status = "active"
	return item, nil
}

func (s *SQLStore) ListMessages(ctx context.Context, scope Scope, sessionID string, page, size int) ([]Message, int64, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(sessionID) == "" {
		return nil, 0, ErrInvalidQuery
	}
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	// Detail is the canonical owner check. Keep the same predicate on the
	// message queries below so a guessed session ID cannot expose another
	// user's messages even when the caller skips the detail endpoint.
	if _, err := s.Detail(ctx, scope, sessionID); err != nil {
		return nil, 0, err
	}
	var total int64
	where, args := ownedMessageWhere(scope, sessionID, "")
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE `+where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count conversation messages: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT m.id,m.session_id,m.role,m.content,m.intent_code,m.knowledge_scope,m.metadata_json,m.created_at FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE `+where+` ORDER BY m.created_at ASC,m.id ASC LIMIT ? OFFSET ?`), append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list conversation messages: %w", err)
	}
	defer rows.Close()
	items := make([]Message, 0)
	for rows.Next() {
		var item Message
		var metadataJSON string
		if err := rows.Scan(&item.ID, &item.SessionID, &item.Role, &item.Content, &item.IntentCode, &item.KnowledgeScope, &metadataJSON, &item.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan conversation message: %w", err)
		}
		if strings.TrimSpace(metadataJSON) != "" && metadataJSON != "{}" {
			if err := json.Unmarshal([]byte(metadataJSON), &item.Metadata); err != nil {
				return nil, 0, fmt.Errorf("decode conversation message metadata: %w", err)
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate conversation messages: %w", err)
	}
	return items, total, nil
}

// ListRevisions returns only revisions belonging to the authenticated scope.
// ListRevisions 只返回当前可信作用域下的消息修订，禁止仅凭 ID 跨主体读取。
func (s *SQLStore) ListRevisions(ctx context.Context, scope Scope, sessionID, messageID string) ([]Revision, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(messageID) == "" {
		return nil, ErrInvalidQuery
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT r.id,r.session_id,r.message_id,r.role,r.content,r.reason,r.revision_no,r.is_current,r.created_at
		FROM platform_conversation_revision r JOIN platform_conversation_session s ON s.id=r.session_id AND s.tenant_id=r.tenant_id AND s.department_id=r.department_id AND s.application_id=r.application_id AND s.principal_type=r.principal_type AND s.owner_id=r.owner_id
		WHERE r.session_id=? AND r.message_id=? AND r.tenant_id=? AND r.department_id=? AND r.application_id=? AND r.principal_type=? AND r.owner_id=? AND s.status <> 'deleted' ORDER BY r.revision_no ASC`), sessionID, messageID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.historyOwner())
	if err != nil {
		return nil, fmt.Errorf("list conversation revisions: %w", err)
	}
	defer rows.Close()
	items := make([]Revision, 0)
	for rows.Next() {
		var item Revision
		if err := rows.Scan(&item.ID, &item.SessionID, &item.MessageID, &item.Role, &item.Content, &item.Reason, &item.RevisionNo, &item.IsCurrent, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan conversation revision: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate conversation revisions: %w", err)
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	return items, nil
}

// ReviseMessage appends an immutable revision and updates the current message
// in one transaction. The base revision is a CAS guard for concurrent edits.
// ReviseMessage 在一个事务中追加不可变修订并更新当前消息；baseRevision
// 作为并发编辑的 CAS 防线。
func (s *SQLStore) ReviseMessage(ctx context.Context, scope Scope, sessionID, messageID, content, reason string, baseRevision uint64) (Revision, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(messageID) == "" || strings.TrimSpace(content) == "" || len([]rune(content)) > 100000 {
		return Revision{}, ErrInvalidQuery
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Revision{}, fmt.Errorf("begin conversation revision: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var role, oldContent string
	// The message/session row lock serializes revisions; PostgreSQL disallows aggregate row locking.
	var currentRevision uint64
	where, args := ownedMessageWhere(scope, sessionID, messageID)
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT m.role,m.content FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE `+where+` FOR UPDATE`), args...).Scan(&role, &oldContent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Revision{}, ErrNotFound
		}
		return Revision{}, fmt.Errorf("lock conversation message: %w", err)
	}
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COALESCE(MAX(revision_no),0) FROM platform_conversation_revision WHERE session_id=? AND message_id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=?`), sessionID, messageID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID).Scan(&currentRevision); err != nil {
		return Revision{}, fmt.Errorf("read conversation revision: %w", err)
	}
	if currentRevision == 0 {
		// The first edit is revision 1 and the caller's base revision may be 0
		// when editing an unedited message.
		if baseRevision != 0 {
			return Revision{}, ErrRevisionConflict
		}
	} else if baseRevision != currentRevision {
		return Revision{}, ErrRevisionConflict
	}
	now := s.clock()
	no := currentRevision + 1
	id := conversationID("revision", scope, sessionID, messageID, fmt.Sprint(no))
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_revision SET is_current=FALSE WHERE session_id=? AND message_id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=?`), sessionID, messageID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID); err != nil {
		return Revision{}, fmt.Errorf("close conversation revision: %w", err)
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_revision(id,session_id,message_id,tenant_id,department_id,application_id,principal_type,owner_id,role,content,reason,revision_no,is_current,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), id, sessionID, messageID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID, role, content, strings.TrimSpace(reason), no, true, now); err != nil {
		return Revision{}, fmt.Errorf("insert conversation revision: %w", err)
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_message SET content=? WHERE id=? AND session_id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=?`), content, messageID, sessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType); err != nil {
		return Revision{}, fmt.Errorf("update conversation message: %w", err)
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET preview=?,updated_at=?,revision=revision+1 WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=?`), truncate(content, 2048), now, sessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID); err != nil {
		return Revision{}, fmt.Errorf("update conversation session after revision: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return Revision{}, fmt.Errorf("commit conversation revision: %w", err)
	}
	_ = oldContent // retained for clear intent: the immutable row preserves it.
	return Revision{ID: id, SessionID: sessionID, MessageID: messageID, Role: role, Content: content, Reason: strings.TrimSpace(reason), RevisionNo: no, IsCurrent: true, CreatedAt: now}, nil
}

// Regenerate records a durable, idempotent replay request and creates a
// separate session branch.  The actual Agent execution is dispatched by the
// platform runtime; this command never mutates the original answer.
// Regenerate 记录可持久化且幂等的重执行请求，并创建独立会话分支；真正执行由
// 平台 Runtime 调度，本命令绝不修改原答案。
func (s *SQLStore) Regenerate(ctx context.Context, scope Scope, sessionID, messageID, versionMode string) (Regeneration, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(sessionID) == "" || strings.TrimSpace(messageID) == "" {
		return Regeneration{}, ErrInvalidQuery
	}
	versionMode = strings.TrimSpace(versionMode)
	if versionMode == "" {
		versionMode = "original_snapshot"
	}
	if versionMode != "original_snapshot" && versionMode != "current_release" {
		return Regeneration{}, ErrInvalidQuery
	}
	base, err := s.Detail(ctx, scope, sessionID)
	if err != nil {
		return Regeneration{}, err
	}
	lookup := `SELECT id,session_id,message_id,branch_session_id,version_mode,status FROM platform_conversation_regeneration WHERE session_id=? AND message_id=? AND version_mode=? AND tenant_id=? AND department_id=? AND application_id=? AND principal_type=? AND owner_id=?`
	var existing Regeneration
	lookupErr := s.db.QueryRowContext(ctx, sqlutil.Bind(lookup), sessionID, messageID, versionMode, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID).Scan(&existing.ID, &existing.SessionID, &existing.MessageID, &existing.BranchSessionID, &existing.VersionMode, &existing.Status)
	if lookupErr == nil {
		return existing, nil
	}
	if !errors.Is(lookupErr, sql.ErrNoRows) {
		return Regeneration{}, fmt.Errorf("lookup regeneration: %w", lookupErr)
	}
	var messageExists int
	where, args := ownedMessageWhere(scope, sessionID, messageID)
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE `+where), args...).Scan(&messageExists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Regeneration{}, ErrNotFound
		}
		return Regeneration{}, fmt.Errorf("check regeneration message: %w", err)
	}
	now := s.clock()
	item := Regeneration{
		ID:        conversationID("regenerate", scope, sessionID, messageID, versionMode),
		SessionID: sessionID, MessageID: messageID,
		BranchSessionID: conversationID("regeneration-branch", scope, sessionID, messageID, versionMode),
		VersionMode:     versionMode, Status: "queued",
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Regeneration{}, fmt.Errorf("begin regeneration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_regeneration(id,session_id,message_id,branch_session_id,tenant_id,department_id,application_id,principal_type,owner_id,version_mode,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`), item.ID, item.SessionID, item.MessageID, item.BranchSessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID, item.VersionMode, item.Status, now); err != nil {
		// A concurrent identical request is a successful idempotent replay.  The
		// caller receives the durable row rather than an internal duplicate key.
		if !sqlutil.IsUniqueViolation(err) {
			return Regeneration{}, fmt.Errorf("create regeneration: %w", err)
		}
		// End the failed PostgreSQL transaction before reading the committed winner.
		_ = tx.Rollback()
		var existing Regeneration
		if scanErr := s.db.QueryRowContext(ctx, sqlutil.Bind(lookup), sessionID, messageID, versionMode, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID).Scan(&existing.ID, &existing.SessionID, &existing.MessageID, &existing.BranchSessionID, &existing.VersionMode, &existing.Status); scanErr == nil {
			return existing, nil
		}
		return Regeneration{}, fmt.Errorf("create regeneration: %w", err)
	}
	branchNow := now
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_session(id,tenant_id,department_id,application_id,principal_type,owner_id,kind,agent_id,agent_version_id,installation_id,title,preview,status,message_count,can_continue,revision,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), item.BranchSessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID, base.Kind, base.AgentID, base.AgentVersionID, base.InstallationID, truncate("Regeneration: "+base.Title, 512), base.Preview, "queued", 0, true, 1, branchNow, branchNow); err != nil {
		return Regeneration{}, fmt.Errorf("create regeneration branch: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return Regeneration{}, fmt.Errorf("commit regeneration: %w", err)
	}
	return item, nil
}

func (s *SQLStore) CreateShare(ctx context.Context, scope Scope, request ShareRequest) (Share, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(request.SessionID) == "" {
		return Share{}, ErrInvalidQuery
	}
	if _, err := s.Detail(ctx, scope, request.SessionID); err != nil {
		return Share{}, err
	}
	if request.TTLSeconds <= 0 {
		request.TTLSeconds = 24 * 60 * 60
	}
	if request.TTLSeconds > 7*24*60*60 {
		return Share{}, ErrInvalidQuery
	}
	id, err := randomShareToken(18)
	if err != nil {
		return Share{}, fmt.Errorf("generate conversation share id: %w", err)
	}
	token, err := randomShareToken(32)
	if err != nil {
		return Share{}, fmt.Errorf("generate conversation share token: %w", err)
	}
	now := s.clock()
	tokenHash := sha256.Sum256([]byte(token))
	share := Share{ID: "share_" + id, Token: token, SessionID: request.SessionID, OwnerID: scope.PrincipalID, Status: "active", ExpiresAt: now.Add(time.Duration(request.TTLSeconds) * time.Second), IncludeRefs: request.IncludeRefs, CreatedAt: now}
	_, err = s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_share(id,session_id,tenant_id,department_id,application_id,principal_type,owner_id,token_hash,status,expires_at,include_refs,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`), share.ID, share.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, share.OwnerID, hex.EncodeToString(tokenHash[:]), share.Status, share.ExpiresAt, share.IncludeRefs, share.CreatedAt)
	if err != nil {
		return Share{}, fmt.Errorf("create conversation share: %w", err)
	}
	return share, nil
}

// ReadPublicShare resolves a capability URL while enforcing its revocation and
// expiry atomically in the lookup predicate. The caller receives only a
// read-only message projection; continuation and owner identifiers are never
// returned.
// ReadPublicShare 在查询条件中同时校验能力令牌的撤销和过期状态，只返回只读
// 消息投影，不返回继续执行能力或所有者标识。
func (s *SQLStore) ReadPublicShare(ctx context.Context, token string, page, pageSize int) (SharedConversation, error) {
	if !validShareToken(token) {
		return SharedConversation{}, ErrNotFound
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 100
	}
	if pageSize > 100 {
		pageSize = 100
	}
	hash := sha256.Sum256([]byte(token))
	var share Share
	var scope Scope
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,tenant_id,department_id,application_id,principal_type,owner_id,status,expires_at,include_refs,created_at FROM platform_conversation_share WHERE token_hash=? AND status='active' AND expires_at>?`), hex.EncodeToString(hash[:]), s.clock()).Scan(&share.ID, &share.SessionID, &scope.TenantID, &scope.DepartmentID, &scope.ApplicationID, &scope.PrincipalType, &share.OwnerID, &share.Status, &share.ExpiresAt, &share.IncludeRefs, &share.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedConversation{}, ErrNotFound
	}
	if err != nil {
		return SharedConversation{}, fmt.Errorf("resolve public conversation share: %w", err)
	}
	scope.PrincipalID = share.OwnerID
	if s.publicShareAccess != nil {
		resource, err := s.GetSessionResource(ctx, scope, share.SessionID)
		if err != nil {
			return SharedConversation{}, err
		}
		if err := s.publicShareAccess.Authorize(ctx, scope, resource, "history.share"); err != nil {
			return SharedConversation{}, ErrNotFound
		}
	}
	summary, err := s.Detail(ctx, scope, share.SessionID)
	if err != nil {
		return SharedConversation{}, err
	}
	messages, total, err := s.ListMessages(ctx, scope, share.SessionID, page, pageSize)
	if err != nil {
		return SharedConversation{}, err
	}
	shared := SharedConversation{SessionID: summary.ID, Kind: summary.Kind, Title: summary.Title, ExpiresAt: share.ExpiresAt, TotalMessages: total, Page: page, PageSize: pageSize, IncludeReferences: share.IncludeRefs, Messages: make([]SharedMessage, 0, len(messages))}
	for _, item := range messages {
		message := SharedMessage{Role: item.Role, Content: item.Content, CreatedAt: item.CreatedAt}
		if share.IncludeRefs {
			message.References = referencesFromMetadata(item.Metadata)
		}
		shared.Messages = append(shared.Messages, message)
	}
	return shared, nil
}

func randomShareToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validShareToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32
}

func referencesFromMetadata(metadata map[string]any) []any {
	if len(metadata) == 0 {
		return nil
	}
	refs, ok := metadata["references"].([]any)
	if !ok {
		return nil
	}
	return refs
}

func (s *SQLStore) RevokeShare(ctx context.Context, scope Scope, id string) (Share, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(id) == "" {
		return Share{}, ErrInvalidQuery
	}
	share, err := s.getShare(ctx, scope, id, false)
	if err != nil {
		return Share{}, err
	}
	if share.Status == "revoked" {
		return share, nil
	}
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_share SET status='revoked' WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND owner_id=?`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalID); err != nil {
		return Share{}, fmt.Errorf("revoke conversation share: %w", err)
	}
	share.Status = "revoked"
	return share, nil
}

func (s *SQLStore) getShare(ctx context.Context, scope Scope, id string, allowService bool) (Share, error) {
	if allowService && scope.PrincipalType != "service_principal" {
		return Share{}, ErrForbidden
	}
	where := `id=? AND tenant_id=? AND department_id=? AND application_id=?`
	args := []any{id, scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	if !allowService {
		where += ` AND owner_id=?`
		args = append(args, scope.PrincipalID)
	}
	var share Share
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,owner_id,status,expires_at,include_refs,created_at FROM platform_conversation_share WHERE `+where), args...).Scan(&share.ID, &share.SessionID, &share.OwnerID, &share.Status, &share.ExpiresAt, &share.IncludeRefs, &share.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrNotFound
	}
	if err != nil {
		return Share{}, fmt.Errorf("get conversation share: %w", err)
	}
	return share, nil
}

func (s *SQLStore) CreateExport(ctx context.Context, scope Scope, request ExportRequest) (Export, error) {
	if err := scope.Validate(); err != nil || len(request.SessionIDs) != 1 || strings.TrimSpace(request.SessionIDs[0]) == "" {
		return Export{}, ErrInvalidQuery
	}
	sessionID := strings.TrimSpace(request.SessionIDs[0])
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return Export{}, fmt.Errorf("begin conversation export: %w", err)
	}
	defer tx.Rollback()
	summary, err := conversationDetail(ctx, tx, scope, sessionID)
	if err != nil {
		return Export{}, err
	}
	payload, err := conversationExportSnapshot(ctx, tx, scope, sessionID, summary)
	if err != nil {
		return Export{}, fmt.Errorf("encode conversation export: %w", err)
	}
	now := s.clock()
	export := Export{ID: conversationID("export", scope, sessionID, now.String()), SessionID: sessionID, OwnerID: scope.PrincipalID, Status: "pending", PayloadJSON: string(payload), CreatedAt: now}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_export(id,session_id,tenant_id,department_id,application_id,principal_type,owner_id,status,payload_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`), export.ID, export.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, export.OwnerID, export.Status, export.PayloadJSON, export.CreatedAt); err != nil {
		return Export{}, fmt.Errorf("create conversation export: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Export{}, fmt.Errorf("commit conversation export: %w", err)
	}
	return export, nil
}

func (s *SQLStore) GetExport(ctx context.Context, scope Scope, id string) (Export, error) {
	if err := scope.Validate(); err != nil || strings.TrimSpace(id) == "" {
		return Export{}, ErrInvalidQuery
	}
	allowService := scope.PrincipalType == "service_principal"
	where := `id=? AND tenant_id=? AND department_id=? AND application_id=?`
	args := []any{id, scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	if !allowService {
		where += ` AND owner_id=?`
		args = append(args, scope.PrincipalID)
	}
	var export Export
	var approvedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,owner_id,status,payload_json,created_at,approved_at FROM platform_conversation_export WHERE `+where+` AND EXISTS (SELECT 1 FROM platform_conversation_session s WHERE s.id=platform_conversation_export.session_id AND s.tenant_id=platform_conversation_export.tenant_id AND s.department_id=platform_conversation_export.department_id AND s.application_id=platform_conversation_export.application_id AND s.principal_type=platform_conversation_export.principal_type AND s.owner_id=platform_conversation_export.owner_id AND s.status <> 'deleted')`), args...).Scan(&export.ID, &export.SessionID, &export.OwnerID, &export.Status, &export.PayloadJSON, &export.CreatedAt, &approvedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Export{}, ErrNotFound
	}
	if err != nil {
		return Export{}, fmt.Errorf("get conversation export: %w", err)
	}
	if approvedAt.Valid {
		export.ApprovedAt = approvedAt.Time
	}
	return export, nil
}

func (s *SQLStore) ApproveExport(ctx context.Context, scope Scope, id string) (Export, error) {
	if scope.PrincipalType != "service_principal" {
		return Export{}, ErrForbidden
	}
	export, err := s.GetExport(ctx, scope, id)
	if err != nil {
		return Export{}, err
	}
	if export.Status != "pending" {
		return export, ErrForbidden
	}
	now := s.clock()
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_export SET status='approved',approved_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND status='pending'`), now, id, scope.TenantID, scope.DepartmentID, scope.ApplicationID); err != nil {
		return Export{}, fmt.Errorf("approve conversation export: %w", err)
	}
	export.Status, export.ApprovedAt = "approved", now
	return export, nil
}

func (s *SQLStore) RequestDeletion(ctx context.Context, scope Scope, request DeleteRequest) (DeletionRequest, error) {
	if err := scope.Validate(); err != nil || len(request.SessionIDs) != 1 || strings.TrimSpace(request.SessionIDs[0]) == "" || strings.TrimSpace(request.Reason) == "" {
		return DeletionRequest{}, ErrInvalidQuery
	}
	if _, err := s.Detail(ctx, scope, request.SessionIDs[0]); err != nil {
		return DeletionRequest{}, err
	}
	now := s.clock()
	item := DeletionRequest{ID: conversationID("delete", scope, request.SessionIDs[0], now.String()), SessionID: request.SessionIDs[0], OwnerID: scope.PrincipalID, Reason: truncate(request.Reason, 512), Status: "pending", RequestedAt: now}
	if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_deletion(id,session_id,tenant_id,department_id,application_id,principal_type,owner_id,reason,status,requested_at) VALUES (?,?,?,?,?,?,?,?,?,?)`), item.ID, item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, item.OwnerID, item.Reason, item.Status, item.RequestedAt); err != nil {
		return DeletionRequest{}, fmt.Errorf("request conversation deletion: %w", err)
	}
	return item, nil
}

func (s *SQLStore) ListDeletionRequests(ctx context.Context, scope Scope, page, size int) ([]DeletionRequest, int64, error) {
	return s.listDeletionRequests(ctx, scope, page, size, scope.PrincipalType == "service_principal")
}

// ListDeletionRequestsForManagement is called after the Conversation Module
// has resolved the user as an active scoped administrator through Identity.
// ListDeletionRequestsForManagement 仅能在 Conversation Module 通过 Identity
// 确认用户为有效作用域管理员后调用。
func (s *SQLStore) ListDeletionRequestsForManagement(ctx context.Context, scope Scope, page, size int) ([]DeletionRequest, int64, error) {
	if scope.PrincipalType != "user" {
		return nil, 0, ErrForbidden
	}
	return s.listDeletionRequests(ctx, scope, page, size, true)
}

func (s *SQLStore) listDeletionRequests(ctx context.Context, scope Scope, page, size int, managed bool) ([]DeletionRequest, int64, error) {
	if err := scope.Validate(); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	where := `tenant_id=? AND department_id=? AND application_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	if !managed {
		where += ` AND owner_id=?`
		args = append(args, scope.PrincipalID)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_deletion WHERE `+where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count deletion requests: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,session_id,owner_id,reason,status,requested_at,approved_at FROM platform_conversation_deletion WHERE `+where+` ORDER BY requested_at DESC,id DESC LIMIT ? OFFSET ?`), append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list deletion requests: %w", err)
	}
	defer rows.Close()
	items := make([]DeletionRequest, 0)
	for rows.Next() {
		var item DeletionRequest
		var approvedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.SessionID, &item.OwnerID, &item.Reason, &item.Status, &item.RequestedAt, &approvedAt); err != nil {
			return nil, 0, fmt.Errorf("scan deletion request: %w", err)
		}
		if approvedAt.Valid {
			item.ApprovedAt = approvedAt.Time
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate deletion requests: %w", err)
	}
	return items, total, nil
}

func (s *SQLStore) ApproveDeletion(ctx context.Context, scope Scope, id string) (DeletionRequest, error) {
	if scope.PrincipalType != "service_principal" || strings.TrimSpace(id) == "" {
		return DeletionRequest{}, ErrForbidden
	}
	return s.approveDeletion(ctx, scope, id)
}

// ApproveDeletionByUser is called only after the Conversation Module has
// resolved the active, scoped administrator from the Identity source of truth.
// ApproveDeletionByUser 仅能在 Conversation Module 从 Identity 权威源确认该用户
// 是有效且作用域匹配的管理员后调用。
func (s *SQLStore) ApproveDeletionByUser(ctx context.Context, scope Scope, id string) (DeletionRequest, error) {
	if scope.PrincipalType != "user" || strings.TrimSpace(id) == "" {
		return DeletionRequest{}, ErrForbidden
	}
	return s.approveDeletion(ctx, scope, id)
}

func (s *SQLStore) approveDeletion(ctx context.Context, scope Scope, id string) (DeletionRequest, error) {
	return s.approveDeletionWithCheck(ctx, scope, id, nil)
}

func (s *SQLStore) approveDeletionWithCheck(ctx context.Context, scope Scope, id string, check func(context.Context, SessionResource) error) (DeletionRequest, error) {
	if check != nil && s.deletionRecorder == nil {
		return DeletionRequest{}, ErrDeletionRecorderUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeletionRequest{}, fmt.Errorf("begin deletion approval: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if check != nil {
		if s.deletionGuard == nil {
			return DeletionRequest{}, ErrForbidden
		}
		if err := s.deletionGuard(ctx, tx); err != nil {
			return DeletionRequest{}, err
		}
	}
	var item DeletionRequest
	var approvedAt sql.NullTime
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,owner_id,reason,status,requested_at,approved_at FROM platform_conversation_deletion WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&item.ID, &item.SessionID, &item.OwnerID, &item.Reason, &item.Status, &item.RequestedAt, &approvedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeletionRequest{}, ErrNotFound
	}
	if err != nil {
		return DeletionRequest{}, fmt.Errorf("lock deletion request: %w", err)
	}
	if approvedAt.Valid {
		item.ApprovedAt = approvedAt.Time
	}
	if item.OwnerID == scope.PrincipalID {
		return DeletionRequest{}, ErrForbidden
	}
	if item.Status == "approved" && check != nil {
		return s.replayDeletionApproval(ctx, tx, scope, item, check)
	}
	if item.Status != "pending" {
		return DeletionRequest{}, ErrForbidden
	}
	var sessionStatus string
	var lastActivity time.Time
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,updated_at FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND owner_id=? FOR UPDATE`), item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, item.OwnerID).Scan(&sessionStatus, &lastActivity)
	if errors.Is(err, sql.ErrNoRows) || sessionStatus == "deleted" {
		return DeletionRequest{}, ErrNotFound
	}
	if err != nil {
		return DeletionRequest{}, fmt.Errorf("lock conversation for deletion approval: %w", err)
	}
	var held int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_legal_hold WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=? AND status='active'`), item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&held); err != nil {
		return DeletionRequest{}, fmt.Errorf("check conversation legal hold: %w", err)
	}
	if held > 0 {
		return DeletionRequest{}, ErrLegalHold
	}
	var resource SessionResource
	if check != nil {
		err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,owner_id,principal_type,installation_id,agent_id,agent_version_id FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=?`), item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&resource.ID, &resource.OwnerID, &resource.PrincipalType, &resource.InstallationID, &resource.AgentID, &resource.AgentVersionID)
		if err != nil {
			return DeletionRequest{}, err
		}
		if err := check(ctx, resource); err != nil {
			return DeletionRequest{}, err
		}
	}
	// Return exactly the precision persisted by TIMESTAMPTZ(6), including retries.
	now := s.clock().UTC().Truncate(time.Microsecond)
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_deletion SET status='approved',approved_at=? WHERE id=?`), now, id); err != nil {
		return DeletionRequest{}, fmt.Errorf("approve deletion request: %w", err)
	}
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET status='deleted',can_continue=false,revision=revision+1,updated_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND owner_id=? AND status <> 'deleted'`), now, item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, item.OwnerID)
	if err != nil {
		return DeletionRequest{}, fmt.Errorf("delete conversation session: %w", err)
	}
	affected, err := updated.RowsAffected()
	if err != nil {
		return DeletionRequest{}, fmt.Errorf("confirm conversation deletion: %w", err)
	}
	if affected != 1 {
		return DeletionRequest{}, ErrNotFound
	}
	item.Status, item.ApprovedAt = "approved", now
	if s.deletionRecorder != nil {
		if err := s.deletionRecorder(ctx, tx, scope, item); err != nil {
			return DeletionRequest{}, err
		}
	}
	if check != nil {
		if err := s.enqueueErasure(ctx, tx, scope, item, lastActivity); err != nil {
			return DeletionRequest{}, err
		}
		if err := check(ctx, resource); err != nil {
			return DeletionRequest{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return DeletionRequest{}, fmt.Errorf("commit deletion approval: %w", err)
	}
	return item, nil
}

// GetRetentionPolicy returns the scope-local policy.  Governance operations
// are service-principal only; ordinary users can neither discover nor change
// cleanup windows. / GetRetentionPolicy 只允许服务身份访问，普通用户不能窥探或
// 修改清理窗口。
func (s *SQLStore) GetRetentionPolicy(ctx context.Context, scope Scope, kind string) (RetentionPolicy, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return RetentionPolicy{}, err
	}
	kind = strings.TrimSpace(kind)
	if kind != "qa" && kind != "check" {
		return RetentionPolicy{}, ErrRetentionPolicy
	}
	var item RetentionPolicy
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,kind,retention_days,enabled,revision,updated_by,updated_at FROM platform_conversation_retention_policy WHERE tenant_id=? AND department_id=? AND application_id=? AND kind=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind).Scan(&item.ID, &item.Kind, &item.RetentionDays, &item.Enabled, &item.Revision, &item.UpdatedBy, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RetentionPolicy{}, ErrNotFound
	}
	if err != nil {
		return RetentionPolicy{}, fmt.Errorf("get conversation retention policy: %w", err)
	}
	return item, nil
}

func (s *SQLStore) PutRetentionPolicy(ctx context.Context, scope Scope, policy RetentionPolicy) (RetentionPolicy, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return RetentionPolicy{}, err
	}
	policy.Kind = strings.TrimSpace(policy.Kind)
	if (policy.Kind != "qa" && policy.Kind != "check") || policy.RetentionDays < 1 || policy.RetentionDays > 36500 {
		return RetentionPolicy{}, ErrRetentionPolicy
	}
	if policy.ID == "" {
		policy.ID = conversationID("retention", scope, policy.Kind)
	}
	now := s.clock()
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_retention_policy(id,tenant_id,department_id,application_id,kind,retention_days,enabled,revision,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (tenant_id,department_id,application_id,kind) DO UPDATE SET retention_days=EXCLUDED.retention_days,enabled=EXCLUDED.enabled,revision=platform_conversation_retention_policy.revision+1,updated_by=EXCLUDED.updated_by,updated_at=EXCLUDED.updated_at`), policy.ID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, policy.Kind, policy.RetentionDays, policy.Enabled, 1, scope.PrincipalID, now)
	if err != nil {
		return RetentionPolicy{}, fmt.Errorf("put conversation retention policy: %w", err)
	}
	return s.GetRetentionPolicy(ctx, scope, policy.Kind)
}

func (s *SQLStore) PlaceLegalHold(ctx context.Context, scope Scope, request LegalHoldRequest) (LegalHold, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return LegalHold{}, err
	}
	request.SessionID = strings.TrimSpace(request.SessionID)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.SessionID == "" || request.Reason == "" || len([]rune(request.Reason)) > 512 {
		return LegalHold{}, ErrInvalidQuery
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LegalHold{}, fmt.Errorf("begin conversation legal hold: %w", err)
	}
	defer tx.Rollback()
	var status string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), request.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return LegalHold{}, ErrNotFound
		}
		return LegalHold{}, fmt.Errorf("lock governed conversation: %w", err)
	}
	if status == "deleted" {
		var pending int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_erasure e JOIN platform_conversation_deletion d ON d.id=e.request_id AND d.tenant_id=e.tenant_id AND d.department_id=e.department_id AND d.application_id=e.application_id WHERE d.session_id=? AND e.tenant_id=? AND e.department_id=? AND e.application_id=? AND e.status <> 'completed'`), request.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&pending); err != nil {
			return LegalHold{}, err
		}
		if pending == 0 {
			return LegalHold{}, ErrNotFound
		}
	}
	var existing LegalHold
	var releasedAt sql.NullTime
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,reason,status,placed_by,released_by,created_at,released_at FROM platform_conversation_legal_hold WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=? AND status='active' ORDER BY created_at DESC LIMIT 1`), request.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&existing.ID, &existing.SessionID, &existing.Reason, &existing.Status, &existing.PlacedBy, &existing.ReleasedBy, &existing.CreatedAt, &releasedAt)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return LegalHold{}, fmt.Errorf("confirm conversation legal hold: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return LegalHold{}, fmt.Errorf("lookup conversation legal hold: %w", err)
	}
	now := s.clock()
	item := LegalHold{ID: conversationID("hold", scope, request.SessionID, now.String()), SessionID: request.SessionID, Reason: request.Reason, Status: "active", PlacedBy: scope.PrincipalID, CreatedAt: now}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_legal_hold(id,session_id,tenant_id,department_id,application_id,reason,status,placed_by,released_by,created_at,released_at) VALUES (?,?,?,?,?,?,?,?,?,?,NULL)`), item.ID, item.SessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, item.Reason, item.Status, item.PlacedBy, "", item.CreatedAt)
	if err != nil {
		return LegalHold{}, fmt.Errorf("place conversation legal hold: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return LegalHold{}, fmt.Errorf("commit conversation legal hold: %w", err)
	}
	return item, nil
}

func (s *SQLStore) ListLegalHolds(ctx context.Context, scope Scope, page, size int) ([]LegalHold, int64, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return nil, 0, err
	}
	page, size = normalizeMessagePage(page, size)
	where := `tenant_id=? AND department_id=? AND application_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_legal_hold WHERE `+where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count conversation legal holds: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT id,session_id,reason,status,placed_by,released_by,created_at,released_at FROM platform_conversation_legal_hold WHERE `+where+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`), append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list conversation legal holds: %w", err)
	}
	defer rows.Close()
	items := make([]LegalHold, 0)
	for rows.Next() {
		var item LegalHold
		var releasedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.SessionID, &item.Reason, &item.Status, &item.PlacedBy, &item.ReleasedBy, &item.CreatedAt, &releasedAt); err != nil {
			return nil, 0, fmt.Errorf("scan conversation legal hold: %w", err)
		}
		if releasedAt.Valid {
			item.ReleasedAt = &releasedAt.Time
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate conversation legal holds: %w", err)
	}
	return items, total, nil
}

func (s *SQLStore) ReleaseLegalHold(ctx context.Context, scope Scope, id string) (LegalHold, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return LegalHold{}, err
	}
	if strings.TrimSpace(id) == "" {
		return LegalHold{}, ErrInvalidQuery
	}
	var item LegalHold
	var releasedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,reason,status,placed_by,released_by,created_at,released_at FROM platform_conversation_legal_hold WHERE id=? AND tenant_id=? AND department_id=? AND application_id=?`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&item.ID, &item.SessionID, &item.Reason, &item.Status, &item.PlacedBy, &item.ReleasedBy, &item.CreatedAt, &releasedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LegalHold{}, ErrNotFound
	}
	if err != nil {
		return LegalHold{}, fmt.Errorf("get conversation legal hold: %w", err)
	}
	if releasedAt.Valid {
		item.ReleasedAt = &releasedAt.Time
	}
	if item.Status == "released" {
		return item, nil
	}
	now := s.clock()
	if _, err = s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_legal_hold SET status='released',released_by=?,released_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND status='active'`), scope.PrincipalID, now, id, scope.TenantID, scope.DepartmentID, scope.ApplicationID); err != nil {
		return LegalHold{}, fmt.Errorf("release conversation legal hold: %w", err)
	}
	item.Status, item.ReleasedBy, item.ReleasedAt = "released", scope.PrincipalID, &now
	return item, nil
}

// SweepExpired performs a bounded, soft-delete sweep.  It is fail-closed on
// hold checks: a held session is never marked deleted. / SweepExpired 只做有界
// 软删除；保全检查失败或存在保全时均不删除。
func (s *SQLStore) SweepExpired(ctx context.Context, scope Scope, before time.Time, limit int) (RetentionSweep, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return RetentionSweep{}, err
	}
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT s.id,s.updated_at,p.retention_days FROM platform_conversation_session s JOIN platform_conversation_retention_policy p ON p.tenant_id=s.tenant_id AND p.department_id=s.department_id AND p.application_id=s.application_id AND p.kind=s.kind AND p.enabled=TRUE WHERE s.tenant_id=? AND s.department_id=? AND s.application_id=? AND s.status <> 'deleted' AND s.updated_at<=(?::timestamptz - p.retention_days * INTERVAL '1 day') ORDER BY s.updated_at ASC,s.id ASC LIMIT ?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, before, limit)
	if err != nil {
		return RetentionSweep{}, fmt.Errorf("list expired conversations: %w", err)
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		var updatedAt time.Time
		var retentionDays int
		if err := rows.Scan(&id, &updatedAt, &retentionDays); err != nil {
			return RetentionSweep{}, fmt.Errorf("scan expired conversation: %w", err)
		}
		if updatedAt.After(before.Add(-time.Duration(retentionDays) * 24 * time.Hour)) {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return RetentionSweep{}, fmt.Errorf("iterate expired conversations: %w", err)
	}
	result := RetentionSweep{Scanned: len(ids)}
	for _, id := range ids {
		held, disposed, err := s.sweepExpiredSession(ctx, scope, id, before)
		if err != nil {
			return RetentionSweep{}, err
		}
		if held {
			result.Held++
		}
		if disposed {
			result.Disposed++
		}
	}
	return result, nil
}

// Both the sweeper and PlaceLegalHold lock the session row before inspecting
// holds. A hold committed first blocks disposal; a disposal committed first
// prevents a new hold from being reported as protecting a deleted session.
func (s *SQLStore) sweepExpiredSession(ctx context.Context, scope Scope, id string, before time.Time) (held, disposed bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, fmt.Errorf("begin expired conversation disposal: %w", err)
	}
	defer tx.Rollback()
	var status, kind string
	var updatedAt time.Time
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,kind,updated_at FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&status, &kind, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("lock expired conversation: %w", err)
	}
	if status == "deleted" {
		return false, false, nil
	}
	var retentionDays int
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT retention_days FROM platform_conversation_retention_policy WHERE tenant_id=? AND department_id=? AND application_id=? AND kind=? AND enabled=TRUE FOR UPDATE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, kind).Scan(&retentionDays)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("lock conversation retention policy: %w", err)
	}
	if retentionDays < 1 {
		return false, false, ErrRetentionPolicy
	}
	if updatedAt.After(before.Add(-time.Duration(retentionDays) * 24 * time.Hour)) {
		return false, false, nil
	}
	var activeHolds int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_legal_hold WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=? AND status='active'`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&activeHolds); err != nil {
		return false, false, fmt.Errorf("check expired conversation hold: %w", err)
	}
	if activeHolds > 0 {
		return true, false, nil
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET status='deleted',can_continue=FALSE,revision=revision+1,updated_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND status <> 'deleted'`), before, id, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return false, false, fmt.Errorf("dispose expired conversation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, false, fmt.Errorf("confirm expired conversation disposal: %w", err)
	}
	if affected != 1 {
		return false, false, fmt.Errorf("confirm expired conversation disposal: affected=%d", affected)
	}
	if err := tx.Commit(); err != nil {
		return false, false, fmt.Errorf("commit expired conversation disposal: %w", err)
	}
	return false, true, nil
}

func requireGovernanceScope(scope Scope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if scope.PrincipalType != "service_principal" {
		return ErrForbidden
	}
	return nil
}

func validateRunSessionBinding(session Summary, run sharedkernel.Scope) error {
	if session.AgentID != run.AgentID || session.AgentVersionID != run.AgentVersionID || session.InstallationID != run.InstallationID {
		return errors.New("conversation run binding conflict")
	}
	return nil
}

func conversationID(prefix string, scope Scope, values ...string) string {
	raw := strings.Join(append([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID}, values...), "|")
	sum := sha256.Sum256([]byte(raw))
	return prefix + "-" + hex.EncodeToString(sum[:])
}

// ownedMessageWhere is shared by every message read/command path. A message
// row intentionally does not duplicate owner_id; the join to its session is
// therefore part of the authorization predicate, not just a convenience join.
// ownedMessageWhere 统一所有消息读写路径的归属过滤。消息表不重复保存
// owner_id，因此必须通过会话 JOIN 把 owner 作为授权条件，而不能仅按 ID 读。
func ownedMessageWhere(scope Scope, sessionID, messageID string) (string, []any) {
	where := `m.session_id=? AND m.tenant_id=? AND m.department_id=? AND m.application_id=? AND m.principal_type=? AND s.owner_id=? AND s.status <> 'deleted'`
	args := []any{sessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.historyOwner()}
	if strings.TrimSpace(messageID) != "" {
		where = `m.id=? AND ` + where
		args = append([]any{messageID}, args...)
	}
	return where, args
}

func truncate(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	// Keep the existing byte budget without splitting UTF-8 code points.
	// 保留原有字节上限，但不能截断中文或Emoji的UTF-8编码。
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

var _ Store = (*SQLStore)(nil)
var _ GovernanceStore = (*SQLStore)(nil)
var _ RetentionStore = (*SQLStore)(nil)
