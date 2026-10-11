package conversation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
)

// Complete exports are bounded by bytes, never silently by message count.
// 完整导出按字节限制资源，不能按消息数量静默截断。
const maxExportPayloadBytes = 8 * 1024 * 1024

func conversationExportSnapshot(ctx context.Context, tx *sql.Tx, scope Scope, sessionID string, summary Summary) ([]byte, error) {
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT m.id,m.session_id,m.role,m.content,m.intent_code,m.knowledge_scope,m.metadata_json,m.created_at FROM platform_conversation_message m
		JOIN platform_conversation_session s ON s.id=m.session_id AND s.tenant_id=m.tenant_id AND s.department_id=m.department_id AND s.application_id=m.application_id AND s.principal_type=m.principal_type
		WHERE m.session_id=? AND m.tenant_id=? AND m.department_id=? AND m.application_id=? AND m.principal_type=? AND s.owner_id=? AND s.status <> 'deleted'
		ORDER BY m.created_at ASC,m.id ASC`), sessionID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, scope.PrincipalID)
	if err != nil {
		return nil, fmt.Errorf("read conversation export: %w", err)
	}
	defer rows.Close()
	return encodeConversationExport(summary, func() (Message, bool, error) {
		if !rows.Next() {
			return Message{}, false, rows.Err()
		}
		var item Message
		var metadata string
		if err := rows.Scan(&item.ID, &item.SessionID, &item.Role, &item.Content, &item.IntentCode, &item.KnowledgeScope, &metadata, &item.CreatedAt); err != nil {
			return Message{}, false, err
		}
		if strings.TrimSpace(metadata) != "" && metadata != "{}" {
			if err := json.Unmarshal([]byte(metadata), &item.Metadata); err != nil {
				return Message{}, false, err
			}
		}
		return item, true, nil
	})
}

func encodeConversationExport(summary Summary, next func() (Message, bool, error)) ([]byte, error) {
	var payload bytes.Buffer
	appendPart := func(part []byte) error {
		if len(part) > maxExportPayloadBytes-payload.Len() {
			return ErrExportTooLarge
		}
		_, err := payload.Write(part)
		return err
	}
	_ = appendPart([]byte(`{"messages":[`))
	count := 0
	for {
		message, ok, err := next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		encoded, err := json.Marshal(message)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			if err := appendPart([]byte(",")); err != nil {
				return nil, err
			}
		}
		if err := appendPart(encoded); err != nil {
			return nil, err
		}
		count++
	}
	summary.MessageCount = count
	encoded, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	if err := appendPart(append(append([]byte(`],"summary":`), encoded...), '}')); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}
