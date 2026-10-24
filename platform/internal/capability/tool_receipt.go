package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ToolReceiptQuery contains immutable bindings, not an instruction to execute.
// 提交回执查询只包含不可变绑定，不包含重新执行副作用的指令。
type ToolReceiptQuery struct {
	Scope          sharedkernel.Scope
	CallID         string
	Name           string
	Fingerprint    string
	RuntimeAudit   *ToolRuntimeAuditBinding `json:",omitempty"`
	InputEvidence  *ToolInputEvidence       `json:",omitempty"`
	RemoteContract *RemoteToolContract      `json:",omitempty"`
}

type BusinessToolReceiptPort interface {
	LookupToolReceipt(context.Context, ToolReceiptQuery) (map[string]any, bool, error)
}

// Recovery is read-only at the business Port, followed by ledger-only repair.
// 业务 Port 只查回执，随后只修复调用账本；禁止重跑副作用。
func (m *Module) restoreBusinessTool(ctx context.Context, q ToolReceiptQuery) (map[string]any, bool, error) {
	// Reload the original contract instead of inferring it from today's tool
	// registration. This also covers immediate receipt recovery after HTTP loss.
	if read, ok := m.toolStore.(toolReceiptReadStore); ok {
		saved, found, err := read.LookupToolInvocation(ctx, ToolReceiptScopeHash(q.Scope), q.CallID)
		if err != nil {
			return nil, false, err
		}
		if found && saved.Fingerprint != q.Fingerprint {
			return nil, false, ErrToolInvocationConflict
		}
		if found && saved.ReceiptQuery != nil {
			original := saved.ReceiptQuery
			if ToolReceiptScopeHash(original.Scope) != ToolReceiptScopeHash(q.Scope) || original.Name != q.Name || original.CallID != q.CallID || original.Fingerprint != q.Fingerprint {
				return nil, false, ErrToolInvocationConflict
			}
			q = *original
		}
	}
	port, ok := m.tools.(BusinessToolReceiptPort)
	if isNotificationTool(q.Name) {
		port, ok = m.notifications.(BusinessToolReceiptPort)
	} else if m.tools == nil || !m.tools.Supports(q.Name) {
		return nil, false, nil
	}
	if !ok {
		return nil, false, nil
	}
	store, ok := m.toolStore.(toolReceiptCompletionStore)
	if !ok {
		return nil, false, errors.New("tool receipt completion port unavailable")
	}
	result, found, err := port.LookupToolReceipt(ctx, q)
	if err != nil || !found {
		return nil, false, err
	}
	if result == nil {
		return nil, false, errors.New("empty business tool receipt")
	}
	if err := store.RestoreCommitted(ctx, ToolReceiptScopeHash(q.Scope), q.CallID, q.Fingerprint, result); err != nil {
		return nil, false, err
	}
	return result, true, nil
}

type toolReceiptCompletionStore interface {
	RestoreCommitted(context.Context, string, string, string, map[string]any) error
}

// ToolCommandFingerprint is shared with domain receipt writers.
// 业务回执与网关使用同一指纹算法，避免协议漂移。
func ToolCommandFingerprint(name string, payload map[string]any) (string, error) {
	raw, err := json.Marshal(struct {
		Name    string         `json:"name"`
		Payload map[string]any `json:"payload"`
	}{name, payload})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func ToolReceiptScopeHash(s sharedkernel.Scope) string {
	raw, _ := json.Marshal([]string{s.TenantID, s.DepartmentID, s.ApplicationID, s.AgentID, s.AgentInstanceID, s.PrincipalType, s.PrincipalID, s.InstallationID, s.AgentVersionID, s.SessionID, s.RunID})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func (s *memoryToolInvocationStore) RestoreCommitted(_ context.Context, scope, id, fp string, result map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scope + "\x00" + id
	r, ok := s.records[key]
	if !ok || r.Fingerprint != fp || r.Status != "running" && r.Status != "unknown" && r.Status != "completed" {
		return ErrToolInvocationConflict
	}
	if r.Status == "completed" {
		a, err := json.Marshal(r.Result)
		if err != nil {
			return err
		}
		b, err := json.Marshal(result)
		if err != nil {
			return err
		}
		equal, err := equalCanonicalToolResultJSON(a, b)
		if err != nil {
			return err
		}
		if !equal {
			return ErrToolInvocationConflict
		}
		return nil
	}
	r.Status, r.Result = "completed", cloneToolResult(result)
	s.records[key] = r
	return nil
}

func (s *SQLToolInvocationStore) RestoreCommitted(ctx context.Context, scope, id, fp string, result map[string]any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var savedFP, status string
	var savedResult []byte
	var fence uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT fingerprint,status,result_json,lease_fence FROM platform_tool_invocation WHERE scope_hash=? AND call_id=? FOR UPDATE`), scope, id).Scan(&savedFP, &status, &savedResult, &fence); err != nil {
		return err
	}
	if savedFP != fp {
		return ErrToolInvocationConflict
	}
	if status == "completed" {
		equal, err := equalCanonicalToolResultJSON(savedResult, raw)
		if err != nil {
			return err
		}
		if !equal {
			return ErrToolInvocationConflict
		}
		return tx.Commit()
	}
	if status != "unknown" && status != "running" {
		return ErrToolInvocationConflict
	}
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='completed',result_json=?,updated_at=clock_timestamp() WHERE scope_hash=? AND call_id=? AND fingerprint=? AND status IN ('unknown','running')`), string(raw), scope, id, fp)
	if err != nil {
		return err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrToolInvocationConflict
	}
	if err := s.recordRuntimeAuditTx(ctx, tx, ToolExecutionLease{ScopeHash: scope, CallID: id, Fingerprint: fp, Fence: fence}, "receipt_reconciled", result); err != nil {
		return err
	}
	return tx.Commit()
}

// equalCanonicalToolResultJSON ignores JSON object key order only. It keeps
// number lexemes with UseNumber and rejects duplicate keys, malformed JSON,
// and trailing values so a stored receipt cannot be weakened by coercion.
func equalCanonicalToolResultJSON(left, right []byte) (bool, error) {
	canonical := func(raw []byte) ([]byte, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		value, err := decodeCanonicalToolJSONValue(decoder)
		if err != nil {
			return nil, err
		}
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			if err == nil {
				return nil, errors.New("trailing tool receipt value")
			}
			return nil, err
		}
		return json.Marshal(value)
	}
	a, err := canonical(left)
	if err != nil {
		return false, err
	}
	b, err := canonical(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(a, b), nil
}

func decodeCanonicalToolJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("invalid tool receipt object key")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, errors.New("duplicate tool receipt object key")
				}
				item, err := decodeCanonicalToolJSONValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = item
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid tool receipt object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				item, err := decodeCanonicalToolJSONValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid tool receipt array")
			}
			return array, nil
		default:
			return nil, errors.New("invalid tool receipt delimiter")
		}
	case nil, bool, string, json.Number:
		return value, nil
	default:
		return nil, errors.New("invalid tool receipt value")
	}
}
