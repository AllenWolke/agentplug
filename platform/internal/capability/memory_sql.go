package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"time"
)

// SQLMemoryStore is the modular-monolith implementation of the MemoryStore
// port. It keeps the single-instance deployment durable across process
// restarts and leaves the request-shaped port ready for Redis/remote adapters.
// SQLMemoryStore 让单体单实例的记忆跨进程重启保持一致；Port 仍可替换为
// Redis 或远程服务，不把数据库连接泄露给 Agent。
type SQLMemoryStore struct {
	db             *sql.DB
	authorityGuard func(context.Context, *sql.Tx) error
	cancellation   *memoryCancellation
}

func NewSQLMemoryStore(db *sql.DB) (*SQLMemoryStore, error) {
	if db == nil {
		return nil, errors.New("memory SQL database is required")
	}
	return &SQLMemoryStore{db: db}, nil
}

func (s *SQLMemoryStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("memory SQL database is required")
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`
CREATE TABLE IF NOT EXISTS platform_memory_entry (
  scope_key VARCHAR(64) NOT NULL PRIMARY KEY,
  scope_prefix VARCHAR(64) NOT NULL,
  value_json TEXT NOT NULL,
  expires_at TIMESTAMPTZ(6) NOT NULL,
  created_at TIMESTAMPTZ(6) NOT NULL,
  updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_platform_memory_prefix_expiry ON platform_memory_entry (scope_prefix, expires_at);`))
	if err != nil {
		return fmt.Errorf("migrate platform memory: %w", err)
	}
	return nil
}

func (s *SQLMemoryStore) Load(ctx context.Context, key string) (memoryEntry, bool, error) {
	hash := memoryHash(key)
	var raw []byte
	var expiresAt time.Time
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT value_json, expires_at FROM platform_memory_entry WHERE scope_key=?`), hash).Scan(&raw, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return memoryEntry{}, false, nil
	}
	if err != nil {
		return memoryEntry{}, false, err
	}
	now := time.Now().UTC()
	if !now.Before(expiresAt) {
		// A concurrent Save may refresh the row after our read. Only remove a
		// value that is still expired when PostgreSQL acquires the deletion lock.
		// 读取后可能发生并发刷新；取得删除锁时仍已过期的行才允许清理。
		_, _ = s.db.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_memory_entry WHERE scope_key=? AND expires_at<=?`), hash, now)
		return memoryEntry{}, false, nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return memoryEntry{}, false, fmt.Errorf("decode platform memory: %w", err)
	}
	return memoryEntry{Value: value, ExpiresAt: expiresAt}, true, nil
}

func (s *SQLMemoryStore) Save(ctx context.Context, key string, entry memoryEntry, maxEntries int) error {
	return s.save(ctx, key, entry, maxEntries, nil)
}

func (s *SQLMemoryStore) save(ctx context.Context, key string, entry memoryEntry, maxEntries int, check func(context.Context) error) error {
	if entry.Value == nil || entry.ExpiresAt.IsZero() {
		return errors.New("memory value and expiry are required")
	}
	raw, err := json.Marshal(entry.Value)
	if err != nil {
		return fmt.Errorf("encode platform memory: %w", err)
	}
	hash := memoryHash(key)
	prefix := memoryHash(memoryScopePrefix(key))
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if s.cancellation != nil && s.cancellation.bind != nil {
		mutation, ok := ctx.Value(memoryMutationKey{}).(memoryMutation)
		if !ok || mutation.Scope.ValidateTrusted() != nil {
			return errMemoryContinuityUnavailable
		}
		ctx = s.cancellation.bind(ctx, tx, mutation.Scope)
		if ctx == nil {
			return errMemoryContinuityUnavailable
		}
	}
	if check != nil {
		if err := s.authorityGuard(ctx, tx); err != nil {
			return errors.Join(errMemoryContinuityUnavailable, err)
		}
		if err := check(ctx); err != nil {
			return errors.Join(errMemoryWriteDenied, err)
		}
	}
	step, replay, err := s.prepareMemoryEffectTx(ctx, tx, hash)
	if err != nil {
		return err
	}
	if replay {
		return tx.Commit()
	}
	if err := lockLedgerScope(ctx, tx, "memory-prefix", prefix); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_memory_entry WHERE scope_prefix=? AND expires_at<=?`), prefix, now); err != nil {
		return err
	}
	if maxEntries > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_memory_entry WHERE scope_prefix=?`), prefix).Scan(&count); err != nil {
			return err
		}
		var exists int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_memory_entry WHERE scope_key=?`), hash).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 && count >= maxEntries {
			return errMemoryLimitExceeded
		}
	}
	if s.cancellation != nil {
		stamp, err := s.captureMemoryEffectTx(ctx, tx, step, prefix)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_memory_entry(scope_key,scope_prefix,value_json,expires_at,created_at,updated_at,effect_stamp)
VALUES(?,?,?,?,?,?,?) ON CONFLICT(scope_key) DO UPDATE SET value_json=EXCLUDED.value_json,expires_at=EXCLUDED.expires_at,updated_at=EXCLUDED.updated_at,effect_stamp=EXCLUDED.effect_stamp`), hash, prefix, raw, entry.ExpiresAt.UTC(), now, now, stamp)
		if err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, sqlutil.Bind(`
INSERT INTO platform_memory_entry (scope_key, scope_prefix, value_json, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (scope_key) DO UPDATE SET value_json=EXCLUDED.value_json, expires_at=EXCLUDED.expires_at, updated_at=EXCLUDED.updated_at`), hash, prefix, raw, entry.ExpiresAt.UTC(), now, now); err != nil {
		return err
	}
	if check != nil {
		if err := check(ctx); err != nil {
			return errors.Join(errMemoryWriteDenied, err)
		}
	}
	return tx.Commit()
}

func memoryHash(value string) string {
	hash := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}
