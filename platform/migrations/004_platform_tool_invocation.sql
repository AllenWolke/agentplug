-- Platform-owned Tool side-effect idempotency ledger.
-- 平台所有的 Tool 副作用幂等账本；恢复或重试只能回放已完成结果。
CREATE TABLE IF NOT EXISTS platform_tool_invocation (
  scope_hash CHAR(64) NOT NULL,
  call_id VARCHAR(255) NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL,
  result_json LONGTEXT NULL,
  lease_owner VARCHAR(64) NOT NULL DEFAULT '',
  lease_token CHAR(32) NOT NULL DEFAULT '',
  lease_fence BIGINT UNSIGNED NOT NULL DEFAULT 0,
  lease_until DATETIME(6) NULL,
  phase VARCHAR(16) NOT NULL DEFAULT '',
  recovery_query LONGTEXT NULL,
  retry_after DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (scope_hash, call_id),
  KEY idx_platform_tool_invocation_scope (scope_hash, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
