-- Platform-owned model invocation idempotency and budget ledger.
-- 平台所有的模型调用幂等与预算账本；可替换为远程 Usage Service。
CREATE TABLE IF NOT EXISTS platform_model_invocation (
  scope_hash CHAR(64) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL,
  response_json LONGTEXT NULL,
  cost_cents BIGINT NOT NULL DEFAULT 0,
  billing_recovery_json LONGTEXT NULL,
  billing_state VARCHAR(16) NOT NULL DEFAULT '',
  billing_retry_at DATETIME(6) NULL,
  invocation_token CHAR(32) NOT NULL DEFAULT '',
  preparation_deadline DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (scope_hash, idempotency_key),
  KEY idx_platform_model_invocation_scope (scope_hash, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Durable manual decisions and their application status; 持久化人工决策及执行审计。
CREATE TABLE IF NOT EXISTS platform_model_billing_decision (
  scope_hash CHAR(64) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  reservation_id VARCHAR(128) NOT NULL,
  decision_id VARCHAR(64) NOT NULL,
  decision_json LONGTEXT NOT NULL,
  status VARCHAR(16) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  applied_at DATETIME(6) NULL,
  PRIMARY KEY(scope_hash,idempotency_key,reservation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
