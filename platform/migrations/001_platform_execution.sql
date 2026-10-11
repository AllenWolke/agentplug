-- Platform-owned execution state for the modular-monolith Run Provider.
-- 平台模块拥有运行状态；业务模块只通过 Execution Repository/Contract 访问。
CREATE TABLE IF NOT EXISTS platform_execution_run (
  run_id VARCHAR(128) NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  department_id VARCHAR(128) NOT NULL,
  application_id VARCHAR(128) NOT NULL,
  agent_instance_id VARCHAR(128) NOT NULL,
  agent_id VARCHAR(128) NOT NULL,
  principal_id VARCHAR(128) NOT NULL,
  principal_type VARCHAR(32) NOT NULL,
  installation_id VARCHAR(128) NOT NULL,
  agent_version_id VARCHAR(128) NOT NULL,
  session_id VARCHAR(128) NOT NULL,
  authorization_epoch BIGINT UNSIGNED NOT NULL DEFAULT 0,
  trace_id VARCHAR(128) NOT NULL,
  idempotency_key VARCHAR(128) NOT NULL,
  scope_idem_hash CHAR(64) NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  request_json LONGTEXT NULL,
  agent_endpoint VARCHAR(512) NOT NULL DEFAULT '',
  status VARCHAR(32) NOT NULL,
  revision BIGINT UNSIGNED NOT NULL,
  lease_token VARCHAR(128) NOT NULL DEFAULT '',
  lease_until DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  UNIQUE KEY uq_platform_execution_idem_hash (scope_idem_hash),
  KEY idx_platform_execution_scope (tenant_id, department_id, application_id, principal_id, run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS platform_execution_event (
  seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  run_id VARCHAR(128) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  payload JSON NOT NULL,
  occurred_at DATETIME(6) NOT NULL,
  KEY idx_platform_execution_event_run (run_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
