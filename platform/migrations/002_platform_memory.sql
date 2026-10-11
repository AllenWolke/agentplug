-- Platform-owned durable working/session memory.
-- 平台拥有可跨进程重启的工作/会话记忆；Agent 只访问 MemoryStore/Capability Contract。
CREATE TABLE IF NOT EXISTS platform_memory_entry (
  scope_key CHAR(64) NOT NULL PRIMARY KEY,
  scope_prefix CHAR(64) NOT NULL,
  value_json LONGTEXT NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  KEY idx_platform_memory_prefix_expiry (scope_prefix, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
