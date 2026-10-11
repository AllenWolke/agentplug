-- Authoritative source facts; projection rows never grant access to documents.
-- Apply only through the explicit platform migration, never from a worker.
CREATE TABLE IF NOT EXISTS platform_knowledge_task_checkpoint (
 tenant_id text NOT NULL, department_id text NOT NULL, application_id text NOT NULL, knowledge_id text NOT NULL,
 run_id text NOT NULL, owner_digest varchar(64) NOT NULL,
 revision bigint NOT NULL CHECK (revision > 0), checkpoint_digest varchar(64) NOT NULL,
 payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 67108864),
 updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,department_id,application_id,knowledge_id,run_id)
);
CREATE TABLE IF NOT EXISTS platform_knowledge_source_head (
 tenant_id text NOT NULL, department_id text NOT NULL, application_id text NOT NULL, knowledge_id text NOT NULL,
 source_revision bigint NOT NULL CHECK (source_revision >= 0),
 PRIMARY KEY (tenant_id,department_id,application_id,knowledge_id)
);
CREATE TABLE IF NOT EXISTS platform_knowledge_document_version (
 tenant_id text NOT NULL, department_id text NOT NULL, application_id text NOT NULL, knowledge_id text NOT NULL,
 document_id text NOT NULL, document_version bigint NOT NULL CHECK (document_version > 0),
 source_revision bigint NOT NULL CHECK (source_revision > 0),
 acl_revision bigint NOT NULL CHECK (acl_revision > 0), deleted boolean NOT NULL,
 content_digest varchar(64) NOT NULL, payload jsonb NOT NULL,
 PRIMARY KEY (tenant_id,department_id,application_id,knowledge_id,document_id,document_version),
 FOREIGN KEY (tenant_id,department_id,application_id,knowledge_id)
 REFERENCES platform_knowledge_source_head(tenant_id,department_id,application_id,knowledge_id)
);
CREATE TABLE IF NOT EXISTS platform_knowledge_document_head (
 tenant_id text NOT NULL, department_id text NOT NULL, application_id text NOT NULL, knowledge_id text NOT NULL,
 document_id text NOT NULL, document_version bigint NOT NULL,
 PRIMARY KEY (tenant_id,department_id,application_id,knowledge_id,document_id),
 FOREIGN KEY (tenant_id,department_id,application_id,knowledge_id,document_id,document_version)
 REFERENCES platform_knowledge_document_version(tenant_id,department_id,application_id,knowledge_id,document_id,document_version)
);
CREATE TABLE IF NOT EXISTS platform_knowledge_source_event (
 tenant_id text NOT NULL, department_id text NOT NULL, application_id text NOT NULL, knowledge_id text NOT NULL,
 source_revision bigint NOT NULL CHECK (source_revision > 0),
 document_id text NOT NULL, document_version bigint NOT NULL,
 idempotency_hash varchar(64) NOT NULL, request_digest varchar(64) NOT NULL,
 receipt jsonb NOT NULL, created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,department_id,application_id,knowledge_id,source_revision),
 UNIQUE (tenant_id,department_id,application_id,knowledge_id,idempotency_hash),
 FOREIGN KEY (tenant_id,department_id,application_id,knowledge_id,document_id,document_version)
 REFERENCES platform_knowledge_document_version(tenant_id,department_id,application_id,knowledge_id,document_id,document_version)
);
