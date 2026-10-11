-- Platform-owned projection, not the authoritative document/ACL database.
-- Run with the migration identity; the application never invokes this DDL.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE SCHEMA IF NOT EXISTS knowledge;

CREATE TABLE IF NOT EXISTS knowledge.generations (
    tenant_id text NOT NULL,
    department_id text NOT NULL,
    application_id text NOT NULL,
    knowledge_id text NOT NULL,
    generation_id text NOT NULL,
    embedding_model_version text NOT NULL,
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
    tokenizer_version text NOT NULL,
    state text NOT NULL CHECK (state IN ('building', 'ready')),
    PRIMARY KEY (tenant_id, department_id, application_id, knowledge_id, generation_id),
    UNIQUE (tenant_id, department_id, application_id, knowledge_id, generation_id, dimensions)
);

CREATE TABLE IF NOT EXISTS knowledge.chunks (
    tenant_id text NOT NULL,
    department_id text NOT NULL,
    application_id text NOT NULL,
    knowledge_id text NOT NULL,
    generation_id text NOT NULL,
    document_id text NOT NULL,
    document_version text NOT NULL,
    acl_revision text NOT NULL,
    chunk_id text NOT NULL,
    body text NOT NULL CHECK (octet_length(body) <= 1048576),
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
    embedding vector NOT NULL CHECK (vector_dims(embedding) = dimensions AND vector_norm(embedding) > 0),
    PRIMARY KEY (tenant_id, department_id, application_id, knowledge_id, generation_id, document_id, chunk_id),
    FOREIGN KEY (tenant_id, department_id, application_id, knowledge_id, generation_id, dimensions)
      REFERENCES knowledge.generations (tenant_id, department_id, application_id, knowledge_id, generation_id, dimensions)
);

CREATE TABLE IF NOT EXISTS knowledge.active_generations (
    tenant_id text NOT NULL,
    department_id text NOT NULL,
    application_id text NOT NULL,
    knowledge_id text NOT NULL,
    generation_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant_id, department_id, application_id, knowledge_id),
    FOREIGN KEY (tenant_id, department_id, application_id, knowledge_id, generation_id)
      REFERENCES knowledge.generations (tenant_id, department_id, application_id, knowledge_id, generation_id)
);

-- Completeness receipts are written atomically with source-bound generations.
CREATE TABLE IF NOT EXISTS knowledge.index_receipts (
 tenant_id text NOT NULL, department_id text NOT NULL, application_id text NOT NULL, knowledge_id text NOT NULL,
 generation_id text NOT NULL, source_revision bigint NOT NULL CHECK(source_revision>=0),
 config_hash varchar(64) NOT NULL, source_digest varchar(64) NOT NULL, manifest_hash varchar(64) NOT NULL,
 document_count integer NOT NULL CHECK(document_count>=0),chunk_count integer NOT NULL CHECK(chunk_count>=0),
 PRIMARY KEY(tenant_id,department_id,application_id,knowledge_id,generation_id),
 FOREIGN KEY(tenant_id,department_id,application_id,knowledge_id,generation_id)
 REFERENCES knowledge.generations(tenant_id,department_id,application_id,knowledge_id,generation_id)
);
