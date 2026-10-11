package policyasset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// SQLDB is the smallest database surface required by the policy resolver.
// SQLDB 是策略 Resolver 所需的最小数据库接口，便于替换本地或远程适配器。
type SQLDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var ErrPolicyNotFound = errors.New("policy snapshot not found")

// SQLResolver loads immutable six-policy snapshots using the trusted scope.
// It deliberately does not accept policy IDs from an unscoped URL or header.
// SQLResolver 只按可信 Scope 加载不可变六策略快照，不接受裸 ID 越权查询。
type SQLResolver struct{ db SQLDB }

func NewSQLResolver(db SQLDB) *SQLResolver { return &SQLResolver{db: db} }

// PromptTemplateSeed is the deploy-time representation of an immutable
// prompt body.  The control plane stores the body beside its published hash;
// Agents never need to ship a second authoritative copy in their image.
// PromptTemplateSeed 是部署时注入的不可变 Prompt 正文；控制面把正文和发布
// 哈希一起存储，Agent 镜像不再维护第二份事实源。
type PromptTemplateSeed struct {
	TemplateHash string `json:"template_hash"`
	Template     string `json:"template"`
}

// EnsurePromptTemplates materializes approved prompt bodies into existing
// scoped snapshots during the trusted deployment/bootstrap path. It is not
// exposed through the browser module or used as a request-time fallback.
func (r *SQLResolver) EnsurePromptTemplates(ctx context.Context, raw string) error {
	if r == nil || r.db == nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var seeds []PromptTemplateSeed
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		var byHash map[string]string
		if err := json.Unmarshal([]byte(trimmed), &byHash); err != nil {
			return fmt.Errorf("decode prompt template map: %w", err)
		}
		for hash, template := range byHash {
			seeds = append(seeds, PromptTemplateSeed{TemplateHash: hash, Template: template})
		}
	} else if err := json.Unmarshal([]byte(trimmed), &seeds); err != nil {
		return fmt.Errorf("decode prompt template seeds: %w", err)
	}
	if len(seeds) == 0 {
		return errors.New("prompt template seeds are empty")
	}
	for _, seed := range seeds {
		hash := strings.TrimSpace(seed.TemplateHash)
		template := strings.TrimSpace(seed.Template)
		if hash == "" || template == "" {
			return errors.New("prompt template hash and body are required")
		}
		if len(template) > 128*1024 {
			return errors.New("prompt template exceeds 128 KiB")
		}
		if _, err := r.db.ExecContext(ctx, sqlutil.Bind(`
UPDATE platform_policy_snapshot
SET prompt_policy_json=jsonb_set(prompt_policy_json::jsonb, '{template}', to_jsonb(?::text), true)::json, updated_at=CURRENT_TIMESTAMP
WHERE prompt_policy_json->>'template_hash'=?`), template, hash); err != nil {
			return fmt.Errorf("materialize prompt template %s: %w", hash, err)
		}
	}
	return nil
}

func (r *SQLResolver) EnsureSchema(ctx context.Context) error {
	if r == nil || r.db == nil {
		return errors.New("policy resolver database is required")
	}
	_, err := r.db.ExecContext(ctx, sqlutil.Bind(`
CREATE TABLE IF NOT EXISTS platform_policy_snapshot (
  tenant_id VARCHAR(128) NOT NULL,
  department_id VARCHAR(128) NOT NULL,
  application_id VARCHAR(128) NOT NULL,
  agent_id VARCHAR(128) NOT NULL,
  agent_version_id VARCHAR(128) NOT NULL,
  revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
  snapshot_hash VARCHAR(64) NOT NULL,
  model_profile_id VARCHAR(128) NOT NULL,
  prompt_version_id VARCHAR(128) NOT NULL,
  tool_policy_id VARCHAR(128) NOT NULL,
  memory_policy_id VARCHAR(128) NOT NULL,
  knowledge_policy_id VARCHAR(128) NOT NULL,
  runtime_policy_id VARCHAR(128) NOT NULL,
  model_policy_json JSON NOT NULL,
  prompt_policy_json JSON NOT NULL,
  tool_policy_json JSON NOT NULL,
  memory_policy_json JSON NOT NULL,
  knowledge_policy_json JSON NOT NULL,
  runtime_policy_json JSON NOT NULL,
  rule_policy_json JSON NOT NULL,
  created_at TIMESTAMPTZ(6) NOT NULL,
  updated_at TIMESTAMPTZ(6) NOT NULL,
  PRIMARY KEY (tenant_id, department_id, application_id, agent_id, agent_version_id)
);
`))
	if err != nil {
		return fmt.Errorf("create platform policy snapshot schema: %w", err)
	}
	return nil
}

func (r *SQLResolver) Resolve(ctx context.Context, scope sharedkernel.Scope, agentVersionID string) (Snapshot, error) {
	if r == nil || r.db == nil || scope.Validate() != nil || agentVersionID == "" {
		return Snapshot{}, ErrScopeMismatch
	}
	var snapshot Snapshot
	var modelJSON, promptJSON, toolJSON, memoryJSON, knowledgeJSON, runtimeJSON, ruleJSON []byte
	err := r.db.QueryRowContext(ctx, sqlutil.Bind(`
	SELECT model_profile_id, prompt_version_id, tool_policy_id, memory_policy_id,
       knowledge_policy_id, runtime_policy_id, revision, snapshot_hash,
       model_policy_json, prompt_policy_json, tool_policy_json, memory_policy_json,
       knowledge_policy_json, runtime_policy_json, rule_policy_json
FROM platform_policy_snapshot
WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, agentVersionID,
	).Scan(
		&snapshot.ModelProfileID, &snapshot.PromptVersionID, &snapshot.ToolPolicyID,
		&snapshot.MemoryPolicyID, &snapshot.KnowledgePolicyID, &snapshot.RuntimePolicyID,
		&snapshot.Revision, &snapshot.Hash,
		&modelJSON, &promptJSON, &toolJSON, &memoryJSON, &knowledgeJSON, &runtimeJSON, &ruleJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrPolicyNotFound
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("resolve platform policy snapshot: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := json.Unmarshal(modelJSON, &snapshot.Model); err != nil {
		return Snapshot{}, fmt.Errorf("decode model policy: %w", err)
	}
	if err := json.Unmarshal(promptJSON, &snapshot.Prompt); err != nil {
		return Snapshot{}, fmt.Errorf("decode prompt policy: %w", err)
	}
	if err := json.Unmarshal(toolJSON, &snapshot.Tool); err != nil {
		return Snapshot{}, fmt.Errorf("decode tool policy: %w", err)
	}
	if err := json.Unmarshal(memoryJSON, &snapshot.Memory); err != nil {
		return Snapshot{}, fmt.Errorf("decode memory policy: %w", err)
	}
	if err := json.Unmarshal(knowledgeJSON, &snapshot.Knowledge); err != nil {
		return Snapshot{}, fmt.Errorf("decode knowledge policy: %w", err)
	}
	if err := json.Unmarshal(runtimeJSON, &snapshot.Runtime); err != nil {
		return Snapshot{}, fmt.Errorf("decode runtime policy: %w", err)
	}
	if err := json.Unmarshal(ruleJSON, &snapshot.Rule); err != nil {
		return Snapshot{}, fmt.Errorf("decode rule policy: %w", err)
	}
	snapshot.RuleBundleVersion = snapshot.Rule.Version
	snapshot.RuleBundleChecksum = snapshot.Rule.Checksum
	if err := snapshot.ValidateDetails(); err != nil {
		return Snapshot{}, fmt.Errorf("policy snapshot details incomplete: %w", err)
	}
	return snapshot, nil
}

// Upsert stores an administrator-approved bootstrap snapshot. Runtime HTTP
// requests never call this method; they resolve the immutable scoped record.
func (r *SQLResolver) Upsert(ctx context.Context, scope sharedkernel.Scope, snapshot Snapshot) error {
	if snapshot.Rule.Version == "" && snapshot.RuleBundleVersion != "" {
		snapshot.Rule.Version = snapshot.RuleBundleVersion
	}
	if snapshot.Rule.Checksum == "" && snapshot.RuleBundleChecksum != "" {
		snapshot.Rule.Checksum = snapshot.RuleBundleChecksum
	}
	if r == nil || r.db == nil || scope.Validate() != nil || snapshot.Validate() != nil || snapshot.ValidateDetails() != nil {
		return ErrScopeMismatch
	}
	modelJSON, _ := json.Marshal(snapshot.Model)
	promptJSON, _ := json.Marshal(snapshot.Prompt)
	toolJSON, _ := json.Marshal(snapshot.Tool)
	memoryJSON, _ := json.Marshal(snapshot.Memory)
	knowledgeJSON, _ := json.Marshal(snapshot.Knowledge)
	runtimeJSON, _ := json.Marshal(snapshot.Runtime)
	ruleJSON, _ := json.Marshal(snapshot.Rule)
	_, err := r.db.ExecContext(ctx, sqlutil.Bind(`
INSERT INTO platform_policy_snapshot
 (tenant_id, department_id, application_id, agent_id, agent_version_id, revision,
  snapshot_hash, model_profile_id, prompt_version_id, tool_policy_id, memory_policy_id,
  knowledge_policy_id, runtime_policy_id, model_policy_json, prompt_policy_json,
  tool_policy_json, memory_policy_json, knowledge_policy_json, runtime_policy_json, rule_policy_json,
  created_at, updated_at)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id,department_id,application_id,agent_id,agent_version_id) DO UPDATE SET
 revision=EXCLUDED.revision, snapshot_hash=EXCLUDED.snapshot_hash,
 model_profile_id=EXCLUDED.model_profile_id, prompt_version_id=EXCLUDED.prompt_version_id,
 tool_policy_id=EXCLUDED.tool_policy_id, memory_policy_id=EXCLUDED.memory_policy_id,
 knowledge_policy_id=EXCLUDED.knowledge_policy_id, runtime_policy_id=EXCLUDED.runtime_policy_id,
 model_policy_json=EXCLUDED.model_policy_json, prompt_policy_json=EXCLUDED.prompt_policy_json,
 tool_policy_json=EXCLUDED.tool_policy_json, memory_policy_json=EXCLUDED.memory_policy_json,
 knowledge_policy_json=EXCLUDED.knowledge_policy_json, runtime_policy_json=EXCLUDED.runtime_policy_json,
	 rule_policy_json=EXCLUDED.rule_policy_json,
 updated_at=CURRENT_TIMESTAMP`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID,
		snapshot.Revision, snapshot.Hash, snapshot.ModelProfileID, snapshot.PromptVersionID,
		snapshot.ToolPolicyID, snapshot.MemoryPolicyID, snapshot.KnowledgePolicyID, snapshot.RuntimePolicyID,
		modelJSON, promptJSON, toolJSON, memoryJSON, knowledgeJSON, runtimeJSON, ruleJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert platform policy snapshot: %w", err)
	}
	return nil
}

// SnapshotFromContext is the narrow conversion used by capability handlers.
// SnapshotFromContext 只用于能力网关比较请求声明与控制面快照。
func SnapshotFromContext(ids map[string]string) Snapshot {
	return Snapshot{
		ModelProfileID: ids["model_profile_id"], PromptVersionID: ids["prompt_version_id"],
		ToolPolicyID: ids["tool_policy_id"], MemoryPolicyID: ids["memory_policy_id"],
		KnowledgePolicyID: ids["knowledge_policy_id"], RuntimePolicyID: ids["runtime_policy_id"],
		RuleBundleVersion: ids["rule_bundle_version"], RuleBundleChecksum: ids["rule_bundle_checksum"],
		Rule: RulePolicy{Version: ids["rule_bundle_version"], Checksum: ids["rule_bundle_checksum"]},
	}
}

// SameIDs prevents an Agent from substituting a different policy revision.
func (s Snapshot) SameIDs(other Snapshot) bool {
	return s.ModelProfileID == other.ModelProfileID && s.PromptVersionID == other.PromptVersionID &&
		s.ToolPolicyID == other.ToolPolicyID && s.MemoryPolicyID == other.MemoryPolicyID &&
		s.KnowledgePolicyID == other.KnowledgePolicyID && s.RuntimePolicyID == other.RuntimePolicyID
}

// MarshalJSON keeps policy snapshots safe to expose in audit metadata without
// adding database handles or secrets.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type wire struct {
		ModelProfileID     string          `json:"model_profile_id"`
		PromptVersionID    string          `json:"prompt_version_id"`
		ToolPolicyID       string          `json:"tool_policy_id"`
		MemoryPolicyID     string          `json:"memory_policy_id"`
		KnowledgePolicyID  string          `json:"knowledge_policy_id"`
		RuntimePolicyID    string          `json:"runtime_policy_id"`
		RuleBundleVersion  string          `json:"rule_bundle_version,omitempty"`
		RuleBundleChecksum string          `json:"rule_bundle_checksum,omitempty"`
		Revision           uint64          `json:"revision"`
		Hash               string          `json:"hash"`
		Model              ModelPolicy     `json:"model"`
		Prompt             PromptPolicy    `json:"prompt"`
		Tool               ToolPolicy      `json:"tool"`
		Memory             MemoryPolicy    `json:"memory"`
		Knowledge          KnowledgePolicy `json:"knowledge"`
		Runtime            RuntimePolicy   `json:"runtime"`
		Rule               RulePolicy      `json:"rule"`
	}
	return json.Marshal(wire{ModelProfileID: s.ModelProfileID, PromptVersionID: s.PromptVersionID, ToolPolicyID: s.ToolPolicyID, MemoryPolicyID: s.MemoryPolicyID, KnowledgePolicyID: s.KnowledgePolicyID, RuntimePolicyID: s.RuntimePolicyID, RuleBundleVersion: s.RuleBundleVersion, RuleBundleChecksum: s.RuleBundleChecksum, Revision: s.Revision, Hash: s.Hash, Model: s.Model, Prompt: s.Prompt, Tool: s.Tool, Memory: s.Memory, Knowledge: s.Knowledge, Runtime: s.Runtime, Rule: s.Rule})
}

// UnmarshalJSON mirrors the stable wire representation used by runtime inputs
// and the policy asset management API.
func (s *Snapshot) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("nil policy snapshot target")
	}
	var wire struct {
		ModelProfileID     string          `json:"model_profile_id"`
		PromptVersionID    string          `json:"prompt_version_id"`
		ToolPolicyID       string          `json:"tool_policy_id"`
		MemoryPolicyID     string          `json:"memory_policy_id"`
		KnowledgePolicyID  string          `json:"knowledge_policy_id"`
		RuntimePolicyID    string          `json:"runtime_policy_id"`
		RuleBundleVersion  string          `json:"rule_bundle_version"`
		RuleBundleChecksum string          `json:"rule_bundle_checksum"`
		Revision           uint64          `json:"revision"`
		Hash               string          `json:"hash"`
		Model              ModelPolicy     `json:"model"`
		Prompt             PromptPolicy    `json:"prompt"`
		Tool               ToolPolicy      `json:"tool"`
		Memory             MemoryPolicy    `json:"memory"`
		Knowledge          KnowledgePolicy `json:"knowledge"`
		Runtime            RuntimePolicy   `json:"runtime"`
		Rule               RulePolicy      `json:"rule"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*s = Snapshot{
		ModelProfileID: wire.ModelProfileID, PromptVersionID: wire.PromptVersionID,
		ToolPolicyID: wire.ToolPolicyID, MemoryPolicyID: wire.MemoryPolicyID,
		KnowledgePolicyID: wire.KnowledgePolicyID, RuntimePolicyID: wire.RuntimePolicyID,
		RuleBundleVersion: wire.RuleBundleVersion, RuleBundleChecksum: wire.RuleBundleChecksum,
		Revision: wire.Revision, Hash: wire.Hash, Model: wire.Model, Prompt: wire.Prompt,
		Tool: wire.Tool, Memory: wire.Memory, Knowledge: wire.Knowledge,
		Runtime: wire.Runtime, Rule: wire.Rule,
	}
	return nil
}
