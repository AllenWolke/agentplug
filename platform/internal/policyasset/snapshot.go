package policyasset

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type Snapshot struct {
	ModelProfileID     string
	PromptVersionID    string
	ToolPolicyID       string
	MemoryPolicyID     string
	KnowledgePolicyID  string
	RuntimePolicyID    string
	RuleBundleVersion  string
	RuleBundleChecksum string
	Revision           uint64
	Hash               string
	Model              ModelPolicy
	Prompt             PromptPolicy
	Tool               ToolPolicy
	Memory             MemoryPolicy
	Knowledge          KnowledgePolicy
	Runtime            RuntimePolicy
	Rule               RulePolicy
}

// Detail fields are immutable behavior materialized at publish time. IDs
// alone are not enough to constrain runtime behavior.
type ModelPolicy struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	// ModelVersionID pins a published capability snapshot to an approved model
	// catalog version. It is required when the governed invocation path is wired.
	ModelVersionID          string  `json:"model_version_id,omitempty"`
	EmbeddingModelVersionID string  `json:"embedding_model_version_id,omitempty"`
	EmbeddingProvider       string  `json:"embedding_provider,omitempty"`
	EmbeddingModel          string  `json:"embedding_model,omitempty"`
	MaxTokens               int     `json:"max_tokens"`
	MaxInputTokens          int     `json:"max_input_tokens,omitempty"`
	Temperature             float64 `json:"temperature"`
	// ReasoningMode is published policy, never an Agent request override.
	ReasoningMode string `json:"reasoning_mode,omitempty"`
	// ReasoningEffort is reviewed together with the chat policy and budget.
	ReasoningEffort         string `json:"reasoning_effort,omitempty"`
	AllowExternal           bool   `json:"allow_external"`
	BudgetCents             int64  `json:"budget_cents"`
	InputMicrosPer1KTokens  int64  `json:"input_micros_per_1k_tokens"`
	OutputMicrosPer1KTokens int64  `json:"output_micros_per_1k_tokens"`
}

// ForEmbedding selects only the optional target published in this model profile.
// It preserves shared trust/budget limits and never accepts request overrides.
// Profiles already dedicated to embedding may continue using their primary target.
func (p ModelPolicy) ForEmbedding() (ModelPolicy, error) {
	if err := p.ValidateReasoningMode(); err != nil {
		return ModelPolicy{}, err
	}
	if err := p.ValidateEmbeddingTarget(); err != nil {
		return ModelPolicy{}, err
	}
	if p.EmbeddingModelVersionID != "" {
		p.ModelVersionID = p.EmbeddingModelVersionID
		p.Provider = p.EmbeddingProvider
		p.Model = p.EmbeddingModel
	}
	p.ReasoningMode = ""
	p.ReasoningEffort = ""
	return p, nil
}

func (p ModelPolicy) ValidateReasoningMode() error {
	if p.ReasoningMode != "" && p.ReasoningMode != "enabled" && p.ReasoningMode != "disabled" {
		return ErrMissingPolicy
	}
	if p.ReasoningEffort != "" && (p.ReasoningMode != "enabled" ||
		(p.ReasoningEffort != "low" && p.ReasoningEffort != "high" && p.ReasoningEffort != "max")) {
		return ErrMissingPolicy
	}
	return nil
}

func (p ModelPolicy) ValidateEmbeddingTarget() error {
	values := []string{p.EmbeddingModelVersionID, p.EmbeddingProvider, p.EmbeddingModel}
	present := 0
	for _, value := range values {
		if value != "" {
			if strings.TrimSpace(value) != value || len(value) > 256 {
				return ErrMissingPolicy
			}
			present++
		}
	}
	if present != 0 && present != len(values) {
		return ErrMissingPolicy
	}
	return nil
}

type PromptPolicy struct {
	TemplateHash string `json:"template_hash"`
	// Template is immutable prompt content published together with the hash.
	// Template 是随哈希一起发布的不可变 Prompt 正文。
	Template string `json:"template,omitempty"`
}
type ToolPolicy struct {
	AllowedTools        []string             `json:"allowed_tools"`
	RequireConfirmation []string             `json:"require_confirmation"`
	Functions           []FunctionDefinition `json:"functions,omitempty"`
}
type MemoryPolicy struct {
	WorkingTTLSeconds int  `json:"working_ttl_seconds"`
	SessionTTLSeconds int  `json:"session_ttl_seconds"`
	TaskTTLSeconds    int  `json:"task_ttl_seconds"`
	MaxEntries        int  `json:"max_entries"`
	LongTermEnabled   bool `json:"long_term_enabled"`
	SemanticEnabled   bool `json:"semantic_enabled"`
}
type KnowledgePolicy struct {
	DocumentBindings     []KnowledgeDocumentBinding `json:"document_bindings,omitempty"`
	AllowedScopes        []string                   `json:"allowed_scopes"`
	RequireReferences    bool                       `json:"require_references"`
	AllowPartialDegraded bool                       `json:"allow_partial_degraded"`
	AllowReplay          bool                       `json:"allow_replay"`
}
type RuntimePolicy struct {
	MaxAttempts        int                    `json:"max_attempts"`
	TaskTimeoutSeconds int                    `json:"task_timeout_seconds"`
	LeaseSeconds       int                    `json:"lease_seconds"`
	CancelGraceSeconds int                    `json:"cancel_grace_seconds"`
	Context            *ContextPolicy         `json:"context,omitempty"`
	AllowedSkills      []string               `json:"allowed_skills,omitempty"`
	Delegation         *AgentDelegationPolicy `json:"delegation,omitempty"`
	RunBudget          *RunBudgetPolicy       `json:"run_budget,omitempty"`
	Harness            *HarnessPolicy         `json:"harness,omitempty"`
}

// HarnessPolicy is approved with the immutable runtime asset. SDK options may
// tighten these bounds, never widen them or choose a degradation policy.
type HarnessPolicy struct {
	MaxRounds         int    `json:"max_rounds"`
	MaxToolCalls      int    `json:"max_tool_calls"`
	MaxRepeatedCalls  int    `json:"max_repeated_calls"`
	MaxElapsedSeconds int    `json:"max_elapsed_seconds"`
	LimitBehavior     string `json:"limit_behavior"`
}

func (p HarnessPolicy) Validate() error {
	if p.MaxRounds < 1 || p.MaxRounds > 8 || p.MaxToolCalls < 1 || p.MaxToolCalls > 16 || p.MaxRepeatedCalls < 1 || p.MaxRepeatedCalls > 4 || p.MaxElapsedSeconds < 10 || p.MaxElapsedSeconds > 3600 || (p.LimitBehavior != "error" && p.LimitBehavior != "incomplete") {
		return ErrMissingPolicy
	}
	return nil
}

func (p RuntimePolicy) EffectiveHarnessPolicy() (HarnessPolicy, error) {
	limits := HarnessPolicy{MaxRounds: 8, MaxToolCalls: 16, MaxRepeatedCalls: 1, MaxElapsedSeconds: 300, LimitBehavior: "error"}
	if p.Harness != nil {
		limits = *p.Harness
	}
	return limits, limits.Validate()
}

// RunBudgetPolicy is an explicitly approved root-Run allowance, shared by the
// root and all coordinated descendants. It does not replace per-Agent price
// windows. Absence preserves old snapshot hashes; zero means zero allowance.
type RunBudgetPolicy struct {
	LimitTokens int64 `json:"limit_tokens"`
	LimitMicros int64 `json:"limit_micros"`
}

func (p RunBudgetPolicy) Validate() error {
	if p.LimitTokens < 0 || p.LimitMicros < 0 {
		return ErrMissingPolicy
	}
	return nil
}

// Delegation is explicitly published, never supplied by model output. Absence
// disables business routing and child execution without changing old hashes.
type AgentDelegationPolicy struct {
	AllowedAgentIDs []string `json:"allowed_agent_ids"`
	TaskTypes       []string `json:"task_types"`
	MaxDepth        int      `json:"max_depth"`
	MaxChildren     int      `json:"max_children"`
}

func (p AgentDelegationPolicy) Validate() error {
	if p.MaxDepth < 1 || p.MaxDepth > 4 || p.MaxChildren < 1 || p.MaxChildren > 16 || len(p.AllowedAgentIDs) < 1 || len(p.AllowedAgentIDs) > 32 || len(p.TaskTypes) < 1 || len(p.TaskTypes) > 16 {
		return ErrMissingPolicy
	}
	for _, values := range [][]string{p.AllowedAgentIDs, p.TaskTypes} {
		seen := map[string]bool{}
		for _, id := range values {
			if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "*\x00\r\n") || seen[id] {
				return ErrMissingPolicy
			}
			seen[id] = true
		}
	}
	return nil
}

// ContextPolicy is pinned with the approved runtime snapshot, not selected by
// a model or business request. Summaries retain excerpts as untrusted data.
type ContextPolicy struct {
	MaxMessages     int    `json:"max_messages"`
	Mode            string `json:"mode"`
	SummaryMaxBytes int    `json:"summary_max_bytes,omitempty"`
}

func (p RuntimePolicy) ValidateContext() error {
	if p.Harness != nil && p.Harness.Validate() != nil {
		return ErrMissingPolicy
	}
	if p.RunBudget != nil && p.RunBudget.Validate() != nil {
		return ErrMissingPolicy
	}
	if p.Delegation != nil && p.Delegation.Validate() != nil {
		return ErrMissingPolicy
	}
	if len(p.AllowedSkills) > 32 {
		return ErrMissingPolicy
	}
	seen := map[string]bool{}
	for _, id := range p.AllowedSkills {
		if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || strings.ContainsAny(id, "*\x00\r\n") || seen[id] {
			return ErrMissingPolicy
		}
		seen[id] = true
	}
	if p.Context == nil {
		return nil
	}
	c := p.Context
	if c.MaxMessages < 2 || c.MaxMessages > 256 || c.Mode != "window" && c.Mode != "summary" && c.Mode != "reject" || c.SummaryMaxBytes < 0 || c.SummaryMaxBytes > 16384 || c.Mode == "summary" && c.SummaryMaxBytes < 128 || c.Mode != "summary" && c.SummaryMaxBytes != 0 {
		return ErrMissingPolicy
	}
	return nil
}

func (p ModelPolicy) ValidateInputLimit() error {
	if p.MaxInputTokens < 0 || p.MaxInputTokens > 1048576 {
		return ErrMissingPolicy
	}
	return nil
}

// RulePolicy pins an optional deterministic artifact version and digest.
// Agents using this binding must verify both before executing the artifact.
type RulePolicy struct {
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
}

var (
	ErrMissingPolicy = errors.New("policy snapshot is incomplete")
	ErrScopeMismatch = errors.New("policy snapshot scope mismatch")
)

func (s Snapshot) Validate() error {
	if err := s.ValidateIDs(); err != nil {
		return err
	}
	if s.Revision == 0 || strings.TrimSpace(s.Hash) == "" {
		return ErrMissingPolicy
	}
	return nil
}

// ValidateDetails is required for a production SQL snapshot. Fixture
// resolvers may omit details for fast unit tests.
func (s Snapshot) ValidateDetails() error {
	if s.Runtime.ValidateContext() != nil || s.Model.ValidateInputLimit() != nil {
		return ErrMissingPolicy
	}
	if s.Tool.ValidateFunctions() != nil {
		return ErrMissingPolicy
	}
	if s.Model.ValidateReasoningMode() != nil {
		return ErrMissingPolicy
	}
	if err := s.Model.ValidateEmbeddingTarget(); err != nil {
		return ErrMissingPolicy
	}
	if strings.TrimSpace(s.Model.Provider) == "" || strings.TrimSpace(s.Model.Model) == "" || s.Model.MaxTokens < 1 {
		return ErrMissingPolicy
	}
	if strings.TrimSpace(s.Prompt.TemplateHash) == "" || s.Tool.AllowedTools == nil || s.Knowledge.AllowedScopes == nil {
		return ErrMissingPolicy
	}
	if err := s.Knowledge.ValidateDocuments(); err != nil {
		return ErrMissingPolicy
	}
	if s.Memory.MaxEntries < 1 || s.Runtime.MaxAttempts < 1 || s.Runtime.TaskTimeoutSeconds < 1 || s.Runtime.LeaseSeconds < 1 {
		return ErrMissingPolicy
	}
	if (strings.TrimSpace(s.Rule.Version) == "") != (strings.TrimSpace(s.Rule.Checksum) == "") {
		return ErrMissingPolicy
	}
	if len(strings.TrimSpace(s.Rule.Checksum)) > 0 && len(strings.TrimSpace(s.Rule.Checksum)) != 64 {
		return ErrMissingPolicy
	}
	return nil
}

// ValidateIDs checks the six policy identities before a resolved revision is
// compared. Requests carry IDs; the control plane supplies revision/hash.
// ValidateIDs 用于校验请求携带的六个策略 ID；版本号和哈希由控制面补齐。
func (s Snapshot) ValidateIDs() error {
	for _, id := range []string{s.ModelProfileID, s.PromptVersionID, s.ToolPolicyID, s.MemoryPolicyID, s.KnowledgePolicyID, s.RuntimePolicyID} {
		if strings.TrimSpace(id) == "" {
			return ErrMissingPolicy
		}
	}
	return nil
}

// ExecutionInput materializes the immutable control-plane snapshot in the
// cross-language Agent Execution v2 input contract. It deliberately exports
// only published policy data, never database or provider credentials.
// ExecutionInput 将不可变控制面快照物化为跨语言 Agent Execution v2 输入契约；
// 只导出已发布策略数据，不导出数据库凭据或模型 Provider 密钥。
func (s Snapshot) ExecutionInput() (map[string]any, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if err := s.ValidateDetails(); err != nil {
		return nil, err
	}
	input := map[string]any{
		"content_hash":        s.Hash,
		"revision":            s.Revision,
		"model_profile_id":    s.ModelProfileID,
		"prompt_version_id":   s.PromptVersionID,
		"tool_policy_id":      s.ToolPolicyID,
		"memory_policy_id":    s.MemoryPolicyID,
		"knowledge_policy_id": s.KnowledgePolicyID,
		"runtime_policy_id":   s.RuntimePolicyID,
		"model":               s.Model,
		"prompt":              s.Prompt,
		"tool":                s.Tool,
		"memory":              s.Memory,
		"knowledge":           s.Knowledge,
		"runtime":             s.Runtime,
	}
	rule := s.Rule
	if rule.Version == "" {
		rule.Version = s.RuleBundleVersion
	}
	if rule.Checksum == "" {
		rule.Checksum = s.RuleBundleChecksum
	}
	if rule.Version != "" || rule.Checksum != "" {
		if rule.Version == "" || len(rule.Checksum) != 64 {
			return nil, ErrMissingPolicy
		}
		input["rule_bundle"] = rule
	}
	return input, nil
}

func (s Snapshot) AllowsTool(name string) bool {
	if len(s.Tool.AllowedTools) == 0 {
		// A published explicit [] disables this capability. Nil remains the
		// legacy fixture convention; ValidateDetails rejects nil in SQL policy.
		return s.Tool.AllowedTools == nil
	}
	for _, item := range s.Tool.AllowedTools {
		if item == name {
			return true
		}
	}
	return false
}

func (s Snapshot) AllowsKnowledgeScope(scope string) bool {
	if len(s.Knowledge.AllowedScopes) == 0 {
		return s.Knowledge.AllowedScopes == nil
	}
	for _, item := range s.Knowledge.AllowedScopes {
		if item == scope {
			return true
		}
	}
	return false
}

// SameRuleBinding compares optional artifact bindings; absent bindings match
// only when both version and digest are absent.
func (s Snapshot) SameRuleBinding(other Snapshot) bool {
	leftVersion := strings.TrimSpace(s.Rule.Version)
	if leftVersion == "" {
		leftVersion = strings.TrimSpace(s.RuleBundleVersion)
	}
	rightVersion := strings.TrimSpace(other.Rule.Version)
	if rightVersion == "" {
		rightVersion = strings.TrimSpace(other.RuleBundleVersion)
	}
	leftChecksum := strings.TrimSpace(s.Rule.Checksum)
	if leftChecksum == "" {
		leftChecksum = strings.TrimSpace(s.RuleBundleChecksum)
	}
	rightChecksum := strings.TrimSpace(other.Rule.Checksum)
	if rightChecksum == "" {
		rightChecksum = strings.TrimSpace(other.RuleBundleChecksum)
	}
	return leftVersion == rightVersion && strings.EqualFold(leftChecksum, rightChecksum)
}

type Resolver interface {
	Resolve(context.Context, sharedkernel.Scope, string) (Snapshot, error)
}

// StaticResolver is a deterministic test/fixture resolver. Production
// adapters will load the immutable snapshot from the platform control plane.
// StaticResolver 用于确定性测试；生产 Adapter 从平台控制面读取不可变快照。
type StaticResolver struct{ Snapshot Snapshot }

func (r StaticResolver) Resolve(_ context.Context, scope sharedkernel.Scope, _ string) (Snapshot, error) {
	if err := scope.Validate(); err != nil {
		return Snapshot{}, ErrScopeMismatch
	}
	if err := r.Snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return r.Snapshot, nil
}
