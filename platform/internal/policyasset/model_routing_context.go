package policyasset

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// RoutingExecutionContextSHA256 binds qualification to the actual Prompt,
// tools, evidence and runtime behavior. Candidate chat identities, reasoning
// choices and the routing pool are excluded because those are under evaluation.
func RoutingExecutionContextSHA256(s Snapshot) string {
	rule := s.Rule
	if rule.Version == "" {
		rule.Version = s.RuleBundleVersion
	}
	if rule.Checksum == "" {
		rule.Checksum = s.RuleBundleChecksum
	}
	raw, err := json.Marshal(struct {
		Version                                             string
		PromptID, ToolID, MemoryID, KnowledgeID, RuntimeID  string
		Prompt                                              PromptPolicy
		Tool                                                ToolPolicy
		Memory                                              MemoryPolicy
		Knowledge                                           KnowledgePolicy
		Runtime                                             RuntimePolicy
		Rule                                                RulePolicy
		InputLimit, OutputLimit                             int
		AllowExternal                                       bool
		BudgetCents                                         int64
		EmbeddingVersion, EmbeddingProvider, EmbeddingModel string
		ContextCache                                        *ContextCachePolicy `json:",omitempty"`
	}{"model-routing-execution-context/v1", s.PromptVersionID, s.ToolPolicyID, s.MemoryPolicyID, s.KnowledgePolicyID, s.RuntimePolicyID,
		s.Prompt, s.Tool, s.Memory, s.Knowledge, s.Runtime, rule, s.Model.MaxInputTokens, s.Model.MaxTokens,
		s.Model.AllowExternal, s.Model.BudgetCents, s.Model.EmbeddingModelVersionID, s.Model.EmbeddingProvider, s.Model.EmbeddingModel, s.Model.ContextCache})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// RoutingBehaviorContextSHA256 removes only release-specific asset identities.
// It preserves every Prompt, tool, evidence, memory, runtime and model-limit
// value, including cache and embedding identity. It grants no qualification.
func RoutingBehaviorContextSHA256(s Snapshot) string {
	s.PromptVersionID, s.ToolPolicyID, s.MemoryPolicyID, s.KnowledgePolicyID, s.RuntimePolicyID = "", "", "", "", ""
	return RoutingExecutionContextSHA256(s)
}

// QualificationProfile is a capability applicability fingerprint, not an
// assertion that source and destination corpora or execution inputs are equal.
// Source verification continues to use its original full execution digest.
// Prompt, tools, runtime, limits, knowledge rules, memory, rule and embedding
// remain exact. Scope/document membership are authorized at the destination
// on every use. Only transparent provider prefix caching is semantically inert;
// an unsupported cache policy cannot be silently normalized here.
func RoutingQualificationProfileSHA256(s Snapshot) string {
	if s.Model.ValidateContextCache() != nil || s.Model.ValidateEmbeddingTarget() != nil {
		return ""
	}
	s.Knowledge.DocumentBindings = nil
	s.Knowledge.AllowedScopes = nil
	s.Model.ContextCache = nil
	// The immutable embedding version pins the provider/model identity. A
	// provider catalog key is a current routing alias and may be renamed when
	// merging namespaces. Keep the version and wire model exact; the gateway
	// still requires the destination alias to match that approved version.
	// Historical full execution hashes keep the original alias unchanged.
	if s.Model.EmbeddingModelVersionID != "" {
		s.Model.EmbeddingProvider = ""
	}
	raw, err := json.Marshal(struct {
		Version     string
		Context     string
		Temperature float64
	}{"model-routing-qualification-profile/v1", RoutingBehaviorContextSHA256(s), s.Model.Temperature})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// SnapshotFromRoutingExecutionInput handles the existing signed execution wire
// representation. It neither resolves current policy nor changes old hashing.
func SnapshotFromRoutingExecutionInput(value any) (Snapshot, error) {
	raw, err := json.Marshal(value)
	var snapshot Snapshot
	if err != nil || json.Unmarshal(raw, &snapshot) != nil {
		return Snapshot{}, ErrMissingPolicy
	}
	var rule struct {
		RuleBundle *RulePolicy `json:"rule_bundle"`
	}
	if json.Unmarshal(raw, &rule) != nil {
		return Snapshot{}, ErrMissingPolicy
	}
	if rule.RuleBundle != nil {
		snapshot.Rule = *rule.RuleBundle
	}
	return snapshot, nil
}
