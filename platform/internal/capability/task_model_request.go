package capability

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/contract"
)

// TaskWorkloadCredential is supplied by an operator-owned secret resolver.
// Neither field may be serialized into durable job descriptors or logs.
type TaskWorkloadCredential struct {
	ClientID string `json:"-"`
	Secret   string `json:"-"`
}

// BuildTaskEmbeddingRequest constructs an in-process request with the same
// HMAC framing and workload headers as ordinary capability calls. It grants
// no authority: OpenTaskEmbeddingSession verifies the token/current command,
// IAM, workload credential and published policy before any model operation.
func (m *Module) BuildTaskEmbeddingRequest(ctx context.Context, command contract.ExecuteRequest, token string, credential TaskWorkloadCredential) (*http.Request, error) {
	denied := func() (*http.Request, error) {
		return nil, &KnowledgeModelError{Status: 403, Code: "TASK_MODEL_CONTEXT_DENIED"}
	}
	if m == nil || ctx == nil || m.publicKey == nil || m.internalToken == "" || m.signingSecret == "" || command.ContextToken != "" || command.Scope.Validate() != nil || (command.Operation != "invoke" && command.Operation != "run" && command.Operation != "resume") {
		return denied()
	}
	for _, value := range []string{credential.ClientID, credential.Secret} {
		if value == "" || len(value) > 4096 || strings.TrimSpace(value) != value {
			return denied()
		}
		for _, char := range value {
			if char < 33 || char > 126 {
				return denied()
			}
		}
	}
	policy, ok := command.Input["policy_snapshot"].(map[string]any)
	if !ok {
		return denied()
	}
	ref := func(key string) string { value, _ := policy[key].(string); return value }
	s := command.Scope
	c := harnessContext{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentID: s.AgentID, AgentInstanceID: s.AgentInstanceID, InstallationID: s.InstallationID, AgentVersionID: s.AgentVersionID, PrincipalType: s.PrincipalType, ActorID: s.PrincipalID, SessionID: s.SessionID, TaskID: s.RunID, ParentRunID: s.ParentRunID, TraceID: s.TraceID, AuthorizationEpoch: s.AuthorizationEpoch, RequestID: "index-model:" + s.RunID, PlatformContextToken: token, ModelProfileID: ref("model_profile_id"), PromptVersionID: ref("prompt_version_id"), ToolPolicyID: ref("tool_policy_id"), MemoryPolicyID: ref("memory_policy_id"), KnowledgePolicyID: ref("knowledge_policy_id"), RuntimePolicyID: ref("runtime_policy_id")}
	c.RuleBundleVersion, c.RuleBundleChecksum = ref("rule_bundle_version"), ref("rule_bundle_checksum")
	for _, id := range []string{c.ModelProfileID, c.PromptVersionID, c.ToolPolicyID, c.MemoryPolicyID, c.KnowledgePolicyID, c.RuntimePolicyID} {
		if id == "" || len(id) > 128 {
			return denied()
		}
	}
	if verifyToken(m.publicKey, m.issuer, m.audience, c) != nil {
		return denied()
	}
	digest, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil {
		return denied()
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	var claims struct {
		BodyHash   string   `json:"body_hash"`
		PolicyHash string   `json:"policy_snapshot_hash"`
		Actions    []string `json:"actions"`
	}
	if err != nil || json.Unmarshal(claimBytes, &claims) != nil || claims.BodyHash != digest || claims.PolicyHash != ref("content_hash") || len(claims.Actions) != 1 || claims.Actions[0] != command.Operation {
		return denied()
	}
	input, _ := json.Marshal(map[string]string{"index_task_body_hash": digest})
	body, err := json.Marshal(envelope{Context: c, Input: input})
	if err != nil || len(body) > maxBody {
		return denied()
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "/internal/model/embed", bytes.NewReader(body))
	if err != nil {
		return denied()
	}
	mac := hmac.New(sha256.New, []byte(m.signingSecret))
	_, _ = mac.Write(requestSignaturePayload(r.Method, r.URL.RequestURI(), body))
	r.Header.Set("X-Internal-Token", m.internalToken)
	r.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
	r.Header.Set("X-Platform-Context", "Bearer "+token)
	r.Header.Set("X-Agent-Client-ID", credential.ClientID)
	r.Header.Set("X-Agent-Client-Secret", credential.Secret)
	// This is a same-process call. The credential must explicitly allow the
	// platform's loopback peer; no operator CIDR restrictions are bypassed.
	r.RemoteAddr = "127.0.0.1:0"
	return r, nil
}
