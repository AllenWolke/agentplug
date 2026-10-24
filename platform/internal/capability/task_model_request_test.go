package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestTaskEmbeddingRequestBindsSignedCanonicalCommand(t *testing.T) {
	for _, mode := range []string{"allowed", "allowed-rule-bundle", "allowed-nested-rule-bundle", "changed-rule-bundle", "changed-input", "changed-scope", "changed-policy", "changed-operation", "invalid-secret", "missing-credential", "expired", "retained-token"} {
		t.Run(mode, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", AgentInstanceID: "instance", InstallationID: "install", AgentVersionID: "v1", PrincipalID: "user", PrincipalType: "user", SessionID: "session", RunID: "run", TraceID: strings.Repeat("b", 32), AuthorizationEpoch: 1}
			request := contract.ExecuteRequest{ProtocolVersion: "agent-execution/v2", Operation: "invoke", InputSchema: "knowledge-index/v1", IdempotencyKey: "index", Scope: contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentID: scope.AgentID, AgentInstanceID: scope.AgentInstanceID, InstallationID: scope.InstallationID, AgentVersionID: scope.AgentVersionID, PrincipalID: scope.PrincipalID, PrincipalType: scope.PrincipalType, SessionID: scope.SessionID, RunID: scope.RunID, TraceID: scope.TraceID, AuthorizationEpoch: scope.AuthorizationEpoch}, Input: map[string]any{"knowledge_id": "docs", "policy_snapshot": map[string]any{"content_hash": strings.Repeat("b", 64), "model_profile_id": "model", "prompt_version_id": "prompt", "tool_policy_id": "tools", "memory_policy_id": "memory", "knowledge_policy_id": "knowledge", "runtime_policy_id": "runtime"}}}
			signer := conversation.Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime", TTL: time.Minute}
			if mode == "allowed-rule-bundle" || mode == "changed-rule-bundle" {
				policy := request.Input["policy_snapshot"].(map[string]any)
				policy["rule_bundle_version"] = "0.2.0"
				policy["rule_bundle_checksum"] = strings.Repeat("d", 64)
			}
			if mode == "expired" {
				signer.Clock = func() time.Time { return time.Now().Add(-5 * time.Minute) }
			}
			if mode == "allowed-nested-rule-bundle" {
				request.Input["policy_snapshot"].(map[string]any)["rule_bundle"] = map[string]any{"version": "0.4.0", "checksum": strings.Repeat("d", 64)}
			}
			token, err := signer.Sign(sharedkernel.BindExecutionLease(context.Background(), 4, "private-lease-token"), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			credential := TaskWorkloadCredential{ClientID: "fixture-client", Secret: "fixture-client-secret"}
			switch mode {
			case "changed-rule-bundle":
				request.Input["policy_snapshot"].(map[string]any)["rule_bundle_version"] = "foreign"
			case "changed-input":
				request.Input["knowledge_id"] = "foreign"
			case "changed-scope":
				request.Scope.RunID = "foreign"
			case "changed-policy":
				request.Input["policy_snapshot"].(map[string]any)["content_hash"] = strings.Repeat("c", 64)
			case "changed-operation":
				request.Operation = "run"
			case "invalid-secret":
				credential.Secret = "header\r\ninjection"
			case "missing-credential":
				credential = TaskWorkloadCredential{}
			case "retained-token":
				request.ContextToken = token
			}
			module := NewModule("internal-token", "signing-secret", public, "platform", "agent-runtime")
			r, err := module.BuildTaskEmbeddingRequest(context.Background(), request, token, credential)
			if mode != "allowed" && mode != "allowed-rule-bundle" && mode != "allowed-nested-rule-bundle" {
				if err == nil || r != nil {
					t.Fatal("changed or stale command accepted", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "allowed-nested-rule-bundle" {
				var decoded envelope
				if json.Unmarshal(body, &decoded) != nil || decoded.Context.RuleBundleVersion != "0.4.0" || decoded.Context.RuleBundleChecksum != strings.Repeat("d", 64) {
					t.Fatal("nested published rule binding was lost")
				}
			}
			var wire envelope
			if json.Unmarshal(body, &wire) != nil || wire.Context.TaskID != scope.RunID || wire.Context.ModelProfileID != "model" {
				t.Fatal("incorrect capability context")
			}
			if mode == "allowed-rule-bundle" && (wire.Context.RuleBundleVersion != "0.2.0" || wire.Context.RuleBundleChecksum != strings.Repeat("d", 64)) {
				t.Fatal("signed published rule binding was omitted")
			}
			mac := hmac.New(sha256.New, []byte(module.signingSecret))
			mac.Write(requestSignaturePayload(r.Method, r.URL.RequestURI(), body))
			if r.Header.Get("X-Context-Signature") != fmt.Sprintf("sha256=%x", mac.Sum(nil)) || r.Header.Get("X-Agent-Client-ID") != credential.ClientID || r.Header.Get("X-Agent-Client-Secret") != credential.Secret || r.RemoteAddr != "127.0.0.1:0" {
				t.Fatal("request framing or workload credential changed")
			}
			serialized, _ := json.Marshal(credential)
			if string(serialized) != "{}" || strings.Contains(string(body), credential.Secret) || strings.Contains(string(body), "private-lease-token") {
				t.Fatal("secret serialized into command")
			}
		})
	}
}
