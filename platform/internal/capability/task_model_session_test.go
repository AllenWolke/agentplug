package capability

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestTaskEmbeddingSessionVerifiesScopeGrantAndLifetime(t *testing.T) {
	for _, mode := range []string{"allowed", "foreign-run", "bad-signature", "expired", "resource-denied", "revoked-after-open", "closed", "parent-canceled", "wrong-route", "unsigned-module"} {
		t.Run(mode, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			resolver := governedInvocationResolver()
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			resolver.snapshot.Model.EmbeddingModelVersionID = "embedding-version"
			resolver.snapshot.Model.EmbeddingProvider = "embedding-provider"
			resolver.snapshot.Model.EmbeddingModel = "embedding-model"
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			if mode == "unsigned-module" {
				m.publicKey = nil
			}
			authority := &resourceAuthorityFixture{}
			m.SetLiveExecutionAuthority(authority)
			gateway := &cacheCheckUsageGateway{}
			resolved := 0
			m.SetGovernedModelInvocation(modelAccessResolverFunc(func(context.Context, sharedkernel.Scope, string) (modelgateway.Selection, error) {
				resolved++
				return modelgateway.Selection{ModelVersionID: "embedding-version", ProviderID: "embedding-provider-id", ProviderKey: "embedding-provider", ModelID: "embedding-model-id", ModelKey: "embedding-model", TrustZone: modelgovernance.TrustLocal}, nil
			}), gateway)
			c := capabilityContext()
			expires := time.Now().Unix() + 120
			if mode == "expired" {
				expires = time.Now().Unix() - 1
			}
			c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-10, expires)
			body, err := json.Marshal(envelope{Context: c, Input: json.RawMessage(`{"task_binding":"immutable-index-job"}`)})
			if err != nil {
				t.Fatal(err)
			}
			path := "/internal/model/embed"
			if mode == "wrong-route" {
				path = "/internal/model/generate"
			}
			parentCtx, parentCancel := context.WithCancel(context.Background())
			defer parentCancel()
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(parentCtx)
			r.Header.Set("X-Internal-Token", m.internalToken)
			r.Header.Set("X-Platform-Context", "Bearer "+c.PlatformContextToken)
			mac := hmac.New(sha256.New, []byte(m.signingSecret))
			mac.Write(requestSignaturePayload(http.MethodPost, path, body))
			r.Header.Set("X-Context-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
			if mode == "bad-signature" {
				r.Header.Set("X-Context-Signature", "invalid")
			}
			expected := sharedkernel.Scope{TenantID: c.TenantID, DepartmentID: c.DepartmentID, ApplicationID: c.ApplicationID, AgentID: c.AgentID, AgentInstanceID: c.AgentInstanceID, InstallationID: c.InstallationID, AgentVersionID: c.AgentVersionID, PrincipalID: c.ActorID, PrincipalType: c.PrincipalType, SessionID: c.SessionID, RunID: c.TaskID, TraceID: c.TraceID, AuthorizationEpoch: c.AuthorizationEpoch}
			if mode == "foreign-run" {
				expected.RunID = "foreign"
			}
			if mode == "resource-denied" {
				authority.denied = true
			}
			session, err := m.OpenTaskEmbeddingSession(context.Background(), r, expected)
			if mode == "foreign-run" || mode == "bad-signature" || mode == "expired" || mode == "resource-denied" || mode == "wrong-route" || mode == "unsigned-module" {
				if err == nil || session.Call != nil || gateway.calls != 0 {
					t.Fatal("invalid session admitted", err)
				}
				if mode == "expired" || mode == "resource-denied" {
					var admission *KnowledgeModelError
					want := "CONTEXT_EXPIRED"
					if mode == "resource-denied" {
						want = "RESOURCE_AUTHORITY"
					}
					if !errors.As(err, &admission) || admission.Code != "CAPABILITY_DENIED" || admission.DiagnosticCode != want {
						t.Fatal("admission stage missing or public code changed", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal("valid session rejected", err)
			}
			defer session.Close()
			if session.Scope != expected || resolved != 1 || gateway.calls != 0 || authority.access.Action != "model.embed" {
				t.Fatal("opening changed scope or sent model")
			}
			// Returned policy metadata cannot mutate the pinned private envelope.
			session.Policy.Model.EmbeddingModelVersionID = "forged"
			if mode == "revoked-after-open" {
				authority.denied = true
			}
			if mode == "closed" {
				session.Close()
				session.Close()
			}
			if mode == "parent-canceled" {
				parentCancel()
				time.Sleep(10 * time.Millisecond)
			}
			err = session.Check(context.Background(), "embed")
			if mode == "allowed" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("stale session continued", mode)
			}
			if mode == "closed" || mode == "parent-canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("lifetime not enforced", err)
				}
			}
			if _, err := session.Call(context.Background(), "generate", map[string]any{}); err == nil {
				t.Fatal("embedding session reached chat")
			}
			if mode != "allowed" {
				if _, err := session.Call(context.Background(), "embed", map[string]any{"texts": []string{"secret"}}); err == nil {
					t.Fatal("invalid session called embedding")
				}
			}
			if gateway.calls != 0 {
				t.Fatal("session boundary sent model")
			}
		})
	}
}
