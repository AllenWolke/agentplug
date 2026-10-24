package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type checkpointCapacityProbe struct {
	loads       int
	write       *StateWrite
	beforeReply func()
}

func (p *checkpointCapacityProbe) Load(_ context.Context, _ sharedkernel.Scope, _, _, _ string, revision uint64) (Checkpoint, bool, error) {
	p.loads++
	if p.beforeReply != nil {
		p.beforeReply()
	}
	return Checkpoint{Revision: revision}, revision != 0, nil
}
func (p *checkpointCapacityProbe) Save(_ context.Context, write StateWrite, _ func(context.Context) error) (Checkpoint, error) {
	p.write = &write
	return Checkpoint{Revision: write.ExpectedRevision + 1}, nil
}

func TestCheckpointCapacityHTTPUsesOnlyPinnedPolicyAndLiveAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "published"}[explicit], func(t *testing.T) {
			resolver := governedInvocationResolver()
			resolver.snapshot.Hash = strings.Repeat("b", 64)
			resolver.snapshot.Memory = policyasset.MemoryPolicy{MaxEntries: 8192, TaskTTLSeconds: 3600}
			if explicit {
				resolver.snapshot.Memory.CheckpointHistory = &policyasset.CheckpointHistoryPolicy{Version: "checkpoint-history/v1", MaxRevisions: 4096}
				resolver.snapshot.Memory.CheckpointAdmission = &policyasset.CheckpointAdmissionPolicy{Version: "checkpoint-admission/v1", Mode: "reserved_quota"}
			}
			m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", public, "platform", "agent-runtime", nil, resolver)
			p := &checkpointCapacityProbe{}
			m.SetCheckpointStore(p)
			revoked := false
			m.SetLiveExecutionAuthority(contextPreparationAuthority{
				testLiveAuthorityFunc: func(context.Context, sharedkernel.Scope, string, string, string) error { return nil },
				resource: func(a CapabilityResourceAccess) error {
					if revoked || a.ResourceType != "memory" || a.ResourceID != "memory-a" {
						return errors.New("denied")
					}
					return nil
				},
			})
			actor := capabilityContext()
			actor.PlatformContextToken = signedContextToken(t, private, actor, time.Now().Unix()-1, time.Now().Unix()+120)
			input := map[string]any{"operation": "load", "namespace": "graph", "key": "main", "schema_id": "schema://fixture/graph/v1", "revision": 65}
			response := capabilityRequest(t, m, "/internal/state/checkpoint", actor, input)
			if !explicit {
				if response.Code != 400 || p.loads != 0 {
					t.Fatal("legacy high revision reached store", response.Code)
				}
			} else if response.Code != 200 || p.loads != 1 {
				t.Fatal("published high revision denied", response.Code, response.Body.String())
			}
			input["revision"] = 0
			response = capabilityRequest(t, m, "/internal/state/checkpoint", actor, input)
			var body struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &body) != nil {
				t.Fatal("load failed", response.Code)
			}
			_, hasMetadata := body.Data["checkpoint_history"]
			if hasMetadata != explicit {
				t.Fatal("legacy shape changed or published negotiation missing")
			}
			write := map[string]any{"operation": "save", "namespace": "graph", "key": "main", "schema_id": "schema://fixture/graph/v1", "expected_revision": 64, "value": map[string]any{}, "idempotency_key": "cross-64"}
			response = capabilityRequest(t, m, "/internal/state/checkpoint", actor, write)
			if explicit {
				if response.Code != 200 || p.write == nil || p.write.MaxRevisions != 4096 || p.write.ExpectedRevision != 64 {
					t.Fatal("capacity not passed to store", response.Code, response.Body.String())
				}
			} else if response.Code != 400 || p.write != nil {
				t.Fatal("legacy write crossed64", response.Code)
			}
			write["expected_revision"] = 0
			response = capabilityRequest(t, m, "/internal/state/checkpoint", actor, write)
			if response.Code != 200 || p.write == nil || p.write.ReservedQuota != explicit {
				t.Fatal("admission did not use pinned policy", response.Code)
			}
			for _, field := range []string{"checkpoint_admission", "reserved_quota"} {
				write[field] = true
				if capabilityRequest(t, m, "/internal/state/checkpoint", actor, write).Code != http.StatusBadRequest {
					t.Fatal("caller spoofed admission", field)
				}
				delete(write, field)
			}
			input["checkpoint_history"] = map[string]any{"version": "checkpoint-history/v1", "max_revisions": 4096}
			if capabilityRequest(t, m, "/internal/state/checkpoint", actor, input).Code != http.StatusBadRequest {
				t.Fatal("caller spoofed capacity")
			}
			delete(input, "checkpoint_history")
			p.beforeReply = func() { revoked = true }
			if capabilityRequest(t, m, "/internal/state/checkpoint", actor, input).Code == 200 {
				t.Fatal("capacity/state disclosed after revocation")
			}
		})
	}
}
