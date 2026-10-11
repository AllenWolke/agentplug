package capability

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestCheckpointRecoveryKeyKeepsIdentityAndVersionBoundary(t *testing.T) {
	scope := mcpTestScope()
	prefix, key, err := stateKeys(scope, "harness", "loop")
	if err != nil {
		t.Fatal(err)
	}
	recovered := scope
	recovered.AuthorizationEpoch++
	recovered.TraceID = "recovery-trace"
	p2, k2, err := stateKeys(recovered, "harness", "loop")
	if err != nil || prefix != p2 || key != k2 {
		t.Fatal("same run must recover its checkpoint under renewed authority")
	}
	changes := map[string]func(*sharedkernel.Scope){
		"tenant":         func(s *sharedkernel.Scope) { s.TenantID += "2" },
		"department":     func(s *sharedkernel.Scope) { s.DepartmentID += "2" },
		"app":            func(s *sharedkernel.Scope) { s.ApplicationID += "2" },
		"user":           func(s *sharedkernel.Scope) { s.PrincipalID += "2" },
		"principal type": func(s *sharedkernel.Scope) { s.PrincipalType = "service_principal" },
		"agent":          func(s *sharedkernel.Scope) { s.AgentID += "2" },
		"instance":       func(s *sharedkernel.Scope) { s.AgentInstanceID += "2" },
		"installation":   func(s *sharedkernel.Scope) { s.InstallationID += "2" },
		"version":        func(s *sharedkernel.Scope) { s.AgentVersionID += "2" },
		"session":        func(s *sharedkernel.Scope) { s.SessionID += "2" },
		"run":            func(s *sharedkernel.Scope) { s.RunID += "2" },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			changed := scope
			mutate(&changed)
			p, k, err := stateKeys(changed, "harness", "loop")
			if err != nil || p == prefix || k == key {
				t.Fatalf("checkpoint crossed %s boundary: %v", name, err)
			}
		})
	}
	scope.AuthorizationEpoch = 0
	if _, _, err := stateKeys(scope, "harness", "loop"); !errors.Is(err, ErrStateDenied) {
		t.Fatal("unsigned/incomplete authority must not identify a checkpoint")
	}
}

func TestCheckpointContentHashPreservesLargeNumbersAndSchema(t *testing.T) {
	var value map[string]any
	if err := decodeStateValue([]byte(`{"sequence":9007199254740993,"nested":{"message":"ready"}}`), &value); err != nil {
		t.Fatal(err)
	}
	if value["sequence"] != json.Number("9007199254740993") {
		t.Fatal("checkpoint decoder lost integer precision")
	}
	hash, err := stateContentHash("schema://example/state/v1", value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(value)
	var restored map[string]any
	if decodeStateValue(encoded, &restored) != nil {
		t.Fatal("checkpoint cannot be restored")
	}
	restoredHash, _ := stateContentHash("schema://example/state/v1", restored)
	if hash != restoredHash {
		t.Fatal("immutable checkpoint hash changed on restore")
	}
	otherSchema, _ := stateContentHash("schema://example/state/v2", restored)
	if hash == otherSchema {
		t.Fatal("schema version was excluded from content identity")
	}
	restored["sequence"] = json.Number("9007199254740992")
	tamperedHash, _ := stateContentHash("schema://example/state/v1", restored)
	if hash == tamperedHash {
		t.Fatal("distinct large integers have the same content identity")
	}
}

func TestCheckpointRejectsUnboundedOrAmbiguousDocuments(t *testing.T) {
	for _, document := range []string{`null`, `[]`, `{"a":1} {"b":2}`, `{"a":1} broken`} {
		var decoded map[string]any
		if decodeStateValue([]byte(document), &decoded) == nil {
			t.Fatalf("accepted invalid checkpoint document: %s", document)
		}
	}
	for _, schema := range []string{"schema://", "schema://state v1", "schema://state\tv1", "schema://state*", "https://state/v1"} {
		if _, err := stateContentHash(schema, map[string]any{}); !errors.Is(err, ErrStateSchema) {
			t.Fatal("invalid schema was accepted")
		}
	}
	if _, err := stateContentHash("schema://state/v1", map[string]any{"value": strings.Repeat("x", 256<<10)}); !errors.Is(err, ErrStateLimit) {
		t.Fatal("oversized checkpoint was accepted")
	}
}
