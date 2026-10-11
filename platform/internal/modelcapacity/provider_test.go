package modelcapacity

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestParseCapacityUnitsRequiresBoundedPositiveLimit(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		want int64
		bad  bool
	}{
		{name: "normal", json: `{"max_concurrent_requests":4}`, want: 4},
		{name: "allows resource dimensions", json: `{"max_concurrent_requests":8,"gpu_memory_mb":24000}`, want: 8},
		{name: "missing", json: `{}`, bad: true},
		{name: "zero", json: `{"max_concurrent_requests":0}`, bad: true},
		{name: "negative", json: `{"max_concurrent_requests":-1}`, bad: true},
		{name: "unbounded", json: `{"max_concurrent_requests":1000001}`, bad: true},
		{name: "malformed", json: `{"max_concurrent_requests":`, bad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseCapacityUnits(json.RawMessage(test.json))
			if test.bad {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("invalid capacity accepted: got=%d err=%v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("capacity=%d err=%v want=%d", got, err, test.want)
			}
		})
	}
}

func TestRequestRequiresTrustedScopeAndBoundedLease(t *testing.T) {
	request := Request{
		Scope:        sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentInstanceID: "install-a", AgentID: "agent-a", PrincipalID: "user-a", PrincipalType: "user", InstallationID: "install-a", AgentVersionID: "version-a", SessionID: "session-a", RunID: "run-a", AuthorizationEpoch: 1, TraceID: "trace-a"},
		DeploymentID: "deployment-a", Units: 1, Owner: "user-a", RequestID: "request-a", TTL: time.Minute,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid capacity request rejected: %v", err)
	}
	request.Scope.TenantID = ""
	if !errors.Is(request.Validate(), ErrInvalid) {
		t.Fatal("untrusted/incomplete scope accepted")
	}
	request.Scope.TenantID = "tenant-a"
	request.TTL = 11 * time.Minute
	if !errors.Is(request.Validate(), ErrInvalid) {
		t.Fatal("unbounded capacity lease accepted")
	}
}

func TestDeploymentHealthAdmissionStates(t *testing.T) {
	for _, test := range []struct {
		health, status string
		accepts        bool
	}{
		{"unknown", "pending", false}, {"warming", "pending", false},
		{"ready", "ready", true}, {"degraded", "ready", true},
		{"unavailable", "failed", false}, {"draining", "draining", false},
	} {
		if got := accepting(test.health, test.status); got != test.accepts {
			t.Errorf("accepting(%q,%q)=%v want %v", test.health, test.status, got, test.accepts)
		}
		if !validState(test.health, test.status) {
			t.Errorf("valid state rejected: %s/%s", test.health, test.status)
		}
	}
}
