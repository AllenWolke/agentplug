package contract

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

const executionV2Golden = `{"protocol_version":"agent-execution/v2","context_token":"fixture.context.token.with.more.than.thirty.two.characters","scope":{"tenant_id":"tenant-a","department_id":"compliance","application_id":"business-app","agent_instance_id":"validation-installation","agent_id":"example-agent","agent_version_id":"version-2","principal_type":"user","principal_id":"user-a","session_id":"session-a","run_id":"run-a","authorization_epoch":3,"trace_id":"0123456789abcdef0123456789abcdef","parent_run_id":"","delegation_depth":0,"installation_id":"validation-installation"},"operation":"run","idempotency_key":"fixture-idempotency-key","input_schema":"schema://example-agent/run/v1","input":{"batch_id":"batch-a","report_type":"1104"}}`

func TestExecutionV2GoldenFixture(t *testing.T) {
	var request ExecuteRequest
	_, currentFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "contracts", "fixtures", "execution-v2-request.json")
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read execution contract golden fixture: %v", err)
	}
	if err := json.Unmarshal(fixture, &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("golden request rejected: %v", err)
	}
	var got, want map[string]any
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	// Normalize only the transport's optional zero-value fields.
	// 仅归一化传输契约的可选零值字段。
	if scope, ok := want["scope"].(map[string]any); ok {
		delete(scope, "parent_run_id")
		delete(scope, "delegation_depth")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire contract changed: got=%s want=%s", encoded, fixture)
	}
}

func TestExecutionV2RejectsBadScopeAndProtocol(t *testing.T) {
	request := ExecuteRequest{ProtocolVersion: "agent-execution/v1"}
	if !errors.Is(request.Validate(), ErrProtocolNotSupported) {
		t.Fatal("expected protocol error")
	}
	request.ProtocolVersion = ProtocolVersion
	request.ContextToken = "12345678901234567890123456789012"
	request.Scope.PrincipalType = "service"
	if !errors.Is(request.Validate(), ErrSchemaValidation) {
		t.Fatal("expected scope schema error")
	}
}

func TestStableErrorCode(t *testing.T) {
	if code := ErrorCode(ErrRevisionConflict); code != "REVISION_CONFLICT" {
		t.Fatalf("unexpected code %s", code)
	}
	if code := ErrorCode(errors.New("unknown")); code != "INTERNAL_ERROR" {
		t.Fatalf("unexpected fallback code %s", code)
	}
}
