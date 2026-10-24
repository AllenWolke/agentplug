package execution

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestPlatformSignatureAcceptedByNativeGoSDKWithNumericEvidence(t *testing.T) {
	fixture := os.Getenv("SDK_GO_NUMERIC_FIXTURE")
	if fixture == "" {
		t.Skip("compiled actual Go SDK receiver required")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope("native-numeric-signature").domain()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, fixture)
	command.Env = append(os.Environ(), "FIXTURE_PUBLIC_KEY="+base64.StdEncoding.EncodeToString(public), "FIXTURE_AGENT_ID="+scope.AgentID)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("native SDK did not publish its socket")
	}
	var address struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(scanner.Bytes(), &address) != nil || address.URL == "" {
		t.Fatal("invalid native SDK socket")
	}
	var request contract.ExecuteRequest
	if err := contract.DecodeJSONPreservingNumbers(gatewayRequest(t, testScope(scope.RunID), "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	request.ContextToken = ""
	request.Input["numeric_evidence"] = map[string]any{"coverage": json.Number("1.0"), "source_id": json.Number("9007199254740993")}
	signer := conversation.Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "numeric-platform", Audience: "numeric-sdk", TTL: time.Minute}
	leaseCtx := sharedkernel.BindExecutionLease(ctx, 2, "numeric-fixture-lease")
	request.ContextToken, err = signer.Sign(leaseCtx, scope, request)
	if err != nil {
		t.Fatal(err)
	}
	gateway := agentgateway.RemoteAdapter{Transport: agentgateway.NewHTTPTransport(&http.Client{Timeout: 5 * time.Second})}
	target := agentgateway.Target{Endpoint: address.URL, Transport: "http", AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, InstallationID: scope.InstallationID, Revision: 1, ManifestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	response, err := gateway.Invoke(ctx, target, request)
	if err != nil || response.Status != "succeeded" || response.Output["coverage_literal"] != "1.0" || response.Output["source_id_literal"] != "9007199254740993" {
		t.Fatalf("actual SDK rejected or changed platform-signed numeric evidence: status=%s err=%v", response.Status, err)
	}
	request.Input["numeric_evidence"].(map[string]any)["source_id"] = json.Number("9007199254740992")
	_, err = gateway.Invoke(ctx, target, request)
	var rejected contract.AppError
	if !errors.As(err, &rejected) || rejected.Code != "CAPABILITY_INVALID" {
		t.Fatal("numeric source tampering passed actual SDK signature boundary")
	}
}
