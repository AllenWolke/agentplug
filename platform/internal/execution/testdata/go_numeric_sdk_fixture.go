// A real SDK receiver for platform-signed HTTP numeric conformance tests.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"

	sdk "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

func main() {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("FIXTURE_PUBLIC_KEY"))
	if err != nil {
		panic("invalid fixture public key")
	}
	server, err := sdk.NewExecutionServer(sdk.ServerConfig{
		PublicKey: ed25519.PublicKey(key), Issuer: "numeric-platform", Audience: "numeric-sdk",
		AgentID: os.Getenv("FIXTURE_AGENT_ID"), Store: sdk.NewMemoryRunStore(), Capabilities: []string{"invoke"},
		Invoke: func(_ context.Context, request sdk.ExecuteRequest) (map[string]any, error) {
			evidence := request.Input["numeric_evidence"].(map[string]any)
			return map[string]any{"coverage_literal": evidence["coverage"].(json.Number).String(), "source_id_literal": evidence["source_id"].(json.Number).String()}, nil
		},
	})
	if err != nil {
		panic("invalid fixture server configuration")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("fixture socket unavailable")
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"url": "http://" + listener.Addr().String()})
	if http.Serve(listener, server.Handler()) != nil {
		os.Exit(1)
	}
}
