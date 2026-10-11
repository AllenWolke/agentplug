// Package main is an isolated integration fixture for platform-controlled
// process recovery. It is never registered by development/demo bootstrap.
package main

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

const fixtureID = "checkpoint-recovery-fixture"

//go:embed manifest.json
var manifest json.RawMessage

func recoverBusiness(ctx context.Context, _ agentplatform.ExecuteRequest) (map[string]any, error) {
	client, ok := agentplatform.CapabilityFromContext(ctx)
	if !ok {
		return nil, &agentplatform.AppError{Code: "CAPABILITY_MISSING", Message: "platform client is required"}
	}
	const schema = "schema://checkpoint-recovery/state/v1"
	loaded, err := client.LoadCheckpoint(ctx, "recovery", "business", schema, 0)
	if err != nil {
		return nil, err
	}
	if err := agentplatform.ValidateRuntimeRecoveryCheckpoint(ctx, "recovery", "business", schema, loaded); err != nil {
		return nil, err
	}
	if loaded["checkpoint"] == nil {
		// Use a genuine approved public tool and its durable invocation receipt.
		// Recovery must consume the checkpoint instead of executing this again.
		tool, err := client.Post(ctx, "/internal/tool/invoke", map[string]any{"name": "runtime.inspect", "call_id": "recovery-inspect", "payload": map[string]any{}, "confirmed": false})
		if err != nil {
			return nil, err
		}
		_, err = client.SaveCheckpoint(ctx, "recovery", "business", schema, "effect-recorded", 0, map[string]any{"phase": "effect_recorded", "tool_result": tool, "sequence": json.Number("9007199254740993")})
		if err != nil {
			return nil, err
		}
		// The integration controller must stop this actual process and provide
		// generation-bound stop evidence before another worker may recover it.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	checkpoint, ok := loaded["checkpoint"].(map[string]any)
	if !ok {
		return nil, &agentplatform.AppError{Code: "STATE_INVALID", Message: "checkpoint object is missing"}
	}
	value, ok := checkpoint["value"].(map[string]any)
	if !ok || value["phase"] != "effect_recorded" || value["sequence"] != json.Number("9007199254740993") {
		return nil, &agentplatform.AppError{Code: "STATE_INVALID", Message: "checkpoint content or precision does not match"}
	}
	revision, ok := checkpoint["revision"].(json.Number)
	if !ok {
		return nil, &agentplatform.AppError{Code: "STATE_INVALID", Message: "checkpoint revision is missing"}
	}
	version, err := revision.Int64()
	if err != nil || version != 1 {
		return nil, &agentplatform.AppError{Code: "STATE_INVALID", Message: "unexpected checkpoint revision"}
	}
	_, err = client.SaveCheckpoint(ctx, "recovery", "business", schema, "recovery-completed", uint64(version), map[string]any{"phase": "recovered", "sequence": value["sequence"], "tool_result": value["tool_result"]})
	if err != nil {
		return nil, err
	}
	if err := client.CompleteRuntimeRecoveryStep(ctx, "recovery", "business", schema); err != nil {
		return nil, err
	}
	return map[string]any{"status": "recovered", "checkpoint_revision": 2, "sequence": "9007199254740993", "tool_reexecuted": false}, nil
}

func selectRecoveryCheckpoints(_ agentplatform.ExecuteRequest, _ []agentplatform.RecoveryCheckpointSnapshot, group map[string]any) (agentplatform.RecoveryPlan, error) {
	if group != nil {
		return agentplatform.RecoveryPlan{}, agentplatform.ErrInvalidTransition
	}
	return agentplatform.RecoveryPlan{Steps: []agentplatform.RecoveryCheckpointStep{{
		Namespace: "recovery", Key: "business", SchemaID: "schema://checkpoint-recovery/state/v1",
		ValidateCheckpoint: func(_ agentplatform.ExecuteRequest, checkpoint map[string]any) error {
			value, ok := checkpoint["value"].(map[string]any)
			if !ok || value["sequence"] != json.Number("9007199254740993") {
				return agentplatform.ErrInvalidTransition
			}
			phase, ok := value["phase"].(string)
			revision, revisionOK := checkpoint["revision"].(json.Number)
			_, toolOK := value["tool_result"].(map[string]any)
			if !ok || !revisionOK || !toolOK || (phase != "effect_recorded" || revision != "1") &&
				(phase != "recovered" || revision != "2") {
				return agentplatform.ErrInvalidTransition
			}
			return nil
		},
		IsComplete: func(value map[string]any) bool { return value["phase"] == "recovered" },
	}}}, nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		log.Fatal("fixture public verification material is required")
	}
	config, err := agentplatform.CapabilityConfigFromEnv()
	if err != nil || config == nil || config.WorkloadClientID == "" {
		log.Fatal("fixture workload capability wiring is required")
	}
	server, err := agentplatform.NewExecutionServer(agentplatform.ServerConfig{PublicKey: ed25519.PublicKey(raw), Issuer: "platform", Audience: "agent-runtime", AgentID: fixtureID, AgentVersion: "1.0.0", Manifest: manifest, Capabilities: []string{"invoke", "run", "resume", "cancel", "events"}, Store: agentplatform.NewMemoryRunStore(), Capability: config, RecoveryCheckpointSelector: selectRecoveryCheckpoints, Invoke: recoverBusiness, Run: func(ctx context.Context, request agentplatform.ExecuteRequest, _ agentplatform.EventSink, _ <-chan struct{}) (map[string]any, error) {
		return recoverBusiness(ctx, request)
	}})
	if err != nil {
		log.Fatal("fixture execution contract is invalid")
	}
	address := os.Getenv("AGENT_HTTP_ADDR")
	if address == "" {
		log.Fatal("fixture bind address is required")
	}
	if err := server.ListenAndServe(ctx, address); err != nil {
		log.Fatal("fixture stopped")
	}
}
