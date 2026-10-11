// Package service provides optional, explicitly registered grader/fixture
// Agents in the independent tool image. The default CLI starts neither server.
package service

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

//go:embed fixture.manifest.json
var fixtureManifest []byte

//go:embed judge.manifest.json
var judgeManifest []byte

//go:embed *.schema.json
var registrationSchemas embed.FS

// RegistrationFiles exports exactly the schemas used by the independently
// deployed service. Publishing, approval, installation and workload binding
// still go through the platform and are never performed by this command.
func RegistrationFiles(mode string) (map[string][]byte, error) {
	manifest, err := Manifest(mode)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"manifest.json": manifest}
	for _, kind := range []string{"input", "output"} {
		b, e := registrationSchemas.ReadFile(mode + "." + kind + ".schema.json")
		if e != nil {
			return nil, errors.New("evaluation registration schema unavailable")
		}
		files[kind+".schema.json"] = b
	}
	return files, nil
}

func Manifest(mode string) ([]byte, error) {
	switch mode {
	case "fixture":
		return append([]byte(nil), fixtureManifest...), nil
	case "judge":
		return append([]byte(nil), judgeManifest...), nil
	default:
		return nil, errors.New("unsupported evaluation service")
	}
}

func Serve(ctx context.Context, mode, address string) error {
	key, e := verificationKey()
	if e != nil {
		return e
	}
	capabilities, e := agentplatform.CapabilityConfigFromEnv()
	if e != nil || capabilities == nil || capabilities.WorkloadClientID == "" {
		return errors.New("registered platform workload wiring is required; no provider credential is accepted")
	}
	issuer, audience := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_ISSUER")), strings.TrimSpace(os.Getenv("AGENT_PLATFORM_AUDIENCE"))
	if issuer == "" {
		issuer = "platform"
	}
	if audience == "" {
		audience = "agent-runtime"
	}
	server, e := executionServer(mode, key, capabilities, issuer, audience)
	if e != nil {
		return e
	}
	return server.ListenAndServe(ctx, address)
}

func executionServer(mode string, key ed25519.PublicKey, capabilities *agentplatform.CapabilityConfig, issuer, audience string) (*agentplatform.ExecutionServer, error) {
	var id string
	var manifest []byte
	var invoke func(context.Context, agentplatform.ExecuteRequest) (map[string]any, error)
	switch mode {
	case "fixture":
		id = "agent-eval-simulation"
		manifest = fixtureManifest
		invoke = invokeFixture
	case "judge":
		id = "agent-eval-judge"
		manifest = judgeManifest
		invoke = invokeJudge
	default:
		return nil, errors.New("unsupported evaluation service")
	}
	var published struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(manifest, &published) != nil || published.Version == "" {
		return nil, errors.New("invalid evaluation service manifest")
	}
	server, e := agentplatform.NewExecutionServer(agentplatform.ServerConfig{PublicKey: key, Issuer: issuer, Audience: audience, AgentID: id, AgentVersion: published.Version, Manifest: manifest, Capabilities: []string{"invoke", "run", "resume", "cancel", "events"}, Store: agentplatform.NewMemoryRunStore(), Capability: capabilities, Invoke: invoke, Run: func(ctx context.Context, r agentplatform.ExecuteRequest, _ agentplatform.EventSink, cancelled <-chan struct{}) (map[string]any, error) {
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		go func() {
			select {
			case <-ctx.Done():
			case <-cancelled:
				stop()
			}
		}()
		return invoke(ctx, r)
	}})
	if e != nil {
		return nil, errors.New("evaluation service execution contract is invalid")
	}
	return server, nil
}

func verificationKey() (ed25519.PublicKey, error) {
	value := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64"))
	if file := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_PUBLIC_KEY_FILE")); file != "" {
		b, e := os.ReadFile(file)
		if e != nil {
			return nil, errors.New("public verification file unavailable")
		}
		value = strings.TrimSpace(string(b))
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding} {
		if b, e := encoding.DecodeString(value); e == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New("platform public verification material is required")
}

type port interface {
	Post(context.Context, string, map[string]any) (map[string]any, error)
	ValidateCurrentExecution(context.Context) error
}

func invokeFixture(ctx context.Context, r agentplatform.ExecuteRequest) (map[string]any, error) {
	c, ok := agentplatform.CapabilityFromContext(ctx)
	if !ok {
		return nil, errors.New("verified platform capability required")
	}
	return runFixture(ctx, r, c)
}
func invokeJudge(ctx context.Context, r agentplatform.ExecuteRequest) (map[string]any, error) {
	c, ok := agentplatform.CapabilityFromContext(ctx)
	if !ok {
		return nil, errors.New("verified platform capability required")
	}
	return runJudge(ctx, r, c)
}
