package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"github.com/lexagent/grpc-mapping-adapter/internal/descriptor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
)

const (
	maxBody         = 8 << 20
	protocolVersion = "agent-execution/v2"
	codecName       = "json"
)

type jsonCodec struct{}

func (jsonCodec) Name() string                      { return codecName }
func (jsonCodec) Marshal(value any) ([]byte, error) { return json.Marshal(value) }
func (jsonCodec) Unmarshal(data []byte, value any) error {
	return json.Unmarshal(data, value)
}

type adapter struct {
	desc   descriptor.Descriptor
	key    ed25519.PublicKey
	issuer string
	conn   *grpc.ClientConn
	now    func() time.Time
}

func main() {
	development := strings.EqualFold(os.Getenv("APP_ENV"), "development")
	descriptorPath := strings.TrimSpace(os.Getenv("ADAPTER_DESCRIPTOR"))
	if descriptorPath == "" {
		log.Fatal("ADAPTER_DESCRIPTOR is required")
	}
	desc, err := descriptor.Load(descriptorPath)
	if err != nil {
		log.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("PLATFORM_CONTEXT_PUBLIC_KEY"))
	if err != nil || len(key) != ed25519.PublicKeySize {
		log.Fatal("PLATFORM_CONTEXT_PUBLIC_KEY is required")
	}
	encoding.RegisterCodec(jsonCodec{})
	conn, err := dial(strings.TrimSpace(os.Getenv("GRPC_UPSTREAM_ADDRESS")), development)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	a := &adapter{desc: desc, key: ed25519.PublicKey(key), issuer: os.Getenv("PLATFORM_CONTEXT_ISSUER"), conn: conn, now: func() time.Time { return time.Now().UTC() }}
	server := &http.Server{Addr: ":" + env("PORT", "8080"), Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func dial(address string, development bool) (*grpc.ClientConn, error) {
	if address == "" || strings.Contains(address, "..") {
		return nil, errors.New("GRPC_UPSTREAM_ADDRESS must be pre-registered")
	}
	options := []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.CallContentSubtype(codecName))}
	if development {
		options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	}
	return grpc.NewClient(address, options...)
}

func (a *adapter) routes() *http.ServeMux {
	handler := http.NewServeMux()
	handler.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) { write(w, 200, map[string]string{"status": "ready"}) })
	handler.HandleFunc("/.well-known/agent-manifest.json", a.manifest)
	handler.HandleFunc("/internal/agent-execution/v2/invoke", a.invoke)
	return handler
}

func (a *adapter) manifest(w http.ResponseWriter, _ *http.Request) {
	id := os.Getenv("AGENT_ID")
	if id == "" {
		id = "grpc-agent"
	}
	write(w, 200, map[string]any{"manifest_version": "agent-manifest/v1", "agent_id": id, "version": "1.0.0", "execution_protocols": []string{protocolVersion}, "capabilities": []string{"invoke"}, "schemas": map[string]string{"input": "schema://" + id + "/input/v1", "output": "schema://" + id + "/output/v1", "event": "schema://" + id + "/event/v1", "checkpoint": "schema://" + id + "/checkpoint/v1"}, "runtime": map[string]string{"transport": "grpc", "isolation": "container", "health_path": "/health/ready"}})
}

func (a *adapter) invoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		http.Error(w, "invalid body", 400)
		return
	}
	var input agentplatform.ExecuteRequest
	if json.Unmarshal(raw, &input) != nil || input.ProtocolVersion != protocolVersion || input.Operation != "invoke" || input.Scope.RunID == "" {
		http.Error(w, "invalid execution contract", 422)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == r.Header.Get("Authorization") || bearer != input.ContextToken {
		http.Error(w, "capability required", 401)
		return
	}
	if _, err := agentplatform.VerifyContext(input, a.key, a.issuer, "agent-runtime", a.now()); err != nil {
		http.Error(w, "invalid capability", 401)
		return
	}
	planHash, ok := mappingPlanHash(input.Input["mapping_plan"])
	if !ok || planHash != a.desc.MappingHash {
		http.Error(w, "invalid immutable mapping plan", 422)
		return
	}
	var output map[string]any
	if err := a.conn.Invoke(r.Context(), "/"+a.desc.Service+"/"+a.desc.Method, withoutMappingPlan(input.Input), &output); err != nil {
		http.Error(w, "upstream Agent unavailable", 502)
		return
	}
	write(w, 200, map[string]any{"protocol_version": protocolVersion, "run_id": input.Scope.RunID, "status": "succeeded", "output_schema": "schema://" + a.desc.AdapterID + "/output/v1", "output": output})
}

func mappingPlanHash(raw any) (string, bool) {
	plan, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	hash, ok := plan["hash"].(string)
	if !ok || hash == "" {
		return "", false
	}
	return hash, true
}

func withoutMappingPlan(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		if key != "mapping_plan" {
			output[key] = value
		}
	}
	return output
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
