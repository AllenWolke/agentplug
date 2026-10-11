// Example Go/Eino Agent Execution v2 service.
// Go/Eino Agent Execution v2 服务示例；HTTP 契约与 Eino 编排解耦。
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	agentplatform "github.com/lexagent/agent-platform-sdk-go/agentplatform"
)

const (
	issuer   = "platform-runtime-gateway"
	audience = "example-go-eino"
)

// server keeps run state behind the transport boundary. Production deployments
// replace this in-memory store with a scoped durable checkpoint store.
// server 将运行状态放在传输边界之后；生产环境应替换为带 Scope 的持久化检查点存储。
type server struct {
	publicKey ed25519.PublicKey
	mu        sync.Mutex
	runs      map[string]string
}

func main() {
	key, err := publicKeyFromEnv()
	if err != nil {
		panic(err)
	}
	port := os.Getenv("AGENT_PORT")
	if port == "" {
		port = "8080"
	}
	if err := http.ListenAndServe(":"+port, newServer(key)); err != nil {
		panic(err)
	}
}

func publicKeyFromEnv() (ed25519.PublicKey, error) {
	encoded := strings.TrimSpace(os.Getenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64"))
	if encoded == "" {
		return nil, errors.New("AGENT_PLATFORM_PUBLIC_KEY_BASE64 is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("AGENT_PLATFORM_PUBLIC_KEY_BASE64 must be a raw Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func newServer(publicKey ed25519.PublicKey) http.Handler {
	s := &server{publicKey: publicKey, runs: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent-manifest.json", s.manifest)
	mux.HandleFunc("/internal/agent-execution/v2/invoke", s.invoke)
	mux.HandleFunc("/internal/agent-execution/v2/runs", s.createRun)
	mux.HandleFunc("/internal/agent-execution/v2/runs/", s.runOperation)
	return mux
}

func (s *server) manifest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest_version":    "agent-manifest/v1",
		"agent_id":            "example-go-eino",
		"version":             "2.0.0",
		"execution_protocols": []string{agentplatform.ProtocolVersion},
		"capabilities":        []string{"invoke", "run", "resume", "cancel", "events"},
		"schemas": map[string]string{
			"input": "schema://example-go-eino/input/v1", "output": "schema://example-go-eino/output/v1",
			"event": "schema://agent-platform/event/v1", "checkpoint": "schema://agent-platform/checkpoint/v1",
		},
		"runtime": map[string]string{"transport": "http", "isolation": "container", "health_path": "/health/ready"},
	})
}

func (s *server) invoke(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeExecute(w, r, "invoke")
	if !ok {
		return
	}
	// Eino graph invocation belongs here. / Eino 图调用应位于此处。
	writeJSON(w, http.StatusOK, agentplatform.ExecuteResponse{ProtocolVersion: agentplatform.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded", OutputSchema: "schema://example-go-eino/output/v1", Output: map[string]any{"framework": "eino", "isolated_scope": request.Scope.AgentInstanceID}})
}

func (s *server) createRun(w http.ResponseWriter, r *http.Request) {
	request, ok := s.decodeExecute(w, r, "run")
	if !ok {
		return
	}
	s.mu.Lock()
	s.runs[request.Scope.RunID] = "running"
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, agentplatform.ExecuteResponse{ProtocolVersion: agentplatform.ProtocolVersion, RunID: request.Scope.RunID, Status: "running", OutputSchema: "schema://example-go-eino/output/v1"})
}

func (s *server) runOperation(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/internal/agent-execution/v2/runs/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "RUN_NOT_FOUND", "run path is invalid")
		return
	}
	runID, action := parts[0], parts[1]
	switch action {
	case "resume", "cancel":
		request, ok := s.decodeExecute(w, r, action)
		if !ok {
			return
		}
		if request.Scope.RunID != runID {
			writeError(w, http.StatusConflict, "RUN_SCOPE_MISMATCH", "run_id does not match signed scope")
			return
		}
		s.mu.Lock()
		if _, exists := s.runs[runID]; !exists {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, "RUN_NOT_FOUND", "run does not exist")
			return
		}
		status := "running"
		if action == "cancel" {
			status = "cancelled"
		}
		s.runs[runID] = status
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, agentplatform.ExecuteResponse{ProtocolVersion: agentplatform.ProtocolVersion, RunID: runID, Status: status, OutputSchema: "schema://example-go-eino/output/v1"})
	case "events":
		s.events(w, r, runID)
	default:
		writeError(w, http.StatusNotFound, "RUN_OPERATION_UNKNOWN", "unsupported run operation")
	}
}

func (s *server) events(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "events requires POST")
		return
	}
	var request agentplatform.EventRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if !authorizedBearer(r, request.ContextToken) || request.ProtocolVersion != agentplatform.ProtocolVersion || request.Scope.RunID != runID {
		writeError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "event capability is invalid")
		return
	}
	if _, err := agentplatform.VerifyEventContext(request, s.publicKey, issuer, audience, time.Now().UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "event capability is invalid")
		return
	}
	s.mu.Lock()
	status, exists := s.runs[runID]
	s.mu.Unlock()
	if !exists {
		writeError(w, http.StatusNotFound, "RUN_NOT_FOUND", "run does not exist")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	event := agentplatform.ExecutionEvent{RunID: runID, Seq: request.AfterSeq + 1, EventType: eventType(status), OccurredAt: time.Now().UTC(), Payload: map[string]any{"status": status}}
	payload, _ := json.Marshal(event)
	_, _ = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Seq, event.EventType, payload)
}

func eventType(status string) string {
	if status == "cancelled" {
		return "cancelled"
	}
	return "progress"
}

func (s *server) decodeExecute(w http.ResponseWriter, r *http.Request, action string) (agentplatform.ExecuteRequest, bool) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "operation requires POST")
		return agentplatform.ExecuteRequest{}, false
	}
	var request agentplatform.ExecuteRequest
	if !decodeJSON(w, r, &request) {
		return agentplatform.ExecuteRequest{}, false
	}
	if request.ProtocolVersion != agentplatform.ProtocolVersion || request.Operation != action || !authorizedBearer(r, request.ContextToken) {
		writeError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "execution capability is invalid")
		return agentplatform.ExecuteRequest{}, false
	}
	if _, err := agentplatform.VerifyContext(request, s.publicKey, issuer, audience, time.Now().UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, "CAPABILITY_INVALID", "execution capability is invalid")
		return agentplatform.ExecuteRequest{}, false
	}
	return request, true
}

func authorizedBearer(r *http.Request, token string) bool {
	return r.Header.Get("Authorization") == "Bearer "+token
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "REQUEST_INVALID", "request must be one valid JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, agentplatform.AppError{Code: code, Message: message, Retryable: false})
}
