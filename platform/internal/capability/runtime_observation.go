package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const observationVersion = "runtime-observation/v1"
const observationOutputLimit = 64 * 1024
const observationContextLimit = 2048

// Provider output remains untrusted data. Observations never grant permissions.
// Unknown CPU/memory measurements and historical timing are null, not zero.
type runtimeObservation struct {
	Version                string                  `json:"version"`
	RunID                  string                  `json:"run_id"`
	StepID                 string                  `json:"step_id"`
	CallID                 string                  `json:"call_id"`
	ToolName               string                  `json:"tool_name"`
	ExecutionType          string                  `json:"execution_type"`
	TraceID                string                  `json:"trace_id"`
	PermissionScopeHash    string                  `json:"permission_scope_hash"`
	PermissionScope        *RuntimePermissionScope `json:"permission_scope"`
	AuthorizationEpoch     uint64                  `json:"authorization_epoch"`
	PolicySnapshotHash     string                  `json:"policy_snapshot_hash"`
	StartedAt              *time.Time              `json:"started_at"`
	FinishedAt             *time.Time              `json:"finished_at"`
	DurationMS             *int64                  `json:"duration_ms"`
	Status                 string                  `json:"status"`
	Effect                 string                  `json:"effect"`
	ErrorType              string                  `json:"error_type"`
	Retryable              bool                    `json:"retryable"`
	OutputBytes            int                     `json:"output_size_bytes"`
	Truncated              bool                    `json:"truncated"`
	Filtered               bool                    `json:"filtered"`
	InstructionTrust       string                  `json:"instruction_trust"`
	ContextOutput          any                     `json:"context_output"`
	ContextTruncated       bool                    `json:"context_truncated"`
	ContextEstimatedTokens int                     `json:"context_estimated_tokens"`
	ResourceUsage          map[string]any          `json:"resource_usage"`
	TimingSource           string                  `json:"timing_source"`
}

// Identifies the platform-authorized capability resource, never credentials,
// caller input, or an assertion of access to arbitrary downstream data.
type RuntimePermissionScope struct {
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

func toolPermissionScope(name string) *RuntimePermissionScope {
	return &RuntimePermissionScope{Action: "tool.invoke", ResourceType: "tool", ResourceID: name}
}

func validToolPermissionScope(value *RuntimePermissionScope, name string) bool {
	return value == nil || (value.Action == "tool.invoke" && value.ResourceType == "tool" && value.ResourceID == name)
}

var observationBearer = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
var observationCredential = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[:=]\s*[^\s,;]+`)
var observationControl = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
var observationRoleMarker = regexp.MustCompile(`(?i)<\|(?:im_start|im_end|system|assistant|user)[^>]*\|>|\[/?INST\]`)

type observationSanitizer struct {
	bytes, nodes        int
	truncated, filtered bool
}

func (s *observationSanitizer) value(value any, depth int) any {
	s.nodes++
	if depth > 16 || s.nodes > 2048 || s.bytes > observationOutputLimit {
		s.truncated = true
		return "[output omitted]"
	}
	switch v := value.(type) {
	case nil, bool, float64, float32, int, int32, int64, uint, uint32, uint64, json.Number:
		s.bytes += 32
		return v
	case string:
		// Bound provider text before regex processing. Truncated credential tails
		// are removed too; a full credential never needs to enter a gateway buffer.
		if len(v) > 8192 {
			v = observationUTF8Prefix(v, 8192)
			s.truncated = true
		}
		clean := observationBearer.ReplaceAllString(v, "Bearer [REDACTED]")
		clean = observationCredential.ReplaceAllString(clean, "$1=[REDACTED]")
		clean = observationControl.ReplaceAllString(clean, "")
		clean = observationRoleMarker.ReplaceAllString(clean, "[untrusted role marker]")
		if clean != v {
			s.filtered = true
		}
		limit := 8192
		if remaining := observationOutputLimit - s.bytes; remaining < limit {
			limit = remaining
		}
		if limit < 0 {
			limit = 0
		}
		if len(clean) > limit {
			clean = observationUTF8Prefix(clean, limit)
			s.truncated = true
		}
		s.bytes += len(clean)
		return clean
	case map[string]any:
		if len(v) > 256 {
			s.truncated = true
			return "[object exceeds field limit]"
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		result := make(map[string]any, len(v))
		for _, key := range keys {
			if len(key) > 128 {
				s.truncated = true
				continue
			}
			s.bytes += len(key)
			normal := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
			switch normal {
			case "apikey", "accesstoken", "refreshtoken", "clientsecret", "password", "authorization", "cookie", "setcookie", "environment", "environ", "env", "privatekey", "runtimereceiptversion":
				result[key] = "[REDACTED]"
				s.filtered = true
			default:
				result[key] = s.value(v[key], depth+1)
			}
		}
		return result
	case []any:
		limit := len(v)
		if limit > 256 {
			limit = 256
			s.truncated = true
		}
		result := make([]any, 0, limit)
		for _, item := range v[:limit] {
			result = append(result, s.value(item, depth+1))
		}
		return result
	case []string:
		items := make([]any, 0, min(len(v), 256))
		for i, item := range v {
			if i >= 256 {
				s.truncated = true
				break
			}
			items = append(items, item)
		}
		return s.value(items, depth+1)
	case []map[string]any:
		items := make([]any, 0, min(len(v), 256))
		for i, item := range v {
			if i >= 256 {
				s.truncated = true
				break
			}
			items = append(items, item)
		}
		return s.value(items, depth+1)
	default:
		// Providers must expose bounded JSON values, not arbitrary objects/files.
		s.filtered = true
		return "[unsupported output type]"
	}
}

func observationUTF8Prefix(value string, limit int) string {
	if len(value) <= limit {
		return strings.ToValidUTF8(value, "�")
	}
	value = value[:limit]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func newToolObservation(scope sharedkernel.Scope, name, callID string, started *time.Time, status, effect, errorType string, output map[string]any) (runtimeObservation, map[string]any) {
	sanitizer := observationSanitizer{}
	if output == nil {
		output = map[string]any{}
	}
	safe, ok := sanitizer.value(output, 0).(map[string]any)
	if !ok {
		safe = map[string]any{"output_omitted": true}
		sanitizer.truncated = true
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		safe = map[string]any{"output_omitted": true}
		encoded = []byte(`{"output_omitted":true}`)
		sanitizer.filtered = true
		status, errorType = "failed", "TOOL_OUTPUT_INVALID"
	}
	if len(encoded) > observationOutputLimit {
		safe = map[string]any{"output_omitted": true, "reason": "output_limit"}
		encoded, _ = json.Marshal(safe)
		sanitizer.truncated = true
	}
	step := sha256.Sum256([]byte(ToolReceiptScopeHash(scope) + "\x00" + callID))
	observation := runtimeObservation{Version: observationVersion, RunID: scope.RunID, StepID: fmt.Sprintf("runtime-%x", step), CallID: callID, ToolName: name, ExecutionType: "tool", TraceID: scope.TraceID, PermissionScopeHash: ToolReceiptScopeHash(scope), StartedAt: started, Status: status, Effect: effect, ErrorType: errorType, OutputBytes: len(encoded), Truncated: sanitizer.truncated, Filtered: sanitizer.filtered, InstructionTrust: "untrusted_data", ContextOutput: safe, ContextEstimatedTokens: len(encoded), ResourceUsage: map[string]any{"cpu_time_ms": nil, "peak_memory_bytes": nil, "disk_bytes": nil}, TimingSource: "legacy_receipt"}
	observation.AuthorizationEpoch = scope.AuthorizationEpoch
	if started != nil {
		finished := time.Now().UTC()
		duration := finished.Sub(*started).Milliseconds()
		observation.FinishedAt = &finished
		observation.DurationMS = &duration
		observation.TimingSource = "gateway_wall_clock"
	}
	if len(encoded) > observationContextLimit {
		digest := sha256.Sum256(encoded)
		lower, upper := 0, min(1024, len(encoded))
		var contextOutput map[string]any
		for lower <= upper {
			middle := (lower + upper) / 2
			candidate := map[string]any{"truncated": true, "encoding": "utf8-json-excerpt", "excerpt": observationUTF8Prefix(string(encoded), middle), "output_sha256": fmt.Sprintf("%x", digest)}
			contextJSON, _ := json.Marshal(candidate)
			if len(contextJSON) <= observationContextLimit {
				contextOutput = candidate
				lower = middle + 1
			} else {
				upper = middle - 1
			}
		}
		observation.ContextOutput = contextOutput
		contextJSON, _ := json.Marshal(contextOutput)
		observation.ContextEstimatedTokens = len(contextJSON)
		observation.ContextTruncated = true
	}
	return observation, safe
}

func storedToolObservation(observation runtimeObservation, output map[string]any) map[string]any {
	return map[string]any{"_runtime_receipt_version": observationVersion, "data": output, "observation": observation}
}

// Preserve integer precision for the new receipt protocol while retaining
// legacy float64 result types on unversioned tools.
func decodeToolStoredResult(raw []byte, result *map[string]any) error {
	var header struct {
		Version string `json:"_runtime_receipt_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if header.Version == observationVersion {
		decoder.UseNumber()
	}
	if err := decoder.Decode(result); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing tool receipt")
	}
	return nil
}

func cloneToolResult(result map[string]any) map[string]any {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	var cloned map[string]any
	if decodeToolStoredResult(raw, &cloned) != nil {
		return nil
	}
	return cloned
}

func toolObservationResponse(scope sharedkernel.Scope, name, callID string, stored map[string]any) (map[string]any, error) {
	if stored["_runtime_receipt_version"] == observationVersion {
		raw, err := json.Marshal(stored["observation"])
		if err != nil {
			return nil, err
		}
		var observation runtimeObservation
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&observation) != nil || observation.Version != observationVersion || observation.RunID != scope.RunID || observation.CallID != callID || observation.ToolName != name || observation.PermissionScopeHash != ToolReceiptScopeHash(scope) || !validToolPermissionScope(observation.PermissionScope, name) {
			return nil, errors.New("stored observation binding mismatch")
		}
		result, ok := stored["data"].(map[string]any)
		if !ok {
			return nil, errors.New("stored result object missing")
		}
		return map[string]any{"data": result, "observation": observation}, nil
	}
	observation, safe := newToolObservation(scope, name, callID, nil, "succeeded", "completed", "", stored)
	return map[string]any{"data": safe, "observation": observation}, nil
}

func (m *Module) toolObservedResult(w http.ResponseWriter, r *http.Request, op envelope, name, callID string, result map[string]any) {
	response, err := toolObservationResponse(scopeFromHarness(op.Context), name, callID, result)
	if err != nil {
		m.error(w, 502, "TOOL_RECEIPT_INVALID", "tool receipt binding invalid", op.Context.TraceID)
		return
	}
	m.currentResult(w, r, op, response)
}

func (m *Module) toolObservedFailure(w http.ResponseWriter, r *http.Request, op envelope, name, callID string, started *time.Time, status int, code string, cause error) {
	state, effect := "failed", "not_submitted"
	if cause != nil && !errors.Is(cause, ErrToolNotSubmitted) {
		state, effect = "unknown", "unknown"
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		state = "timeout"
	}
	if errors.Is(cause, context.Canceled) {
		state = "cancelled"
	}
	observation, _ := newToolObservation(scopeFromHarness(op.Context), name, callID, started, state, effect, code, nil)
	observation.AuthorizationEpoch = op.Context.AuthorizationEpoch
	observation.PolicySnapshotHash = op.Policy.Hash
	observation.PermissionScope = toolPermissionScope(name)
	observation.ExecutionType = toolExecutionType(m.tools, name)
	// Never include provider errors, output, environment or credentials in logs.
	logRuntimeObservation(observation)
	if !m.currentCapability(w, r, op) {
		return
	}
	m.write(w, status, response{Code: 1, ErrorCode: code, Message: "tool execution did not return a verified result", TraceID: op.Context.TraceID, Data: map[string]any{"observation": observation}})
}

func logRuntimeObservation(o runtimeObservation) {
	raw, _ := json.Marshal(map[string]any{"run_id": o.RunID, "step_id": o.StepID, "tool_name": o.ToolName, "execution_type": o.ExecutionType, "permission_scope_hash": o.PermissionScopeHash, "permission_scope": o.PermissionScope, "authorization_epoch": o.AuthorizationEpoch, "policy_snapshot_hash": o.PolicySnapshotHash, "started_at": o.StartedAt, "finished_at": o.FinishedAt, "duration_ms": o.DurationMS, "status": o.Status, "error_type": o.ErrorType, "output_size_bytes": o.OutputBytes, "resource_usage": o.ResourceUsage, "trace_id": o.TraceID})
	log.Printf("runtime observation %s", raw)
}

func toolExecutionType(provider ToolProvider, name string) string {
	if described, ok := provider.(RuntimeToolDescriber); ok {
		if descriptor, found := described.DescribeTool(name); found && descriptor.Validate() == nil {
			return descriptor.ExecutionType
		}
	}
	if typed, ok := provider.(interface{ ExecutionType(string) string }); ok {
		kind := typed.ExecutionType(name)
		if kind == "api" || kind == "code" {
			return kind
		}
	}
	return "tool"
}
