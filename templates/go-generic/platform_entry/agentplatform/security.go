package agentplatform

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInvalidCapability = errors.New("invalid platform capability")

type Claims struct {
	Issuer, Audience, SubjectType, SubjectID string
	TenantID, ApplicationID, AgentInstanceID string
	InstallationID                           string
	Actions                                  []string
	PolicySnapshotHash                       string
	BodyHash                                 string
	AuthorizationEpoch                       uint64
	ExecutionRevision                        uint64
	LeaseTokenHash                           string
	IssuedAt, ExpiresAt                      int64
}

type wireClaims struct {
	Issuer             string   `json:"iss"`
	Audience           string   `json:"aud"`
	SubjectType        string   `json:"subject_type"`
	SubjectID          string   `json:"sub"`
	TenantID           string   `json:"tenant_id"`
	ApplicationID      string   `json:"application_id"`
	AgentInstanceID    string   `json:"agent_instance_id"`
	InstallationID     string   `json:"installation_id"`
	AuthorizationEpoch uint64   `json:"authorization_epoch"`
	ExecutionRevision  uint64   `json:"execution_revision"`
	LeaseTokenHash     string   `json:"lease_token_hash"`
	Actions            []string `json:"actions"`
	PolicySnapshotHash string   `json:"policy_snapshot_hash"`
	BodyHash           string   `json:"body_hash"`
	IssuedAt           int64    `json:"iat"`
	ExpiresAt          int64    `json:"exp"`
}

// CanonicalBodyHash excludes the token itself to avoid a signing cycle.
// CanonicalBodyHash 排除令牌本身，避免签名循环依赖。
func CanonicalBodyHash(request ExecuteRequest) (string, error) {
	// encoding/json sorts map keys, matching the canonical SDK rule in Python
	// and Java. / encoding/json 会排序 map 键，与各语言 SDK 的规范一致。
	normalizedInput, err := normalizeJSONValue(request.Input)
	if err != nil {
		return "", err
	}
	value := map[string]any{
		"protocol_version": request.ProtocolVersion,
		"scope":            canonicalScope(request.Scope),
		"operation":        request.Operation,
		"idempotency_key":  request.IdempotencyKey,
		"input_schema":     request.InputSchema,
		"input":            normalizedInput,
	}
	// Bind review decisions too; otherwise a signed approval can become rejection.
	// 恢复决策必须参与签名，防止签名后的审批意见被替换。
	if request.ResumeInput != nil {
		normalizedResume, err := normalizeJSONValue(request.ResumeInput)
		if err != nil {
			return "", err
		}
		value["resume_input"] = normalizedResume
	}
	raw, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalEventHash binds an event subscription to the same immutable scope
// as an execution request. / CanonicalEventHash 将事件订阅绑定到同一不可变作用域。
func CanonicalEventHash(request EventRequest) (string, error) {
	if request.AfterSeq > MaxSafeExecutionEventSequence {
		return "", &AppError{Code: "REQUEST_INVALID", Message: "event cursor is outside the safe integer range"}
	}
	value := map[string]any{
		"protocol_version":     request.ProtocolVersion,
		"scope":                canonicalScope(request.Scope),
		"after_seq":            request.AfterSeq,
		"policy_snapshot_hash": request.PolicySnapshotHash,
	}
	raw, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Execution signatures use JSON data, not HTML. Match the platform and the
// other SDKs without replacing literal <, > or & inside evidence and prompts.
func canonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// normalizeJSONValue converts nested structs to JSON objects and preserves
// number lexemes for cross-language canonical hashing.
// normalizeJSONValue 将嵌套结构体转换为 JSON 对象，并保留数字字面量，确保跨语言哈希一致。
func normalizeJSONValue(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var normalized any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

// canonicalScope normalizes optional fields and lets encoding/json sort every
// scope key, matching the Python SDK's canonical JSON representation.
// canonicalScope 统一可选字段并让 encoding/json 排序全部作用域键，与 Python SDK 一致。
func canonicalScope(scope ScopeKey) map[string]any {
	value := map[string]any{
		"tenant_id": scope.TenantID, "department_id": scope.DepartmentID,
		"application_id": scope.ApplicationID, "agent_instance_id": scope.AgentInstanceID,
		"installation_id": scope.InstallationID,
		"agent_id":        scope.AgentID, "agent_version_id": scope.AgentVersionID,
		"principal_type": scope.PrincipalType, "principal_id": scope.PrincipalID,
		"session_id": scope.SessionID, "run_id": scope.RunID,
		"authorization_epoch": scope.AuthorizationEpoch, "trace_id": scope.TraceID,
	}
	if scope.ParentRunID != "" {
		value["parent_run_id"] = scope.ParentRunID
	}
	if scope.DelegationDepth != 0 {
		value["delegation_depth"] = scope.DelegationDepth
	}
	return value
}

// VerifyContext validates signature, scope, action, body binding and bounded lifetime.
// VerifyContext 校验签名、作用域、动作、请求绑定及有限时效。
func VerifyContext(request ExecuteRequest, key ed25519.PublicKey, issuer, audience string, now time.Time) (Claims, error) {
	w, err := verifyWireClaims(request.ContextToken, key)
	if err != nil {
		return Claims{}, err
	}
	hash, err := CanonicalBodyHash(request)
	policy, ok := request.Input["policy_snapshot"].(map[string]any)
	snapshotHash, hashOK := policy["content_hash"].(string)
	if err != nil || !ok || !hashOK || snapshotHash == "" || !claimsMatch(w, request.Scope, hash, snapshotHash, request.Operation, issuer, audience, now) {
		return Claims{}, ErrInvalidCapability
	}
	return claimsFromWire(w), nil
}

// VerifyEventContext applies the same PEP checks to event subscriptions.
// VerifyEventContext 对事件订阅执行同样的 PEP 校验，不能只信任 run_id。
func VerifyEventContext(request EventRequest, key ed25519.PublicKey, issuer, audience string, now time.Time) (Claims, error) {
	w, err := verifyWireClaims(request.ContextToken, key)
	if err != nil {
		return Claims{}, err
	}
	hash, err := CanonicalEventHash(request)
	if err != nil || request.PolicySnapshotHash == "" || !claimsMatch(w, request.Scope, hash, request.PolicySnapshotHash, "events", issuer, audience, now) {
		return Claims{}, ErrInvalidCapability
	}
	return claimsFromWire(w), nil
}

func verifyWireClaims(token string, key ed25519.PublicKey) (wireClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(key) != ed25519.PublicKeySize {
		return wireClaims{}, ErrInvalidCapability
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	if err != nil || json.Unmarshal(headerRaw, &header) != nil || header["alg"] != "EdDSA" {
		return wireClaims{}, ErrInvalidCapability
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return wireClaims{}, ErrInvalidCapability
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var wire wireClaims
	if err != nil || json.Unmarshal(payload, &wire) != nil {
		return wireClaims{}, ErrInvalidCapability
	}
	return wire, nil
}

func claimsMatch(w wireClaims, scope ScopeKey, hash, snapshotHash, action, issuer, audience string, now time.Time) bool {
	return w.PolicySnapshotHash == snapshotHash && w.Issuer == issuer && w.Audience == audience && w.SubjectType == scope.PrincipalType && w.SubjectID == scope.PrincipalID && w.TenantID == scope.TenantID && w.ApplicationID == scope.ApplicationID && w.AgentInstanceID == scope.AgentInstanceID && w.InstallationID == scope.InstallationID && w.InstallationID != "" && w.AuthorizationEpoch == scope.AuthorizationEpoch && w.BodyHash == hash && w.ExpiresAt > now.Unix() && w.IssuedAt <= now.Add(30*time.Second).Unix() && w.ExpiresAt-w.IssuedAt <= 300 && contains(w.Actions, action)
}

func claimsFromWire(w wireClaims) Claims {
	return Claims{Issuer: w.Issuer, Audience: w.Audience, SubjectType: w.SubjectType, SubjectID: w.SubjectID, TenantID: w.TenantID, ApplicationID: w.ApplicationID, AgentInstanceID: w.AgentInstanceID, InstallationID: w.InstallationID, Actions: w.Actions, PolicySnapshotHash: w.PolicySnapshotHash, BodyHash: w.BodyHash, AuthorizationEpoch: w.AuthorizationEpoch, ExecutionRevision: w.ExecutionRevision, LeaseTokenHash: w.LeaseTokenHash, IssuedAt: w.IssuedAt, ExpiresAt: w.ExpiresAt}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
