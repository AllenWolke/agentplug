package agentplatform

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// CapabilityConfig is deployment wiring, not an Agent-owned model credential.
// CapabilityConfig 仅装配平台网关；业务 Agent 不持有模型厂商凭据。
type CapabilityConfig struct {
	SendLimiter                            SendLimiter
	ObserveCall                            func(CapabilityObservation)
	BaseURL, InternalToken, SigningSecret  string
	WorkloadClientID, WorkloadClientSecret string
	Transport                              http.RoundTripper
	Now                                    func() time.Time
}

// CapabilityClient belongs to one verified execution. Never share across Runs.
// CapabilityClient 只属于一个已验证运行，不得跨 Run 共享上下文。
type CapabilityClient struct {
	checkpointLimits         map[string]uint64
	config                   CapabilityConfig
	client                   *http.Client
	mu                       sync.Mutex
	context                  map[string]any
	traceID                  string
	businessInputFingerprint string
	agentGroupResume         *agentGroupResumeBinding
	agentGroupResumeConsumed bool
	agentGroupGatherAllowed  bool
	agentGroupGatherUsed     bool
}

type capabilityContextKey struct{}

// CapabilityFromContext exposes the injected client to business nodes.
// CapabilityFromContext 让业务节点复用已注入的公共能力客户端。
func CapabilityFromContext(ctx context.Context) (*CapabilityClient, bool) {
	client, ok := ctx.Value(capabilityContextKey{}).(*CapabilityClient)
	return client, ok
}

func NewCapabilityClient(config CapabilityConfig, request ExecuteRequest) (*CapabilityClient, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || config.InternalToken == "" || config.SigningSecret == "" {
		return nil, &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "platform capability wiring is incomplete"}
	}
	if (config.WorkloadClientID == "") != (config.WorkloadClientSecret == "") || config.WorkloadClientSecret != "" && (len(config.WorkloadClientSecret) < 32 || len(config.WorkloadClientSecret) > 512) {
		return nil, &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "Agent workload credentials must be configured together"}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")
	policy, ok := request.Input["policy_snapshot"].(map[string]any)
	if !ok {
		return nil, &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "immutable policy snapshot is missing"}
	}
	s := request.Scope
	businessInputFingerprint, err := executionBusinessHash(request)
	if err != nil || !validHandoffDigest(businessInputFingerprint) {
		return nil, &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "business input fingerprint is invalid"}
	}
	c := map[string]any{"tenant_id": s.TenantID, "department_id": s.DepartmentID, "application_id": s.ApplicationID, "installation_id": s.InstallationID, "agent_instance_id": s.AgentInstanceID, "agent_id": s.AgentID, "agent_version_id": s.AgentVersionID, "principal_type": s.PrincipalType, "actor_id": s.PrincipalID, "request_id": request.IdempotencyKey, "task_id": s.RunID, "thread_id": s.SessionID, "session_id": s.SessionID, "trace_id": s.TraceID, "authorization_epoch": s.AuthorizationEpoch, "idempotency_key": request.IdempotencyKey, "platform_context_token": request.ContextToken}
	if s.ParentRunID != "" {
		c["parent_run_id"] = s.ParentRunID
	}
	for _, key := range []string{"model_profile_id", "prompt_version_id", "tool_policy_id", "memory_policy_id", "knowledge_policy_id", "runtime_policy_id"} {
		value, ok := policy[key].(string)
		if !ok || value == "" {
			return nil, &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "six policy references are required"}
		}
		c[key] = value
	}
	client := &http.Client{Timeout: 310 * time.Second, Transport: config.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &CapabilityClient{config: config, client: client, context: c, traceID: s.TraceID, businessInputFingerprint: businessInputFingerprint}, nil
}

// Post renews first, then signs the actual method/target/body; failures never
// fall back to a direct provider. / 先续签再签实际请求，失败绝不直连厂商。
func (c *CapabilityClient) Post(ctx context.Context, path string, payload map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 310*time.Second)
	defer cancel()
	if !strings.HasPrefix(path, "/internal/") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") || path == "/internal/context/renew" {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "invalid capability path"}
	}
	c.mu.Lock()
	if !c.agentGroupResumeAllowsPostLocked(path, payload) {
		c.mu.Unlock()
		return nil, &AppError{Code: "AGENT_GROUP_RESUME_REJECTED", Message: "resume must continue through the original AgentGroup gather"}
	}
	if err := c.renew(ctx); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	body, err := json.Marshal(map[string]any{"context": c.context, "input": payload})
	token := c.context["platform_context_token"].(string)
	c.mu.Unlock()
	if err != nil {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "invalid capability input"}
	}
	result, sendError := c.send(ctx, path, body, token, 1<<20)
	return c.recoverToolObservation(ctx, path, payload, result, sendError)
}

func tokenClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidCapability
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidCapability
	}
	var claims map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&claims) != nil || claims == nil {
		return nil, ErrInvalidCapability
	}
	return claims, nil
}

func claimTime(claims map[string]any, key string) int64 {
	number, ok := claims[key].(json.Number)
	if !ok {
		return 0
	}
	value, _ := number.Int64()
	return value
}

func (c *CapabilityClient) renew(ctx context.Context) error {
	return c.renewCurrent(ctx, false)
}

// ValidateCurrentExecution forces a platform authority check even while the
// signed token remains valid. It does not invoke business capabilities.
func (c *CapabilityClient) ValidateCurrentExecution(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renewCurrent(ctx, true)
}

func (c *CapabilityClient) renewCurrent(ctx context.Context, force bool) error {
	old := c.context["platform_context_token"].(string)
	claims, err := tokenClaims(old)
	if err != nil || claimTime(claims, "execution_revision") <= 0 || claimTime(claims, "exp") <= 0 {
		return &AppError{Code: "CAPABILITY_RENEWAL_DENIED", Message: "execution capability binding is invalid"}
	}
	if !force && claimTime(claims, "exp") > c.config.Now().Unix()+15 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"context": c.context, "input": map[string]any{}})
	if err != nil {
		return &AppError{Code: "REQUEST_INVALID", Message: "invalid capability context"}
	}
	renewCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := c.send(renewCtx, "/internal/context/renew", body, old, 32768)
	if err != nil {
		return err
	}
	fresh, ok := data["context_token"].(string)
	next, parseErr := tokenClaims(fresh)
	if !ok || parseErr != nil || claimTime(next, "exp") <= c.config.Now().Unix()+15 {
		return &AppError{Code: "CAPABILITY_RENEWAL_DENIED", Message: "renewed execution binding is invalid"}
	}
	// The server verifies signatures. Local comparison prevents a swapped response.
	// 签名由平台校验，本地比较阻止响应将当前运行替换为其他身份。
	for _, field := range []string{"iss", "aud", "subject_type", "sub", "tenant_id", "department_id", "application_id", "installation_id", "agent_instance_id", "agent_id", "agent_version_id", "run_id", "parent_run_id", "session_id", "trace_id", "authorization_epoch", "actions", "body_hash", "policy_snapshot_hash", "execution_revision", "lease_token_hash"} {
		if !reflect.DeepEqual(claims[field], next[field]) {
			return &AppError{Code: "CAPABILITY_RENEWAL_DENIED", Message: "renewed execution binding is invalid"}
		}
	}
	c.context["platform_context_token"] = fresh
	return nil
}

func (c *CapabilityClient) send(ctx context.Context, path string, body []byte, token string, limit int64) (map[string]any, error) {
	target := c.config.BaseURL + path
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "invalid capability target"}
	}
	digest := sha256.Sum256(body)
	proof, _ := json.Marshal([]string{"platform-capability/v2", http.MethodPost, r.URL.RequestURI(), hex.EncodeToString(digest[:])})
	mac := hmac.New(sha256.New, []byte(c.config.SigningSecret))
	_, _ = mac.Write(proof)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Internal-Token", c.config.InternalToken)
	r.Header.Set("X-Platform-Context", "Bearer "+token)
	r.Header.Set("X-Context-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-Trace-ID", c.traceID)
	if c.config.WorkloadClientID != "" {
		r.Header.Set("X-Agent-Client-ID", c.config.WorkloadClientID)
		r.Header.Set("X-Agent-Client-Secret", c.config.WorkloadClientSecret)
	}
	if c.config.SendLimiter != nil {
		release, limitError := c.config.SendLimiter.Acquire(ctx)
		if limitError != nil {
			return nil, limitError
		}
		if release == nil {
			return nil, publicError("CAPABILITY_LIMITER_INVALID")
		}
		defer release()
	}
	started := time.Now()
	status := "failed"
	if c.config.ObserveCall != nil {
		defer func() {
			defer func() { _ = recover() }()
			c.config.ObserveCall(CapabilityObservation{path, float64(time.Since(started)) / float64(time.Millisecond), status})
		}()
	}
	resp, err := c.client.Do(r)
	if err != nil {
		return nil, &capabilityTransportFailure{&AppError{Code: "CAPABILITY_RENEWAL_UNAVAILABLE", Message: "platform capability unavailable", Retryable: true}}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		status = "succeeded"
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if (resp.StatusCode == 401 || resp.StatusCode == 403) && path == "/internal/context/renew" {
		return nil, &AppError{Code: "CAPABILITY_RENEWAL_DENIED", Message: "current execution denied"}
	}
	if resp.StatusCode >= 400 && path != "/internal/context/renew" && err == nil && int64(len(raw)) <= limit {
		var failure struct {
			Code string          `json:"error_code"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &failure) == nil && validCapabilityErrorCode(failure.Code) {
			var observation struct {
				Observation struct {
					Version string `json:"version"`
					Effect  string `json:"effect"`
				} `json:"observation"`
			}
			_ = json.Unmarshal(failure.Data, &observation)
			if observation.Observation.Version == "runtime-observation/v1" && observation.Observation.Effect == "unknown" {
				return nil, &capabilityHTTPFailure{&AppError{Code: "TOOL_RESULT_UNKNOWN", Message: "tool effect requires reconciliation", Retryable: false}, resp.StatusCode}
			}
			return nil, &capabilityHTTPFailure{&AppError{Code: failure.Code, Message: "platform capability rejected", Retryable: resp.StatusCode >= 500, Details: childStopControlErrorDetails(failure.Code, resp.StatusCode, failure.Data)}, resp.StatusCode}
		}
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, &AppError{Code: "CAPABILITY_DENIED", Message: "current execution denied"}
	}
	if err != nil || int64(len(raw)) > limit || resp.StatusCode != http.StatusOK {
		return nil, &AppError{Code: "CAPABILITY_RENEWAL_UNAVAILABLE", Message: "platform capability unavailable", Retryable: true}
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	decode := json.NewDecoder(bytes.NewReader(raw))
	var receiptHeader struct {
		Data struct {
			Observation struct {
				Version string `json:"version"`
			} `json:"observation"`
		} `json:"data"`
	}
	versionedTool := path == "/internal/tool/invoke" && json.Unmarshal(raw, &receiptHeader) == nil && receiptHeader.Data.Observation.Version == "runtime-observation/v1"
	if path == "/internal/state/checkpoint" || path == "/internal/tool/receipt" || path == "/internal/model/receipt" || versionedTool {
		// Business checkpoint integers must survive a restore without being
		// rounded through float64. Keep legacy response types on other routes.
		decode.UseNumber()
	}
	if decode.Decode(&envelope) != nil || envelope.Data == nil {
		return nil, &AppError{Code: "CAPABILITY_RENEWAL_UNAVAILABLE", Message: "invalid platform response", Retryable: true}
	}
	var trailing any
	if decode.Decode(&trailing) != io.EOF {
		return nil, &AppError{Code: "CAPABILITY_RENEWAL_UNAVAILABLE", Message: "invalid platform response", Retryable: true}
	}
	return envelope.Data, nil
}

// Do not expose arbitrary upstream text as an error code.
// 不得将任意上游文本（可能包含凭据）当作错误码透传。
func validCapabilityErrorCode(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, c := range code {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// childStopControlErrorDetails recognizes exactly one safe CAS hint. Ordinary
// errors never expose upstream data, even when an upstream includes it.
func childStopControlErrorDetails(code string, statusCode int, raw json.RawMessage) map[string]any {
	if code != "AGENT_STOP_REVISION_CONFLICT" || statusCode != http.StatusConflict || len(raw) == 0 {
		return nil
	}
	var envelope struct {
		StopControl struct {
			Version           string `json:"version"`
			Status            string `json:"status"`
			ExecutionRevision uint64 `json:"execution_revision"`
		} `json:"stop_control"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil
	}
	control := envelope.StopControl
	if control.Version != "agent-child-stop-control-conflict/v1" || control.ExecutionRevision == 0 || control.ExecutionRevision > 1<<63-1 ||
		(control.Status != "accepted" && control.Status != "running" && control.Status != "waiting") {
		return nil
	}
	return map[string]any{"stop_control": map[string]any{
		"version": control.Version, "status": control.Status, "execution_revision": control.ExecutionRevision,
	}}
}

// CapabilityConfigFromEnv is shared deployment wiring for generated entries.
// CapabilityConfigFromEnv 统一脚手架部署装配，支持 Secret 文件且不回显值。
func CapabilityConfigFromEnv() (*CapabilityConfig, error) {
	base := strings.TrimSpace(os.Getenv("PLATFORM_CAPABILITY_URL"))
	if base == "" {
		return nil, nil
	}
	credential := func(name string) (string, error) {
		value := strings.TrimSpace(os.Getenv(name))
		if path := strings.TrimSpace(os.Getenv(name + "_FILE")); value == "" && path != "" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return "", &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "platform credential file unavailable"}
			}
			value = strings.TrimSpace(string(raw))
		}
		if value == "" || value == "dev-internal-token" || value == "change-me" {
			return "", &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "explicit platform credential required"}
		}
		return value, nil
	}
	token, err := credential("INTERNAL_TOKEN")
	if err != nil {
		return nil, err
	}
	secret, err := credential("INTERNAL_SIGNING_SECRET")
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(os.Getenv("AGENT_CLIENT_ID"))
	clientSecret := ""
	if clientID != "" || strings.TrimSpace(os.Getenv("AGENT_CLIENT_SECRET")) != "" || strings.TrimSpace(os.Getenv("AGENT_CLIENT_SECRET_FILE")) != "" {
		if clientID == "" {
			return nil, &AppError{Code: "CAPABILITY_CONFIG_INVALID", Message: "Agent workload credentials must be configured together"}
		}
		clientSecret, err = credential("AGENT_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
	}
	return &CapabilityConfig{BaseURL: base, InternalToken: token, SigningSecret: secret, WorkloadClientID: clientID, WorkloadClientSecret: clientSecret}, nil
}

func (s *ExecutionServer) businessContext(ctx context.Context, request ExecuteRequest) (context.Context, error) {
	if s.cfg.Capability == nil {
		return ctx, nil
	}
	client, err := NewCapabilityClient(*s.cfg.Capability, request)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, capabilityContextKey{}, client), nil
}

func (s *ExecutionServer) businessContextForActive(ctx context.Context, request ExecuteRequest, active *activeExecution) (context.Context, error) {
	businessCtx, err := s.businessContext(ctx, request)
	if err != nil || active == nil {
		return businessCtx, err
	}
	if active.runtimeRecoveryPlan != nil {
		businessCtx = context.WithValue(businessCtx, recoveryPlanContextKey{}, active.runtimeRecoveryPlan)
	}
	if active.agentGroupResume == nil {
		return businessCtx, nil
	}
	client, ok := CapabilityFromContext(businessCtx)
	if !ok {
		return nil, ErrInvalidTransition
	}
	client.setAgentGroupResumeBinding(active.agentGroupResume)
	return businessCtx, nil
}

func (c CapabilityConfig) String() string { return "CapabilityConfig[redacted]" }
