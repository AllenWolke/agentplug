package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	protocol "github.com/lexagent/code-runtime-contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// CodeBinding is immutable operator configuration. Caller input is only code;
// language, image, resource limits and controller origin are never caller chosen.
type CodeBinding struct {
	ToolName      string          `json:"tool_name"`
	Endpoint      string          `json:"endpoint"`
	ControllerID  string          `json:"controller_id"`
	ProfileID     string          `json:"profile_id"`
	Language      string          `json:"language"`
	Limits        protocol.Limits `json:"limits"`
	TenantID      string          `json:"tenant_id"`
	ApplicationID string          `json:"application_id"`
	AgentIDs      []string        `json:"agent_ids"`
}
type codeBoundTool struct {
	binding CodeBinding
	client  *http.Client
}
type codeBindingScope struct {
	tool, tenant, application, agent string
}

type CodeToolProvider struct {
	tools    map[string]codeBoundTool
	bindings map[codeBindingScope]codeBoundTool
	signer   *protocol.Signer
}

// A private context marker can only be created after gateway IAM and the
// operation-bound human approval. Neither an SDK nor ToolCommand can forge it.
type runtimeExecutionAuthorization struct {
	PolicyHash string
	Approval   ToolConfirmationClaims
}
type runtimeExecutionAuthorizationKey struct{}

func NewCodeToolProvider(bindings []CodeBinding, signer *protocol.Signer, developmentLoopback bool, clientFactory func(string, bool) (*http.Client, error)) (*CodeToolProvider, error) {
	if signer == nil || clientFactory == nil || len(bindings) == 0 || len(bindings) > 16 {
		return nil, errors.New("code controller configuration required")
	}
	p := &CodeToolProvider{tools: map[string]codeBoundTool{}, bindings: map[codeBindingScope]codeBoundTool{}, signer: signer}
	for _, b := range bindings {
		if !strings.HasPrefix(b.ToolName, "code.") || !codeIdentifier(b.ToolName) || !codeIdentifier(b.ControllerID) || !codeIdentifier(b.ProfileID) || !codeIdentifier(b.TenantID) || !codeIdentifier(b.ApplicationID) || (b.Language != "python" && b.Language != "javascript" && b.Language != "shell") || b.Limits.Validate() != nil || len(b.AgentIDs) == 0 || len(b.AgentIDs) > 32 {
			return nil, errors.New("invalid code binding")
		}
		if existing, found := p.tools[b.ToolName]; found && existing.binding.Language != b.Language {
			return nil, errors.New("code tool language must be consistent across scopes")
		}
		seen := map[string]bool{}
		for _, id := range b.AgentIDs {
			if !codeIdentifier(id) || seen[id] {
				return nil, errors.New("invalid code agent scope")
			}
			seen[id] = true
		}
		u, err := url.Parse(b.Endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
			return nil, errors.New("invalid code controller origin")
		}
		client, err := clientFactory(b.Endpoint, developmentLoopback)
		if err != nil || client == nil || client.Transport == nil {
			return nil, errors.New("unsafe code controller origin")
		}
		// Copy the client before setting limits; do not mutate a shared factory object.
		frozen := *client
		frozen.Timeout = 65 * time.Second
		if transport, ok := client.Transport.(*http.Transport); ok {
			controlled := transport.Clone()
			controlled.ResponseHeaderTimeout = 65 * time.Second
			frozen.Transport = controlled
		}
		frozen.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("code controller redirect denied") }
		b.Endpoint = strings.TrimSuffix(b.Endpoint, "/")
		b.AgentIDs = append([]string(nil), b.AgentIDs...)
		bound := codeBoundTool{b, &frozen}
		for _, agent := range b.AgentIDs {
			key := codeBindingScope{b.ToolName, b.TenantID, b.ApplicationID, agent}
			if _, found := p.bindings[key]; found {
				return nil, errors.New("ambiguous code binding scope")
			}
			p.bindings[key] = bound
		}
		if !p.Supports(b.ToolName) {
			p.tools[b.ToolName] = bound
		}
	}
	return p, nil
}
func codeIdentifier(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func (*CodeToolProvider) isolatedCodeRuntime() {}
func (p *CodeToolProvider) Supports(name string) bool {
	if p == nil {
		return false
	}
	_, found := p.tools[name]
	return found
}
func (p *CodeToolProvider) RegisteredTools() []string {
	names := []string{}
	if p != nil {
		for name := range p.tools {
			names = append(names, name)
		}
	}
	return names
}
func (p *CodeToolProvider) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	return RuntimeToolDescriptor{ExecutionType: "code", Risk: "high", TimeoutSeconds: 60}, p.Supports(name)
}
func (m *Module) SetCodeToolProvider(p *CodeToolProvider) error {
	if p == nil {
		return errors.New("code provider required")
	}
	return m.installRuntimeExecutor(p)
}

// The registry has one descriptor per logical tool. Execution and receipt
// lookup select an exact operator-owned scope, never a default binding.
func (p *CodeToolProvider) scopedTool(scope sharedkernel.Scope, name string) (codeBoundTool, bool) {
	if p == nil {
		return codeBoundTool{}, false
	}
	bound, found := p.bindings[codeBindingScope{name, scope.TenantID, scope.ApplicationID, scope.AgentID}]
	return bound, found
}

// Preflight runs before approval consumption or invocation ledger creation.
func (p *CodeToolProvider) ValidateToolCommand(c ToolCommand) error {
	_, found := p.scopedTool(c.Scope, c.Name)
	code, valid := c.Payload["code"].(string)
	if !found || c.Scope.ValidateTrusted() != nil || !codeIdentifier(c.CallID) || !valid || len(c.Payload) != 1 || code == "" || len(code) > 64<<10 || strings.ContainsRune(code, '\x00') {
		return errors.New("invalid scoped code input")
	}
	return nil
}

func (p *CodeToolProvider) permit(ctx context.Context, scope sharedkernel.Scope, name, id, fp, action, code string) (codeBoundTool, protocol.Permit, error) {
	denied := errors.New("code execution authority denied")
	b, found := p.scopedTool(scope, name)
	auth, authorized := ctx.Value(runtimeExecutionAuthorizationKey{}).(runtimeExecutionAuthorization)
	if !found || !authorized || scope.ValidateTrusted() != nil || ctx.Err() != nil || b.binding.TenantID != scope.TenantID || b.binding.ApplicationID != scope.ApplicationID {
		return b, protocol.Permit{}, denied
	}
	now := time.Now()
	hash := ToolReceiptScopeHash(scope)
	approval := auth.Approval
	if approval.ScopeHash != hash || approval.ToolName != name || approval.CallID != id || approval.Fingerprint != fp || approval.PolicyHash != auth.PolicyHash || approval.AuthorizationEpoch != scope.AuthorizationEpoch || approval.ActorID != scope.PrincipalID || approval.ExpiresAt <= now.Unix() {
		return b, protocol.Permit{}, denied
	}
	expires := now.Add(60 * time.Second)
	if approval.ExpiresAt < expires.Unix() {
		expires = time.Unix(approval.ExpiresAt, 0)
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	fence := uint64(0)
	if action == "execute" {
		lease, ok := ctx.Value(toolLeaseContextKey{}).(ToolExecutionLease)
		if !ok || lease.ScopeHash != hash || lease.CallID != id || lease.Fingerprint != fp || lease.Fence == 0 || lease.Token == "" || !lease.Until.After(now) {
			return b, protocol.Permit{}, denied
		}
		fence = lease.Fence
		if lease.Until.Before(expires) {
			expires = lease.Until
		}
	}
	permit := protocol.Permit{Version: "code-permit/v1", Action: action, ControllerID: b.binding.ControllerID, ScopeHash: hash, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, CallerID: scope.PrincipalID, CallerType: scope.PrincipalType, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, AgentInstanceID: scope.AgentInstanceID, InstallationID: scope.InstallationID, RunID: scope.RunID, SessionID: scope.SessionID, TraceID: scope.TraceID, AuthorizationEpoch: scope.AuthorizationEpoch, PolicyHash: auth.PolicyHash, ApprovalID: approval.ApprovalID, ToolName: name, CallID: id, Fingerprint: fp, LeaseFence: fence, ProfileID: b.binding.ProfileID, Language: b.binding.Language, Code: code, Limits: b.binding.Limits, IssuedAt: now.Unix(), ExpiresAt: expires.Unix()}
	if permit.Validate(now) != nil {
		return b, protocol.Permit{}, denied
	}
	return b, permit, nil
}

func (p *CodeToolProvider) Invoke(ctx context.Context, c ToolCommand) (map[string]any, error) {
	if err := p.ValidateToolCommand(c); err != nil {
		return nil, ToolNoEffectError{Err: err}
	}
	code, ok := c.Payload["code"].(string)
	if !ok || len(c.Payload) != 1 || code == "" || len(code) > 64<<10 || strings.ContainsRune(code, '\x00') {
		return nil, ToolNoEffectError{Err: errors.New("invalid code input")}
	}
	fp, err := ToolCommandFingerprint(c.Name, c.Payload)
	if err != nil {
		return nil, ToolNoEffectError{Err: errors.New("invalid code input")}
	}
	b, permit, err := p.permit(ctx, c.Scope, c.Name, c.CallID, fp, "execute", code)
	if err != nil {
		return nil, ToolNoEffectError{Err: err}
	}
	result, found, err := p.request(ctx, b, permit)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("code outcome requires reconciliation")
	}
	return result, nil
}
func (p *CodeToolProvider) LookupToolReceipt(ctx context.Context, q ToolReceiptQuery) (map[string]any, bool, error) {
	b, permit, err := p.permit(ctx, q.Scope, q.Name, q.CallID, q.Fingerprint, "receipt", "")
	if err != nil {
		return nil, false, err
	}
	return p.request(ctx, b, permit)
}
func (p *CodeToolProvider) request(ctx context.Context, b codeBoundTool, permit protocol.Permit) (map[string]any, bool, error) {
	return p.requestWithProof(ctx, b, permit, nil)
}

func (p *CodeToolProvider) requestWithProof(ctx context.Context, b codeBoundTool, permit protocol.Permit, proof func(*protocol.Result)) (map[string]any, bool, error) {
	token, err := p.signer.Sign(permit, time.Now())
	if err != nil {
		return nil, false, ToolNoEffectError{Err: errors.New("code permit unavailable")}
	}
	body, _ := json.Marshal(map[string]string{"permit": token})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.binding.Endpoint+"/v1/"+permit.Action, bytes.NewReader(body))
	if err != nil {
		return nil, false, ToolNoEffectError{Err: errors.New("code request invalid")}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := b.client.Do(request)
	if err != nil {
		return nil, false, errors.New("code controller result unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, false, errors.New("code controller request refused")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(raw) > 16<<20 {
		return nil, false, errors.New("code receipt size invalid")
	}
	var receipt struct {
		Version     string           `json:"version"`
		ScopeHash   string           `json:"scope_hash"`
		ToolName    string           `json:"tool_name"`
		CallID      string           `json:"call_id"`
		Fingerprint string           `json:"fingerprint"`
		Status      string           `json:"status"`
		Result      *protocol.Result `json:"result"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF || receipt.Version != "code-receipt/v1" || receipt.ScopeHash != permit.ScopeHash || receipt.ToolName != permit.ToolName || receipt.CallID != permit.CallID || receipt.Fingerprint != permit.Fingerprint {
		return nil, false, errors.New("code receipt binding invalid")
	}
	if receipt.Status == "not_found" || receipt.Status == "running" || receipt.Status == "unknown" {
		if receipt.Result != nil {
			return nil, false, errors.New("invalid incomplete code receipt")
		}
		return nil, false, nil
	}
	r := receipt.Result
	if receipt.Status != "completed" || r == nil || r.Version != "code-execution/v1" || !r.ContainerRemoved || r.Limits != permit.Limits || len(r.Stdout) > permit.Limits.OutputBytes || len(r.Stderr) > permit.Limits.OutputBytes || r.StartedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) || r.DurationMS < 0 {
		return nil, false, errors.New("code result invalid")
	}
	// Completed receipt means execution ended, not that the code succeeded.
	status := "failed"
	switch r.Status {
	case "succeeded":
		if r.ExitCode != 0 || r.ErrorType != "" || r.OutputTruncated {
			return nil, false, errors.New("code success receipt invalid")
		}
		status = "succeeded"
	case "failed":
		if r.ErrorType != "CODE_EXITED" {
			return nil, false, errors.New("code failure receipt invalid")
		}
	case "timed_out":
		if r.ErrorType != "TIME_LIMIT" {
			return nil, false, errors.New("code timeout receipt invalid")
		}
		status = "timeout"
	case "cancelled":
		if r.ErrorType != "CANCELLED" {
			return nil, false, errors.New("code cancellation receipt invalid")
		}
		status = "cancelled"
	case "resource_limit":
		if r.ErrorType != "RESOURCE_LIMIT" {
			return nil, false, errors.New("code resource receipt invalid")
		}
	case "output_limit":
		if r.ErrorType != "OUTPUT_LIMIT" || !r.OutputTruncated {
			return nil, false, errors.New("code output receipt invalid")
		}
	default:
		return nil, false, errors.New("code outcome invalid")
	}
	resourceUsage, err := protocol.NormalizeResourceUsage(r.ResourceUsage)
	if err != nil {
		return nil, false, errors.New("code resource measurement invalid")
	}
	r.ResourceUsage = resourceUsage
	if proof != nil {
		proof(r)
		// Cancellation reads only cleanup metadata, never a new Observation
		// containing the original stdout/stderr or sensitive business output.
		return nil, true, nil
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return nil, false, errors.New("code result unavailable")
	}
	var out map[string]any
	d = json.NewDecoder(bytes.NewReader(encoded))
	d.UseNumber()
	if d.Decode(&out) != nil {
		return nil, false, errors.New("code result unavailable")
	}
	scope := sharedkernel.Scope{TenantID: permit.TenantID, DepartmentID: permit.DepartmentID, ApplicationID: permit.ApplicationID, AgentID: permit.AgentID, AgentInstanceID: permit.AgentInstanceID, AgentVersionID: permit.AgentVersionID, InstallationID: permit.InstallationID, PrincipalID: permit.CallerID, PrincipalType: permit.CallerType, RunID: permit.RunID, SessionID: permit.SessionID, TraceID: permit.TraceID, AuthorizationEpoch: permit.AuthorizationEpoch}
	observation, safe := newToolObservation(scope, permit.ToolName, permit.CallID, &r.StartedAt, status, "completed", r.ErrorType, out)
	observation.ExecutionType = "code"
	observation.PolicySnapshotHash = permit.PolicyHash
	observation.FinishedAt = &r.FinishedAt
	observation.DurationMS = &r.DurationMS
	observation.TimingSource = "isolated_controller_wall_clock"
	observation.Truncated = observation.Truncated || r.OutputTruncated
	observation.ResourceUsage = resourceUsage
	return storedToolObservation(observation, safe), true, nil
}
