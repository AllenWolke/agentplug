package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/reversibleapi"
)

// Only the documented reversible protocol is supported. This is not a switch
// to turn an arbitrary irreversible POST/MCP tool into a compensable write.
type ReversibleAPIBinding struct {
	ToolName         string   `json:"tool_name"`
	Endpoint         string   `json:"endpoint"`
	TenantID         string   `json:"tenant_id"`
	ApplicationID    string   `json:"application_id"`
	AgentIDs         []string `json:"agent_ids"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	ForwardSecretRef string   `json:"forward_secret_ref"`
	ControlSecretRef string   `json:"control_secret_ref"`
}
type reversibleAPIBound struct {
	binding ReversibleAPIBinding
	client  *http.Client
}
type ReversibleAPIToolProvider struct {
	tools   map[string]reversibleAPIBound
	secrets modelgateway.SecretResolver
	version string
}

func NewReversibleAPIToolProvider(bindings []ReversibleAPIBinding, secrets modelgateway.SecretResolver, development bool, factory func(string, bool) (*http.Client, error)) (*ReversibleAPIToolProvider, error) {
	if len(bindings) == 0 || len(bindings) > 16 || secrets == nil || factory == nil {
		return nil, compensation.ErrInvalid
	}
	p := &ReversibleAPIToolProvider{tools: map[string]reversibleAPIBound{}, secrets: secrets}
	canonical := []string{}
	for _, b := range bindings {
		if !strings.HasPrefix(b.ToolName, "api.") || !codeIdentifier(b.ToolName) || p.Supports(b.ToolName) || !codeIdentifier(b.TenantID) || !codeIdentifier(b.ApplicationID) || len(b.AgentIDs) == 0 || len(b.AgentIDs) > 32 || b.TimeoutSeconds < 1 || b.TimeoutSeconds > 5 || b.ForwardSecretRef == "" || b.ControlSecretRef == "" || b.ForwardSecretRef == b.ControlSecretRef {
			return nil, compensation.ErrInvalid
		}
		u, err := url.Parse(b.Endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
			return nil, compensation.ErrInvalid
		}
		seen := map[string]bool{}
		for _, id := range b.AgentIDs {
			if !codeIdentifier(id) || seen[id] {
				return nil, compensation.ErrInvalid
			}
			seen[id] = true
		}
		b.AgentIDs = append([]string(nil), b.AgentIDs...)
		sort.Strings(b.AgentIDs)
		b.Endpoint = strings.TrimSuffix(b.Endpoint, "/")
		client, err := factory(b.Endpoint, development)
		if err != nil || client == nil || client.Transport == nil {
			return nil, compensation.ErrUnavailable
		}
		frozen := *client
		frozen.Timeout = time.Duration(b.TimeoutSeconds) * time.Second
		frozen.CheckRedirect = func(*http.Request, []*http.Request) error { return compensation.ErrConflict }
		p.tools[b.ToolName] = reversibleAPIBound{b, &frozen}
		raw, _ := json.Marshal(b)
		canonical = append(canonical, string(raw))
	}
	sort.Strings(canonical)
	p.version = "reversible-api.v1." + reversibleapi.Hash(canonical)
	return p, nil
}
func (p *ReversibleAPIToolProvider) Supports(name string) bool {
	if p == nil {
		return false
	}
	_, found := p.tools[name]
	return found
}
func (p *ReversibleAPIToolProvider) RegisteredTools() []string {
	names := []string{}
	if p != nil {
		for name := range p.tools {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
func (p *ReversibleAPIToolProvider) DescribeTool(name string) (RuntimeToolDescriptor, bool) {
	if p == nil {
		return RuntimeToolDescriptor{}, false
	}
	b, found := p.tools[name]
	return RuntimeToolDescriptor{ExecutionType: "api", Risk: "high", TimeoutSeconds: b.binding.TimeoutSeconds}, found
}
func (p *ReversibleAPIToolProvider) step(q ToolReceiptQuery) (compensation.Step, error) {
	if p == nil || q.Scope.ValidateTrusted() != nil || !codeIdentifier(q.CallID) || !auditRuntimeDigest(q.Fingerprint) {
		return compensation.Step{}, compensation.ErrInvalid
	}
	b, found := p.tools[q.Name]
	allowed := false
	for _, id := range b.binding.AgentIDs {
		if id == q.Scope.AgentID {
			allowed = true
		}
	}
	if !found || !allowed || b.binding.TenantID != q.Scope.TenantID || b.binding.ApplicationID != q.Scope.ApplicationID {
		return compensation.Step{}, compensation.ErrConflict
	}
	s := compensation.Step{Root: q.Scope, Scope: q.Scope, ID: compensation.StepID(q.Scope, "api", q.CallID), Kind: "api", Tool: q.Name, Provider: reversibleapi.Provider, ProviderVersion: p.version, CallID: q.CallID, Fingerprint: q.Fingerprint, Ref: reversibleapi.Hash([]string{ToolReceiptScopeHash(q.Scope), q.CallID})}
	return s, s.Validate()
}
func (p *ReversibleAPIToolProvider) ValidateToolCommand(c ToolCommand) error {
	fp, err := ToolCommandFingerprint(c.Name, c.Payload)
	if err != nil {
		return compensation.ErrInvalid
	}
	if _, err = p.step(ToolReceiptQuery{Scope: c.Scope, Name: c.Name, CallID: c.CallID, Fingerprint: fp}); err != nil {
		return err
	}
	key, ok := c.Payload["key"].(string)
	value, valid := c.Payload["value"].(string)
	if len(c.Payload) != 2 || !ok || !valid || key == "" || len(key) > 128 || len(value) > 16384 || strings.ContainsAny(key, "\r\n\x00") {
		return compensation.ErrInvalid
	}
	return nil
}
func (p *ReversibleAPIToolProvider) request(ctx context.Context, s compensation.Step, action string, payload map[string]any) (reversibleapi.Response, error) {
	b, found := p.tools[s.Tool]
	if !found {
		return reversibleapi.Response{}, compensation.ErrUnavailable
	}
	secretRef := b.binding.ControlSecretRef
	if action == "apply" {
		secretRef = b.binding.ForwardSecretRef
	}
	secret, err := p.secrets.ResolveSecret(ctx, secretRef)
	defer clear(secret)
	if err != nil || len(secret) < 32 || len(secret) > 8192 || strings.ContainsAny(string(secret), "\r\n\x00") {
		return reversibleapi.Response{}, compensation.ErrUnavailable
	}
	body, err := json.Marshal(reversibleapi.Request{Version: reversibleapi.Protocol, Action: action, Step: s, Payload: payload})
	if err != nil || len(body) > 32768 {
		return reversibleapi.Response{}, compensation.ErrInvalid
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(b.binding.TimeoutSeconds)*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(callCtx, http.MethodPost, b.binding.Endpoint+"/v1/effects", bytes.NewReader(body))
	if err != nil {
		return reversibleapi.Response{}, compensation.ErrInvalid
	}
	r.Header.Set("Authorization", "Bearer "+string(secret))
	r.Header.Set("Content-Type", "application/json")
	response, err := b.client.Do(r)
	if err != nil {
		return reversibleapi.Response{}, compensation.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return reversibleapi.Response{}, compensation.ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return reversibleapi.Response{}, compensation.ErrUnavailable
	}
	var result reversibleapi.Response
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Version != reversibleapi.Protocol || result.StepDigest != s.Digest() {
		return result, compensation.ErrConflict
	}
	if result.Receipt != nil && result.Receipt.Validate(s) != nil {
		return result, compensation.ErrConflict
	}
	return result, nil
}
func (p *ReversibleAPIToolProvider) Invoke(ctx context.Context, c ToolCommand) (map[string]any, error) {
	if err := p.ValidateToolCommand(c); err != nil {
		return nil, ToolNoEffectError{Err: err}
	}
	fp, _ := ToolCommandFingerprint(c.Name, c.Payload)
	auth, ok := ctx.Value(runtimeExecutionAuthorizationKey{}).(runtimeExecutionAuthorization)
	lease, leased := ctx.Value(toolLeaseContextKey{}).(ToolExecutionLease)
	approval := auth.Approval
	if !ok || !leased || lease.ScopeHash != ToolReceiptScopeHash(c.Scope) || lease.CallID != c.CallID || lease.Fingerprint != fp || lease.Token == "" || lease.Fence == 0 || !lease.Until.After(time.Now()) || approval.ScopeHash != lease.ScopeHash || approval.ActorID != c.Scope.PrincipalID || approval.ToolName != c.Name || approval.CallID != c.CallID || approval.Fingerprint != fp || approval.PolicyHash != auth.PolicyHash || approval.AuthorizationEpoch != c.Scope.AuthorizationEpoch || approval.ExpiresAt <= time.Now().Unix() {
		return nil, ToolNoEffectError{Err: compensation.ErrConflict}
	}
	s, err := p.step(ToolReceiptQuery{Scope: c.Scope, Name: c.Name, CallID: c.CallID, Fingerprint: fp})
	if err != nil {
		return nil, ToolNoEffectError{Err: err}
	}
	result, err := p.request(ctx, s, "apply", c.Payload)
	// After transport submission, a failure is UNKNOWN; never label no effect.
	if err != nil || result.State != "applied" || result.ForwardClosed {
		return nil, compensation.ErrUnavailable
	}
	return map[string]any{"state": "applied", "operation_id": s.ID}, nil
}

type reversibleAPICancellationPort struct {
	provider *ReversibleAPIToolProvider
	ledger   compensation.EffectRegistry
	tools    *SQLToolInvocationStore
}

func (p *ReversibleAPIToolProvider) CancellationBinding(ledger compensation.EffectRegistry, tools *SQLToolInvocationStore) (RuntimeCancellationBinding, error) {
	if p == nil || ledger == nil || tools == nil {
		return RuntimeCancellationBinding{}, compensation.ErrUnavailable
	}
	return RuntimeCancellationBinding{Registration: compensation.Registration{Provider: reversibleapi.Provider, Version: p.version, Timeout: 15 * time.Second, Port: &reversibleAPICancellationPort{p, ledger, tools}}, Tools: p.RegisteredTools(), Step: p.step}, nil
}
func (p *reversibleAPICancellationPort) request(ctx context.Context, s compensation.Step, action string) (reversibleapi.Response, error) {
	if _, err := compensation.LeaseFromContext(ctx, s); err != nil {
		return reversibleapi.Response{}, err
	}
	tx, err := p.tools.db.BeginTx(ctx, nil)
	if err != nil {
		return reversibleapi.Response{}, err
	}
	defer tx.Rollback()
	if err = p.ledger.GuardRegisteredStopTx(ctx, tx, s); err != nil {
		return reversibleapi.Response{}, err
	}
	fact, err := p.tools.ReadCancellationToolTx(ctx, tx, s.Scope, s.CallID)
	if err != nil || fact.Phase != "executing" {
		return reversibleapi.Response{}, compensation.ErrConflict
	}
	expected, err := p.provider.step(fact.Query)
	descriptor, found := p.provider.DescribeTool(fact.Query.Name)
	if err != nil || expected.Digest() != s.Digest() || !found || fact.Query.RuntimeAudit == nil || descriptor != fact.Query.RuntimeAudit.Descriptor {
		return reversibleapi.Response{}, compensation.ErrConflict
	}
	if action == "undo" {
		lease, err := compensation.LeaseFromContext(ctx, s)
		if err != nil {
			return reversibleapi.Response{}, err
		}
		if err = p.ledger.GuardLeaseTx(ctx, tx, lease); err != nil {
			return reversibleapi.Response{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return reversibleapi.Response{}, err
	}
	return p.provider.request(ctx, s, action, nil)
}
func (p *reversibleAPICancellationPort) Lookup(ctx context.Context, s compensation.Step) (compensation.Receipt, bool, error) {
	r, err := p.request(ctx, s, "lookup")
	if err != nil {
		return compensation.Receipt{}, false, err
	}
	if r.Receipt == nil {
		return compensation.Receipt{}, false, nil
	}
	if !r.ForwardClosed {
		return compensation.Receipt{}, false, compensation.ErrConflict
	}
	return *r.Receipt, true, nil
}
func (p *reversibleAPICancellationPort) InspectOriginal(ctx context.Context, s compensation.Step) (compensation.OriginalEffect, error) {
	r, err := p.request(ctx, s, "close")
	if err != nil {
		return compensation.OriginalEffect{}, err
	}
	if !r.ForwardClosed || !auditRuntimeDigest(r.EvidenceDigest) || (r.State != "applied" && r.State != "no_effect") {
		return compensation.OriginalEffect{}, compensation.ErrPending
	}
	o := compensation.OriginalEffect{StepDigest: s.Digest(), State: r.State, EvidenceDigest: r.EvidenceDigest}
	return o, o.Validate(s)
}
func (p *reversibleAPICancellationPort) Compensate(ctx context.Context, s compensation.Step) (compensation.Receipt, error) {
	r, err := p.request(ctx, s, "undo")
	if err != nil {
		return compensation.Receipt{}, err
	}
	if !r.ForwardClosed || r.Receipt == nil {
		return compensation.Receipt{}, errors.Join(compensation.ErrPending, compensation.ErrUnavailable)
	}
	return *r.Receipt, r.Receipt.Validate(s)
}
