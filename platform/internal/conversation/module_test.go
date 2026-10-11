package conversation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type moduleStore struct {
	sessions      map[string]Summary
	messages      map[string][]Message
	shares        map[string]Share
	exports       map[string]Export
	deletions     map[string]DeletionRequest
	revisions     map[string][]Revision
	regenerations map[string]Regeneration
	policies      map[string]RetentionPolicy
	holds         map[string]LegalHold
	managedQuery  ManagedSearchQuery
	managedCalls  int
	messagePage   int
	messageSize   int
}

type stubRunStarter struct {
	runID       string
	messageID   string
	fingerprint string
	request     []byte
	called      bool
}

func (s *stubRunStarter) StartRun(_ context.Context, scope sharedkernel.Scope, runID, _, fingerprint, _ string, request []byte) (string, error) {
	if scope.RunID != runID {
		return "", errors.New("scope/run mismatch")
	}
	s.called = true
	s.runID = runID
	s.fingerprint = fingerprint
	s.request = append([]byte(nil), request...)
	return runID, nil
}

type stubRunPolicyResolver struct {
	policy map[string]any
	err    error
	called bool
}

func (s *stubRunPolicyResolver) ResolveAgentPolicy(_ context.Context, scope sharedkernel.Scope, versionID string) (map[string]any, error) {
	s.called = true
	if scope.AgentVersionID != versionID {
		return nil, errors.New("policy lookup did not use the pinned agent version")
	}
	return s.policy, s.err
}

func (s *stubRunStarter) StartRunWithMessage(ctx context.Context, scope sharedkernel.Scope, runID, idempotencyKey, fingerprint, endpoint string, request []byte, messageID string) (string, error) {
	s.messageID = messageID
	return s.StartRun(ctx, scope, runID, idempotencyKey, fingerprint, endpoint, request)
}

func newModuleStore() *moduleStore {
	return &moduleStore{sessions: make(map[string]Summary), messages: make(map[string][]Message), shares: make(map[string]Share), exports: make(map[string]Export), deletions: make(map[string]DeletionRequest), revisions: make(map[string][]Revision), regenerations: make(map[string]Regeneration), policies: make(map[string]RetentionPolicy), holds: make(map[string]LegalHold)}
}

func (s *moduleStore) EnsureSchema(context.Context) error { return nil }
func (s *moduleStore) Ping(context.Context) error         { return nil }
func (s *moduleStore) CreateSession(_ context.Context, scope Scope, session Session) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if session.ID == "" || session.Kind == "" {
		return ErrInvalidQuery
	}
	summary := session.Summary
	summary.OwnerID = scope.PrincipalID
	s.sessions[session.ID] = summary
	return nil
}
func (s *moduleStore) AppendMessage(_ context.Context, scope Scope, message Message) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if session, ok := s.sessions[message.SessionID]; !ok || session.OwnerID != scope.PrincipalID {
		return ErrNotFound
	}
	s.messages[message.SessionID] = append(s.messages[message.SessionID], message)
	return nil
}
func (s *moduleStore) List(_ context.Context, scope Scope, _ Query) (Page, error) {
	if err := scope.Validate(); err != nil {
		return Page{}, err
	}
	items := make([]Summary, 0, len(s.sessions))
	for _, item := range s.sessions {
		if item.OwnerID == scope.PrincipalID {
			items = append(items, item)
		}
	}
	return Page{Items: items, Total: int64(len(items)), Page: 1, Size: 20}, nil
}
func (s *moduleStore) SearchManaged(_ context.Context, query ManagedSearchQuery) (Page, error) {
	s.managedQuery = query
	s.managedCalls++
	return Page{Items: []Summary{{ID: "managed-session", Kind: query.Kind, Title: query.Text}}, Total: 1, Page: query.Page, Size: query.PageSize}, nil
}
func (s *moduleStore) Detail(_ context.Context, scope Scope, id string) (Summary, error) {
	if err := scope.Validate(); err != nil {
		return Summary{}, err
	}
	item, ok := s.sessions[id]
	if !ok || item.OwnerID != scope.PrincipalID {
		return Summary{}, ErrNotFound
	}
	return item, nil
}
func (s *moduleStore) Resume(ctx context.Context, scope Scope, id string) (Summary, error) {
	return s.Detail(ctx, scope, id)
}
func (s *moduleStore) ListMessages(_ context.Context, scope Scope, id string, page, size int) ([]Message, int64, error) {
	s.messagePage, s.messageSize = page, size
	if _, err := s.Detail(context.Background(), scope, id); err != nil {
		return nil, 0, err
	}
	items := s.messages[id]
	return items, int64(len(items)), nil
}
func (s *moduleStore) ListRevisions(_ context.Context, scope Scope, sessionID, messageID string) ([]Revision, error) {
	if _, err := s.Detail(context.Background(), scope, sessionID); err != nil {
		return nil, err
	}
	items := s.revisions[sessionID+"/"+messageID]
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	return items, nil
}
func (s *moduleStore) ReviseMessage(_ context.Context, scope Scope, sessionID, messageID, content, reason string, base uint64) (Revision, error) {
	if _, err := s.Detail(context.Background(), scope, sessionID); err != nil {
		return Revision{}, err
	}
	key := sessionID + "/" + messageID
	items := s.revisions[key]
	if (len(items) == 0 && base != 0) || (len(items) > 0 && base != items[len(items)-1].RevisionNo) {
		return Revision{}, ErrRevisionConflict
	}
	item := Revision{ID: "rev-" + fmt.Sprint(len(items)+1), SessionID: sessionID, MessageID: messageID, Role: "user", Content: content, Reason: reason, RevisionNo: uint64(len(items) + 1), IsCurrent: true}
	for i := range items {
		items[i].IsCurrent = false
	}
	s.revisions[key] = append(items, item)
	return item, nil
}

func (s *moduleStore) Regenerate(_ context.Context, scope Scope, sessionID, messageID, versionMode string) (Regeneration, error) {
	if _, err := s.Detail(context.Background(), scope, sessionID); err != nil {
		return Regeneration{}, err
	}
	if _, ok := s.messages[sessionID]; !ok {
		return Regeneration{}, ErrNotFound
	}
	if versionMode == "" {
		versionMode = "original_snapshot"
	}
	item := Regeneration{ID: "regen-1", SessionID: sessionID, MessageID: messageID, BranchSessionID: "branch-1", VersionMode: versionMode, Status: "queued"}
	s.regenerations[sessionID+messageID+versionMode] = item
	return item, nil
}

func (s *moduleStore) CreateShare(_ context.Context, scope Scope, request ShareRequest) (Share, error) {
	if _, err := s.Detail(context.Background(), scope, request.SessionID); err != nil {
		return Share{}, err
	}
	item := Share{ID: "share-1", Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SessionID: request.SessionID, OwnerID: scope.PrincipalID, Status: "active", ExpiresAt: time.Now().Add(time.Hour), IncludeRefs: request.IncludeRefs}
	s.shares[item.ID] = item
	return item, nil
}
func (s *moduleStore) RevokeShare(_ context.Context, scope Scope, id string) (Share, error) {
	item, ok := s.shares[id]
	if !ok || item.OwnerID != scope.PrincipalID {
		return Share{}, ErrNotFound
	}
	item.Status = "revoked"
	s.shares[id] = item
	return item, nil
}
func (s *moduleStore) ReadPublicShare(_ context.Context, token string, page, pageSize int) (SharedConversation, error) {
	for _, share := range s.shares {
		if share.Token != token || share.Status != "active" || !share.ExpiresAt.After(time.Now()) {
			continue
		}
		summary := s.sessions[share.SessionID]
		messages := s.messages[share.SessionID]
		if len(messages) > pageSize {
			messages = messages[(page-1)*pageSize:]
		}
		out := SharedConversation{SessionID: summary.ID, Kind: summary.Kind, Title: summary.Title, ExpiresAt: share.ExpiresAt, TotalMessages: int64(len(s.messages[share.SessionID])), Page: page, PageSize: pageSize, IncludeReferences: share.IncludeRefs}
		for _, item := range messages {
			shared := SharedMessage{Role: item.Role, Content: item.Content, CreatedAt: item.CreatedAt}
			if share.IncludeRefs {
				shared.References = referencesFromMetadata(item.Metadata)
			}
			out.Messages = append(out.Messages, shared)
		}
		return out, nil
	}
	return SharedConversation{}, ErrNotFound
}
func (s *moduleStore) CreateExport(_ context.Context, scope Scope, request ExportRequest) (Export, error) {
	if len(request.SessionIDs) != 1 {
		return Export{}, ErrInvalidQuery
	}
	if _, err := s.Detail(context.Background(), scope, request.SessionIDs[0]); err != nil {
		return Export{}, err
	}
	item := Export{ID: "export-1", SessionID: request.SessionIDs[0], OwnerID: scope.PrincipalID, Status: "pending"}
	s.exports[item.ID] = item
	return item, nil
}
func (s *moduleStore) GetExport(_ context.Context, scope Scope, id string) (Export, error) {
	item, ok := s.exports[id]
	if !ok || (scope.PrincipalType != "service_principal" && item.OwnerID != scope.PrincipalID) {
		return Export{}, ErrNotFound
	}
	return item, nil
}
func (s *moduleStore) ApproveExport(ctx context.Context, scope Scope, id string) (Export, error) {
	if scope.PrincipalType != "service_principal" {
		return Export{}, ErrForbidden
	}
	item, err := s.GetExport(ctx, scope, id)
	if err != nil {
		return Export{}, err
	}
	item.Status = "approved"
	s.exports[id] = item
	return item, nil
}
func (s *moduleStore) RequestDeletion(_ context.Context, scope Scope, request DeleteRequest) (DeletionRequest, error) {
	if len(request.SessionIDs) != 1 {
		return DeletionRequest{}, ErrInvalidQuery
	}
	if _, err := s.Detail(context.Background(), scope, request.SessionIDs[0]); err != nil {
		return DeletionRequest{}, err
	}
	item := DeletionRequest{ID: "delete-1", SessionID: request.SessionIDs[0], OwnerID: scope.PrincipalID, Reason: request.Reason, Status: "pending"}
	s.deletions[item.ID] = item
	return item, nil
}
func (s *moduleStore) ListDeletionRequests(_ context.Context, scope Scope, _, _ int) ([]DeletionRequest, int64, error) {
	items := make([]DeletionRequest, 0)
	for _, item := range s.deletions {
		if scope.PrincipalType == "service_principal" || item.OwnerID == scope.PrincipalID {
			items = append(items, item)
		}
	}
	return items, int64(len(items)), nil
}
func (s *moduleStore) ApproveDeletion(_ context.Context, scope Scope, id string) (DeletionRequest, error) {
	if scope.PrincipalType != "service_principal" {
		return DeletionRequest{}, ErrForbidden
	}
	item, ok := s.deletions[id]
	if !ok || item.OwnerID == scope.PrincipalID {
		return DeletionRequest{}, ErrNotFound
	}
	item.Status = "approved"
	s.deletions[id] = item
	return item, nil
}

func (s *moduleStore) ListDeletionRequestsForManagement(_ context.Context, scope Scope, page, size int) ([]DeletionRequest, int64, error) {
	if err := scope.Validate(); err != nil {
		return nil, 0, err
	}
	items := make([]DeletionRequest, 0, len(s.deletions))
	for _, item := range s.deletions {
		items = append(items, item)
	}
	return items, int64(len(items)), nil
}

func (s *moduleStore) ApproveDeletionByUser(_ context.Context, scope Scope, id string) (DeletionRequest, error) {
	item, ok := s.deletions[id]
	if !ok || item.OwnerID == scope.PrincipalID {
		return DeletionRequest{}, ErrForbidden
	}
	item.Status = "approved"
	s.deletions[id] = item
	return item, nil
}

func (s *moduleStore) GetRetentionPolicy(_ context.Context, scope Scope, kind string) (RetentionPolicy, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return RetentionPolicy{}, err
	}
	item, ok := s.policies[kind]
	if !ok {
		return RetentionPolicy{}, ErrNotFound
	}
	return item, nil
}
func (s *moduleStore) PutRetentionPolicy(_ context.Context, scope Scope, item RetentionPolicy) (RetentionPolicy, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return RetentionPolicy{}, err
	}
	if item.RetentionDays < 1 {
		return RetentionPolicy{}, ErrRetentionPolicy
	}
	item.ID, item.UpdatedBy, item.Revision, item.UpdatedAt = "retention-"+item.Kind, scope.PrincipalID, 1, time.Now().UTC()
	s.policies[item.Kind] = item
	return item, nil
}
func (s *moduleStore) PlaceLegalHold(_ context.Context, scope Scope, request LegalHoldRequest) (LegalHold, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return LegalHold{}, err
	}
	if _, ok := s.sessions[request.SessionID]; !ok {
		return LegalHold{}, ErrNotFound
	}
	item := LegalHold{ID: "hold-1", SessionID: request.SessionID, Reason: request.Reason, Status: "active", PlacedBy: scope.PrincipalID, CreatedAt: time.Now().UTC()}
	s.holds[item.ID] = item
	return item, nil
}
func (s *moduleStore) ListLegalHolds(_ context.Context, scope Scope, _, _ int) ([]LegalHold, int64, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return nil, 0, err
	}
	items := make([]LegalHold, 0, len(s.holds))
	for _, item := range s.holds {
		items = append(items, item)
	}
	return items, int64(len(items)), nil
}
func (s *moduleStore) ReleaseLegalHold(_ context.Context, scope Scope, id string) (LegalHold, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return LegalHold{}, err
	}
	item, ok := s.holds[id]
	if !ok {
		return LegalHold{}, ErrNotFound
	}
	now := time.Now().UTC()
	item.Status, item.ReleasedBy, item.ReleasedAt = "released", scope.PrincipalID, &now
	s.holds[id] = item
	return item, nil
}
func (s *moduleStore) SweepExpired(_ context.Context, scope Scope, _ time.Time, _ int) (RetentionSweep, error) {
	if err := requireGovernanceScope(scope); err != nil {
		return RetentionSweep{}, err
	}
	return RetentionSweep{}, nil
}

func requestHeaders(req *http.Request, principal string) {
	req.Header.Set("X-Internal-Token", "module-token")
	req.Header.Set("X-Tenant-ID", "tenant")
	req.Header.Set("X-Department-ID", "department")
	req.Header.Set("X-Application-ID", "application")
	req.Header.Set("X-Principal-Type", "user")
	req.Header.Set("X-Principal-ID", principal)
}

func TestManagedSearchUsesIdentityRolesAndTenantBoundary(t *testing.T) {
	store := newModuleStore()
	module := NewModule(store, "module-token", false)
	roles := []string{"platform_admin"}
	module.SetPrincipalRoleResolver(func(_ context.Context, scope Scope) ([]string, error) {
		if scope.PrincipalID != "admin-user" {
			return nil, ErrForbidden
		}
		return roles, nil
	})
	server := httptest.NewServer(module.Handler())
	defer server.Close()
	call := func(query string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/managed-search"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		requestHeaders(req, "admin-user")
		req.Header.Set("X-Browser-Module", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := call("?tenant_id=other-tenant&kind=qa&q=loan&page=2&page_size=10")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("platform admin cross-tenant status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if store.managedCalls != 0 {
		t.Fatal("cross-tenant query reached the store")
	}
	resp = call("?kind=qa&q=loan&page=2&page_size=10")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-tenant search status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if store.managedCalls != 1 || store.managedQuery.TenantID != "tenant" || store.managedQuery.Kind != "qa" || store.managedQuery.Text != "loan" || store.managedQuery.Page != 2 || store.managedQuery.PageSize != 10 {
		t.Fatalf("search query was not constrained/forwarded: calls=%d query=%+v", store.managedCalls, store.managedQuery)
	}
	roles = []string{"application_admin"}
	resp = call("?kind=check")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("application admin global-search status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	roles = []string{"system_admin"}
	resp = call("?tenant_id=other-tenant&application_id=app-2&kind=check")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("system admin scoped search status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if store.managedQuery.TenantID != "other-tenant" || store.managedQuery.ApplicationID != "app-2" {
		t.Fatalf("system-admin filters not preserved: %+v", store.managedQuery)
	}
}

func TestManagedSearchRejectsInvalidQueryAndMissingIdentityAdapter(t *testing.T) {
	store := newModuleStore()
	module := NewModule(store, "module-token", false)
	server := httptest.NewServer(module.Handler())
	defer server.Close()
	for _, target := range []string{"/managed-search?kind=unknown", "/managed-search?q=" + strings.Repeat("x", 257)} {
		req, _ := http.NewRequest(http.MethodGet, server.URL+target, nil)
		requestHeaders(req, "admin-user")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("search without Identity role resolver status=%d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
	module.SetPrincipalRoleResolver(func(context.Context, Scope) ([]string, error) { return []string{"system_admin"}, nil })
	for _, target := range []string{"/managed-search?kind=unknown", "/managed-search?q=" + strings.Repeat("x", 257)} {
		req, _ := http.NewRequest(http.MethodGet, server.URL+target, nil)
		requestHeaders(req, "admin-user")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid managed search query status=%d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

var _ ManagedSearchReader = (*SQLStore)(nil)

func TestModuleUsesStableSnakeCaseJSONAndScopeIsolation(t *testing.T) {
	store := newModuleStore()
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()

	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","preview":"","message_count":0,"can_continue":true,"revision":1}`
	req, err := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	if err != nil {
		t.Fatal(err)
	}
	requestHeaders(req, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	_ = resp.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/sessions/session-1", nil)
	requestHeaders(req, "bob")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-principal detail status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	_ = resp.Body.Close()
}

func TestModuleNormalizesMessagePagination(t *testing.T) {
	store := newModuleStore()
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","can_continue":true}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/sessions/session-1/messages", nil)
	requestHeaders(req, "alice")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("messages status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
	if store.messagePage != 1 || store.messageSize != 20 {
		t.Fatalf("message pagination = page %d size %d, want page 1 size 20", store.messagePage, store.messageSize)
	}
}

func TestModuleGovernanceRoutesRequireSeparateApprover(t *testing.T) {
	store := newModuleStore()
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","preview":"","message_count":0,"can_continue":true,"revision":1}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create session status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	request := `{"ttl_seconds":3600,"include_refs":true}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/shares", strings.NewReader(request))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("share status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/deletion-requests", strings.NewReader(`{"session_ids":["session-1"],"reason":"retention request"}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deletion status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/deletion-requests/delete-1/approve", strings.NewReader(`{}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("self approval status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/deletion-requests/delete-1/approve", strings.NewReader(`{}`))
	requestHeaders(req, "retention-admin")
	req.Header.Set("X-Principal-Type", "service_principal")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("service approval status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestPublicConversationShareUsesCapabilityTokenAndReadOnlyProjection(t *testing.T) {
	store := newModuleStore()
	store.sessions["session-1"] = Summary{ID: "session-1", Kind: "qa", Title: "问答会话", OwnerID: "alice", CanContinue: true}
	store.messages["session-1"] = []Message{{ID: "message-1", SessionID: "session-1", Role: "agent", Content: "只读回答", Metadata: map[string]any{"references": []any{"secret-reference"}, "internal": "must-not-leak"}}}
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()

	create, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/shares", strings.NewReader(`{"ttl_seconds":3600,"include_refs":false}`))
	requestHeaders(create, "alice")
	created, err := http.DefaultClient.Do(create)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Body.Close()
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create share status=%d", created.StatusCode)
	}
	var share Share
	if err := json.NewDecoder(created.Body).Decode(&share); err != nil {
		t.Fatal(err)
	}
	if !validShareToken(share.Token) || share.Token == share.ID {
		t.Fatalf("share must return a separate 256-bit capability token: %+v", share)
	}

	// A public capability request intentionally needs no browser identity or
	// tenant headers; the unguessable token itself is the authority.
	public, _ := http.NewRequest(http.MethodGet, server.URL+"/shares/"+share.Token, nil)
	response, err := http.DefaultClient.Do(public)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store, private" {
		t.Fatalf("public share status=%d headers=%v", response.StatusCode, response.Header)
	}
	var view SharedConversation
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.SessionID != "session-1" || view.IncludeReferences || len(view.Messages) != 1 || view.Messages[0].Content != "只读回答" || len(view.Messages[0].References) != 0 {
		t.Fatalf("unexpected public projection: %+v", view)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), "alice") || strings.Contains(string(encoded), "must-not-leak") {
		t.Fatalf("public share leaked owner or internal metadata: %s", encoded)
	}

	invalid, _ := http.Get(server.URL + "/shares/not-a-capability")
	if invalid.StatusCode != http.StatusNotFound {
		t.Fatalf("invalid share token status=%d", invalid.StatusCode)
	}
	_ = invalid.Body.Close()

	revoke, _ := http.NewRequest(http.MethodPost, server.URL+"/shares/"+share.ID+"/revoke", strings.NewReader(`{}`))
	requestHeaders(revoke, "alice")
	revoked, err := http.DefaultClient.Do(revoke)
	if err != nil || revoked.StatusCode != http.StatusOK {
		t.Fatalf("revoke status=%v err=%v", revoked.StatusCode, err)
	}
	_ = revoked.Body.Close()
	afterRevoke, _ := http.Get(server.URL + "/shares/" + share.Token)
	if afterRevoke.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked capability status=%d", afterRevoke.StatusCode)
	}
	_ = afterRevoke.Body.Close()
}

func TestShareCapabilityTokenIsUnpredictableAndURLSafe(t *testing.T) {
	first, err := randomShareToken(32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomShareToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !validShareToken(first) || strings.ContainsAny(first, "/+=") {
		t.Fatalf("invalid or repeated capability tokens: %q %q", first, second)
	}
	for _, invalid := range []string{"", "not-a-token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if validShareToken(invalid) {
			t.Fatalf("accepted malformed share token %q", invalid)
		}
	}
}

func TestBrowserDeletionGovernanceUsesIdentityRolesAndCompleteScope(t *testing.T) {
	store := newModuleStore()
	store.deletions["delete-1"] = DeletionRequest{ID: "delete-1", SessionID: "session-1", OwnerID: "alice", Status: "pending"}
	module := NewModule(store, "module-token", false)
	module.SetPrincipalRoleResolver(func(_ context.Context, scope Scope) ([]string, error) {
		if scope.PrincipalID == "reviewer" {
			return []string{"application_admin"}, nil
		}
		return []string{"operator"}, nil
	})
	server := httptest.NewServer(module.Handler())
	defer server.Close()

	request := func(method, path, principal string) *http.Response {
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		requestHeaders(req, principal)
		req.Header.Set("X-Browser-Module", "1")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	denied := request(http.MethodGet, "/deletion-requests", "alice")
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin list status=%d, want 403", denied.StatusCode)
	}
	_ = denied.Body.Close()

	listed := request(http.MethodGet, "/deletion-requests?page=1&page_size=20", "reviewer")
	if listed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listed.Body)
		t.Fatalf("admin list status=%d body=%s", listed.StatusCode, body)
	}
	var page struct {
		Items []DeletionRequest `json:"items"`
	}
	if err := json.NewDecoder(listed.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	_ = listed.Body.Close()
	if len(page.Items) != 1 || page.Items[0].OwnerID != "alice" {
		t.Fatalf("scoped admin listing did not include the requester: %+v", page.Items)
	}

	approved := request(http.MethodPost, "/deletion-requests/delete-1/approve", "reviewer")
	if approved.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approved.Body)
		t.Fatalf("admin approval status=%d body=%s", approved.StatusCode, body)
	}
	_ = approved.Body.Close()
	if store.deletions["delete-1"].Status != "approved" {
		t.Fatalf("approval did not update the persisted request: %+v", store.deletions["delete-1"])
	}
}

func TestAppendMessageUsesRouteSessionAndRejectsSubstitution(t *testing.T) {
	store := newModuleStore()
	handler := NewModule(store, "module-token", false).Handler()
	call := func(path, body, principal string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		requestHeaders(req, principal)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	created := call("/sessions", `{"id":"session-1","kind":"qa","agent_id":"qa","agent_version_id":"v2","status":"active"}`, "alice")
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	for _, test := range []struct {
		body, principal string
		status          int
	}{
		{`{"id":"m1","role":"user","content":"question"}`, "alice", http.StatusCreated},
		{`{"id":"m2","session_id":"another-session","role":"user","content":"question"}`, "alice", http.StatusBadRequest},
		{`{"id":"m3","role":"user","content":"question"}`, "bob", http.StatusNotFound},
	} {
		response := call("/sessions/session-1/messages", test.body, test.principal)
		if response.Code != test.status {
			t.Fatalf("status=%d expected=%d body=%s", response.Code, test.status, response.Body.String())
		}
	}
	// Only the owner's accepted request may be written. / 仅写入所有者的合法请求。
	if len(store.messages["session-1"]) != 1 || store.messages["session-1"][0].SessionID != "session-1" {
		t.Fatal("unexpected message writes")
	}
}

func TestModuleRevisionRoutesUseCASAndScope(t *testing.T) {
	store := newModuleStore()
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","preview":"","message_count":0,"can_continue":true,"revision":1}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/messages", strings.NewReader(`{"id":"message-1","session_id":"session-1","role":"user","content":"old"}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("message status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/messages/message-1/revisions", strings.NewReader(`{"content":"new","reason":"clarify","base_revision":0}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("revision status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/messages/message-1/revisions", strings.NewReader(`{"content":"stale","base_revision":0}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale revision status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/sessions/session-1/messages/message-1/revisions", nil)
	requestHeaders(req, "bob")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-principal revisions status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestModuleRetentionAndLegalHoldRequireGovernanceIdentity(t *testing.T) {
	store := newModuleStore()
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","can_continue":true}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPut, server.URL+"/retention-policy", strings.NewReader(`{"kind":"qa","retention_days":30,"enabled":true}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ordinary user retention status=%d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPut, server.URL+"/retention-policy", strings.NewReader(`{"kind":"qa","retention_days":30,"enabled":true}`))
	requestHeaders(req, "retention-admin")
	req.Header.Set("X-Principal-Type", "service_principal")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("service retention status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/legal-holds", strings.NewReader(`{"session_id":"session-1","reason":"legal review"}`))
	requestHeaders(req, "retention-admin")
	req.Header.Set("X-Principal-Type", "service_principal")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("place hold status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/legal-holds?page=1&page_size=20", nil)
	requestHeaders(req, "retention-admin")
	req.Header.Set("X-Principal-Type", "service_principal")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list holds status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/legal-holds/hold-1/release", strings.NewReader(`{}`))
	requestHeaders(req, "retention-admin")
	req.Header.Set("X-Principal-Type", "service_principal")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("release hold status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestModuleStartsRunThroughRuntimePortWithSessionScope(t *testing.T) {
	store := newModuleStore()
	starter := &stubRunStarter{}
	module := NewModule(store, "module-token", false)
	module.SetRunStarter(starter)
	server := httptest.NewServer(module.Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","can_continue":true}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	body := `{"run_id":"run-1","idempotency_key":"idem-1","message_id":"message-1","agent_endpoint":"http://qa-agent:8080","agent_instance_id":"qa-instance-1","installation_id":"install-qa","authorization_epoch":1,"request":{"question":"文档"}}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/runs", strings.NewReader(body))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("run start status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if !starter.called || starter.runID != "run-1" || starter.messageID != "message-1" || len(starter.fingerprint) != 64 {
		t.Fatalf("runtime starter not called: %+v", starter)
	}
}

func TestModuleResolvesRuntimeBindingInsteadOfTrustingBrowserTarget(t *testing.T) {
	store := newModuleStore()
	starter := &stubRunStarter{}
	module := NewModule(store, "module-token", false)
	module.SetRunStarter(starter)
	module.SetRuntimeBindingResolver(StaticRuntimeBindingResolver{
		"document-assistant": {
			AgentEndpoint: "http://qa-agent:8002", AgentInstanceID: "qa-instance",
			InstallationID: "qa-installation", AgentVersionID: "v2", AuthorizationEpoch: 7,
		},
	})
	server := httptest.NewServer(module.Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","can_continue":true}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	// Endpoint, installation and epoch are intentionally omitted: the resolver
	// supplies them from trusted platform configuration.
	body := `{"run_id":"run-1","idempotency_key":"idem-1","request":{"question":"文档"}}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/runs", strings.NewReader(body))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusAccepted || !starter.called || starter.runID != "run-1" || len(starter.fingerprint) != 64 {
		t.Fatalf("resolved run status=%d starter=%+v", resp.StatusCode, starter)
	}
	_ = resp.Body.Close()

	// A caller cannot force a stable hash for different request bodies and thus
	// cannot trick the idempotency repository into replaying the wrong answer.
	body = `{"run_id":"run-3","idempotency_key":"idem-3","fingerprint":"caller-controlled","request":{"question":"文档"}}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/runs", strings.NewReader(body))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched fingerprint status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// A browser-supplied target that disagrees with the resolver is rejected.
	body = `{"run_id":"run-2","idempotency_key":"idem-2","fingerprint":"fp-2","agent_endpoint":"http://attacker:9000","request":{"question":"越权"}}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/runs", strings.NewReader(body))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("binding mismatch status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestBrowserRunMaterializesPublishedPolicyAndSignsExactEnvelope(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := newModuleStore()
	starter := &stubRunStarter{}
	module := NewModule(store, "module-token", false)
	module.SetRunStarter(starter)
	module.SetRuntimeBindingResolver(StaticRuntimeBindingResolver{
		"document-assistant": {AgentEndpoint: "http://qa-agent:8002", AgentInstanceID: "qa-instance", InstallationID: "qa-install", AgentVersionID: "qa-v2", InputSchemaURI: "schema://document-assistant/input/v2", AuthorizationEpoch: 4},
	})
	policy := &stubRunPolicyResolver{policy: map[string]any{
		"content_hash": strings.Repeat("b", 64), "revision": 2,
		"model_profile_id": "model-qa", "prompt_version_id": "prompt-qa", "tool_policy_id": "tool-qa",
		"memory_policy_id": "memory-qa", "knowledge_policy_id": "knowledge-qa", "runtime_policy_id": "runtime-qa",
		"knowledge": map[string]any{"allowed_scopes": []string{"lexagent_local", "platform-knowledge", "both"}},
	}}
	module.SetRunPolicyResolver(policy)
	module.SetContextTokenSigner(Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime"})
	server := httptest.NewServer(module.Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"qa-v2","title":"history","status":"active","can_continue":true}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create session status=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()
	body := `{"run_id":"run-1","idempotency_key":"browser:run-1","message_id":"message-1","request":{"question":"口径是什么？","knowledge_scope":"platform-knowledge","policy_snapshot":{"content_hash":"` + strings.Repeat("c", 64) + `"}}}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/runs", strings.NewReader(body))
	requestHeaders(req, "alice")
	// Request IDs are often human-readable and must not be forwarded as trace IDs.
	// 请求 ID 通常可读且不符合 Trace ID 格式，不能原样透传。
	req.Header.Set("X-Trace-ID", "modular-frontend-smoke")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("run status=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()
	if !policy.called || !starter.called {
		t.Fatalf("expected policy resolution and run dispatch: policy=%v starter=%v", policy.called, starter.called)
	}
	var executeRequest contract.ExecuteRequest
	if err := json.Unmarshal(starter.request, &executeRequest); err != nil {
		t.Fatal(err)
	}
	if executeRequest.InputSchema != "schema://document-assistant/input/v2" {
		t.Fatalf("browser Run lost the published version's input schema: %q", executeRequest.InputSchema)
	}
	if !validTraceID(executeRequest.Scope.TraceID) || executeRequest.Scope.TraceID != NewContextTraceID("run-1") {
		t.Fatalf("invalid browser trace ID was not normalized: %q", executeRequest.Scope.TraceID)
	}
	snapshot := executeRequest.Input["policy_snapshot"].(map[string]any)
	if snapshot["content_hash"] != strings.Repeat("b", 64) {
		t.Fatalf("browser policy was not replaced by the published snapshot: %#v", snapshot)
	}
	parts := strings.Split(executeRequest.ContextToken, ".")
	if len(parts) != 3 || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), mustDecodeTokenSignature(t, parts[2])) {
		t.Fatal("browser run did not receive a valid platform signature")
	}
	var claims map[string]any
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimBytes, &claims) != nil {
		t.Fatalf("decode signed claims: %v", err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(executeRequest)
	if err != nil || claims["body_hash"] != bodyHash || claims["policy_snapshot_hash"] != strings.Repeat("b", 64) {
		t.Fatalf("signed body/policy mismatch: claims=%v hash=%s err=%v", claims, bodyHash, err)
	}
}

func TestBrowserRunFailsClosedWithoutPublishedPolicyResolver(t *testing.T) {
	store := newModuleStore()
	module := NewModule(store, "module-token", false)
	module.SetRunStarter(&stubRunStarter{})
	module.SetRuntimeBindingResolver(StaticRuntimeBindingResolver{
		"document-assistant": {AgentEndpoint: "http://qa-agent:8002", AgentInstanceID: "qa-instance", InstallationID: "qa-install", AgentVersionID: "qa-v2", AuthorizationEpoch: 4},
	})
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	module.SetContextTokenSigner(Ed25519ContextTokenSigner{PrivateKey: private, Issuer: "platform", Audience: "agent-runtime"})
	server := httptest.NewServer(module.Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"qa-v2","title":"history","status":"active","can_continue":true}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("create session status=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/runs", strings.NewReader(`{"run_id":"run-1","idempotency_key":"browser:run-1","request":{"question":"x"}}`))
	requestHeaders(req, "alice")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("missing policy resolver must fail closed, status=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()
}

func TestModuleRegenerationCreatesIndependentCommand(t *testing.T) {
	store := newModuleStore()
	server := httptest.NewServer(NewModule(store, "module-token", false).Handler())
	defer server.Close()
	create := `{"id":"session-1","kind":"qa","agent_id":"document-assistant","agent_version_id":"v2","title":"history","status":"active","preview":"","message_count":0,"can_continue":true,"revision":1}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/sessions", strings.NewReader(create))
	requestHeaders(req, "alice")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/messages", strings.NewReader(`{"id":"message-1","session_id":"session-1","role":"assistant","content":"old"}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("message status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/messages/message-1/regenerate", strings.NewReader(`{"version_mode":"current_release"}`))
	requestHeaders(req, "alice")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("regenerate status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/sessions/session-1/messages/message-1/regenerate", strings.NewReader(`{"version_mode":"current_release"}`))
	requestHeaders(req, "bob")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-principal regenerate status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
