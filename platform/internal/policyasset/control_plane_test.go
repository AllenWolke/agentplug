package policyasset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testAssetKey struct {
	scope Scope
	typ   AssetType
	id    string
}

func TestAssetIDIsPortableASCIIKey(t *testing.T) {
	for _, id := range []string{"model-1", "prompt.v2", "tool_policy:3", strings.Repeat("a", 128)} {
		if !validID(id) {
			t.Fatalf("valid asset id rejected: %q", id)
		}
	}
	for _, id := range []string{"", "中文", "has space", "path/escape", "a\\b", strings.Repeat("a", 129)} {
		if validID(id) {
			t.Fatalf("non-portable asset id accepted: %q", id)
		}
	}
}

type memoryControlStore struct {
	assets   map[testAssetKey]map[uint64]Asset
	current  map[testAssetKey]uint64
	snapshot map[Scope]Snapshot
}

func newMemoryControlStore() *memoryControlStore {
	return &memoryControlStore{assets: map[testAssetKey]map[uint64]Asset{}, current: map[testAssetKey]uint64{}, snapshot: map[Scope]Snapshot{}}
}
func (*memoryControlStore) EnsureSchema(context.Context) error { return nil }
func (*memoryControlStore) Ping(context.Context) error         { return nil }

func (s *memoryControlStore) CreateAsset(_ context.Context, asset Asset) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	key := testAssetKey{asset.Scope, asset.Type, asset.ID}
	if _, exists := s.current[key]; exists {
		return ErrAssetConflict
	}
	if asset.Revision != 1 || asset.Status != AssetDraft {
		return ErrInvalidAsset
	}
	s.assets[key] = map[uint64]Asset{asset.Revision: cloneAsset(asset)}
	s.current[key] = asset.Revision
	return nil
}

func (s *memoryControlStore) GetAsset(_ context.Context, scope Scope, typ AssetType, id string, revision uint64) (Asset, error) {
	key := testAssetKey{scope, typ, id}
	if revision == 0 {
		revision = s.current[key]
	}
	asset, ok := s.assets[key][revision]
	if !ok {
		return Asset{}, ErrAssetNotFound
	}
	return cloneAsset(asset), nil
}

func (s *memoryControlStore) ListAssets(_ context.Context, scope Scope, typ AssetType, limit int) ([]Asset, error) {
	items := make([]Asset, 0)
	for key, revision := range s.current {
		if key.scope == scope && (typ == "" || key.typ == typ) {
			items = append(items, cloneAsset(s.assets[key][revision]))
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (s *memoryControlStore) GetSnapshot(_ context.Context, scope Scope) (Snapshot, error) {
	snapshot, ok := s.snapshot[scope]
	if !ok {
		return Snapshot{}, ErrPolicyNotFound
	}
	return snapshot, nil
}

func (s *memoryControlStore) UpdateAsset(_ context.Context, scope Scope, typ AssetType, id string, expected uint64, content json.RawMessage) (Asset, error) {
	canonical, hash, err := canonicalContent(typ, content)
	if err != nil {
		return Asset{}, err
	}
	key := testAssetKey{scope, typ, id}
	if s.current[key] == 0 {
		return Asset{}, ErrAssetNotFound
	}
	if s.current[key] != expected {
		return Asset{}, ErrAssetConflict
	}
	previous := s.assets[key][expected]
	asset := Asset{ID: id, Type: typ, Scope: scope, Revision: expected + 1, Status: AssetDraft, Content: canonical, Hash: hash, CreatedBy: previous.CreatedBy}
	s.assets[key][asset.Revision] = asset
	s.current[key] = asset.Revision
	return cloneAsset(asset), nil
}

func (s *memoryControlStore) PublishAsset(_ context.Context, scope Scope, typ AssetType, id string, expected uint64) (Asset, error) {
	key := testAssetKey{scope, typ, id}
	if s.current[key] == 0 {
		return Asset{}, ErrAssetNotFound
	}
	if s.current[key] != expected {
		return Asset{}, ErrAssetConflict
	}
	previous := s.assets[key][expected]
	if previous.Status != AssetDraft {
		return Asset{}, ErrAssetConflict
	}
	asset := cloneAsset(previous)
	asset.Revision++
	asset.Status = AssetPublished
	s.assets[key][asset.Revision] = asset
	s.current[key] = asset.Revision
	return cloneAsset(asset), nil
}

func (s *memoryControlStore) PublishSnapshot(_ context.Context, req PublishSnapshotRequest) (Snapshot, error) {
	if err := req.Scope.validate(); err != nil || len(req.Assets) != 6 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	resolved := make(map[AssetType]Asset, 6)
	for typ, ref := range req.Assets {
		asset, err := s.GetAsset(context.Background(), req.Scope, typ, ref.ID, ref.Revision)
		if err != nil {
			return Snapshot{}, err
		}
		if asset.Status != AssetPublished {
			return Snapshot{}, ErrInvalidSnapshot
		}
		resolved[typ] = asset
	}
	snapshot, err := snapshotFromAssets(req, resolved)
	if err != nil {
		return Snapshot{}, err
	}
	current := s.snapshot[req.Scope]
	if current.Revision != req.ExpectedRevision {
		return Snapshot{}, ErrAssetConflict
	}
	snapshot.Revision = current.Revision + 1
	encoded, _ := json.Marshal(struct {
		Snapshot Snapshot               `json:"snapshot"`
		Assets   map[AssetType]AssetRef `json:"assets"`
	}{snapshot, req.Assets})
	sum := sha256.Sum256(encoded)
	snapshot.Hash = hex.EncodeToString(sum[:])
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	if err := snapshot.ValidateDetails(); err != nil {
		return Snapshot{}, ErrInvalidSnapshot
	}
	s.snapshot[req.Scope] = snapshot
	return snapshot, nil
}

func cloneAsset(asset Asset) Asset {
	asset.Content = append(json.RawMessage(nil), asset.Content...)
	return asset
}

type authorizerCall struct {
	actor  Actor
	action Action
	scope  Scope
}
type testAuthorizer struct {
	err   error
	calls []authorizerCall
	types []AssetType
}

func (a *testAuthorizer) AuthorizePolicyAsset(_ context.Context, actor Actor, action Action, scope Scope) error {
	a.calls = append(a.calls, authorizerCall{actor, action, scope})
	return a.err
}

func (a *testAuthorizer) AuthorizeTypedPolicyAsset(ctx context.Context, actor Actor, action Action, scope Scope, typ AssetType) error {
	a.types = append(a.types, typ)
	return a.AuthorizePolicyAsset(ctx, actor, action, scope)
}

type snapshotOnlyAuthorizer struct{ testAuthorizer }

func (a *snapshotOnlyAuthorizer) AuthorizeTypedPolicyAsset(ctx context.Context, actor Actor, action Action, scope Scope, typ AssetType) error {
	if typ == AssetPrompt || typ == AssetTool {
		return ErrForbidden
	}
	return a.AuthorizePolicyAsset(ctx, actor, action, scope)
}

func TestSnapshotPublisherCannotReadComponentBodiesThroughMixedList(t *testing.T) {
	store := newMemoryControlStore()
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "agent-a", AgentVersionID: "v1"}
	for _, id := range []string{"published-prompt", "draft-prompt"} {
		if err := store.CreateAsset(context.Background(), Asset{ID: id, Type: AssetPrompt, Scope: scope, Revision: 1, Status: AssetDraft, Content: json.RawMessage(`{"template":"PRIVATE-PROMPT-BODY","template_hash":"hash"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.PublishAsset(context.Background(), scope, AssetPrompt, "published-prompt", 1); err != nil {
		t.Fatal(err)
	}
	module := NewModule(store, &snapshotOnlyAuthorizer{}, "module-secret")
	for _, item := range []struct {
		query  string
		status int
	}{{"", 403}, {"&type=prompt", 403}, {"&view=snapshot-references", 200}, {"&view=snapshot-references&type=prompt", 400}} {
		response := httptest.NewRecorder()
		module.Handler().ServeHTTP(response, browserRequest(http.MethodGet, "/assets?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&agent_id=agent-a&agent_version_id=v1"+item.query, ""))
		if response.Code != item.status || strings.Contains(response.Body.String(), "PRIVATE-PROMPT-BODY") {
			t.Fatal("component body leaked through aggregate list", item.query, response.Code, response.Body.String())
		}
		if item.status == 200 && (!strings.Contains(response.Body.String(), "published-prompt") || strings.Contains(response.Body.String(), "draft-prompt") || strings.Contains(response.Body.String(), "content")) {
			t.Fatal("publisher metadata projection is incorrect", response.Body.String())
		}
	}
}

func TestTypedAssetAuthorizationUsesActualRouteTypeAndKeepsSnapshotsSeparate(t *testing.T) {
	store := newMemoryControlStore()
	auth := &testAuthorizer{}
	module := NewModule(store, auth, "module-secret")
	scope := `"scope":{"tenant_id":"tenant-a","department_id":"dept-a","application_id":"app-a","agent_id":"agent-a","agent_version_id":"v1"}`
	request := func(method, path, body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		module.Handler().ServeHTTP(response, browserRequest(method, path, body))
		return response
	}
	if response := request(http.MethodPost, "/assets", `{`+scope+`,"type":"prompt","id":"p","content":{"template":"body","template_hash":"hash"}}`); response.Code != http.StatusCreated {
		t.Fatal(response.Code, response.Body.String())
	}
	if len(auth.types) != 1 || auth.types[0] != AssetPrompt {
		t.Fatal("created asset type not authorized", auth.types)
	}
	before := len(auth.types)
	request(http.MethodPost, "/assets/tool/p/publish", `{`+scope+`,"expected_revision":1,"type":"prompt"}`)
	if len(auth.types) != before {
		t.Fatal("unknown forged type was accepted by strict decoder")
	}
	request(http.MethodPost, "/assets/tool/p/publish", `{`+scope+`,"expected_revision":1}`)
	if auth.types[len(auth.types)-1] != AssetTool {
		t.Fatal("route type was overridden")
	}
	before = len(auth.types)
	request(http.MethodGet, "/snapshots/current?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&agent_id=agent-a&agent_version_id=v1", "")
	if len(auth.types) != before || auth.calls[len(auth.calls)-1].action != ActionRead {
		t.Fatal("snapshot entered the component asset authorization path")
	}
}

func browserRequest(method, path string, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Internal-Token", "module-secret")
	req.Header.Set("X-Browser-Module", "1")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Department-ID", "department-a")
	req.Header.Set("X-Application-ID", "application-a")
	req.Header.Set("X-Principal-Type", "user")
	req.Header.Set("X-Principal-ID", "alice")
	return req
}

var testScope = Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentID: "qa", AgentVersionID: "qa-v1"}

func TestPolicyAssetModuleCreatePublishAndCAS(t *testing.T) {
	store := newMemoryControlStore()
	authorizer := &testAuthorizer{}
	handler := NewModule(store, authorizer, "module-secret").Handler()

	create := `{"id":"model-v1","type":"model","scope":{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","agent_id":"qa","agent_version_id":"qa-v1"},"content":{"provider":"local","model":"qa-small","max_tokens":512,"temperature":0,"allow_external":false,"budget_cents":0,"input_micros_per_1k_tokens":0,"output_micros_per_1k_tokens":0}}`
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, browserRequest(http.MethodPost, "/assets", create))
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"revision":1`) || !strings.Contains(created.Body.String(), `"status":"draft"`) {
		t.Fatalf("create response = %d %s", created.Code, created.Body.String())
	}
	if len(authorizer.calls) != 1 || authorizer.calls[0].action != ActionCreate || authorizer.calls[0].actor.PrincipalID != "alice" || authorizer.calls[0].scope != testScope {
		t.Fatalf("authorizer did not receive trusted actor and requested scope: %+v", authorizer.calls)
	}

	publish := `{"scope":{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","agent_id":"qa","agent_version_id":"qa-v1"},"expected_revision":1}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, browserRequest(http.MethodPost, "/assets/model/model-v1/publish", publish))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"revision":2`) || !strings.Contains(response.Body.String(), `"status":"published"`) {
		t.Fatalf("publish response = %d %s", response.Code, response.Body.String())
	}
	query := httptest.NewRecorder()
	handler.ServeHTTP(query, browserRequest(http.MethodGet, "/assets/model/model-v1?tenant_id=tenant-a&department_id=department-a&application_id=application-a&agent_id=qa&agent_version_id=qa-v1", ""))
	if query.Code != http.StatusOK || !strings.Contains(query.Body.String(), `"model":"qa-small"`) {
		t.Fatalf("scoped asset query response = %d %s", query.Code, query.Body.String())
	}

	update := `{"scope":{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","agent_id":"qa","agent_version_id":"qa-v1"},"expected_revision":1,"content":{"provider":"local","model":"new-model","max_tokens":512,"temperature":0,"allow_external":false,"budget_cents":0,"input_micros_per_1k_tokens":0,"output_micros_per_1k_tokens":0}}`
	conflict := httptest.NewRecorder()
	handler.ServeHTTP(conflict, browserRequest(http.MethodPut, "/assets/model/model-v1", update))
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "REVISION_CONFLICT") {
		t.Fatalf("stale update response = %d %s", conflict.Code, conflict.Body.String())
	}
	update = strings.Replace(update, `"expected_revision":1`, `"expected_revision":2`, 1)
	updated := httptest.NewRecorder()
	handler.ServeHTTP(updated, browserRequest(http.MethodPut, "/assets/model/model-v1", update))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"revision":3`) || !strings.Contains(updated.Body.String(), `"status":"draft"`) {
		t.Fatalf("next immutable draft revision response = %d %s", updated.Code, updated.Body.String())
	}
	old, err := store.GetAsset(context.Background(), testScope, AssetModel, "model-v1", 2)
	if err != nil || old.Status != AssetPublished || !strings.Contains(string(old.Content), "qa-small") {
		t.Fatalf("published revision was not immutable: %+v, %v", old, err)
	}
}

func TestPolicyAssetModuleRejectsUnauthorizedAndNonBrowserCalls(t *testing.T) {
	store := newMemoryControlStore()
	authorizer := &testAuthorizer{err: ErrForbidden}
	handler := NewModule(store, authorizer, "module-secret").Handler()
	body := `{"id":"memory-v1","type":"memory","scope":{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","agent_id":"qa","agent_version_id":"qa-v1"},"content":{"max_entries":10}}`
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, browserRequest(http.MethodPost, "/assets", body))
	if denied.Code != http.StatusForbidden || len(store.current) != 0 {
		t.Fatalf("unauthorized create response = %d %s; store rows=%d", denied.Code, denied.Body.String(), len(store.current))
	}
	if len(authorizer.calls) != 1 || authorizer.calls[0].actor.PrincipalID != "alice" {
		t.Fatalf("trusted actor was not checked: %+v", authorizer.calls)
	}

	internal := browserRequest(http.MethodPost, "/assets", body)
	internal.Header.Del("X-Browser-Module")
	noBrowser := httptest.NewRecorder()
	handler.ServeHTTP(noBrowser, internal)
	if noBrowser.Code != http.StatusUnauthorized || len(authorizer.calls) != 1 {
		t.Fatalf("non-browser management call response = %d %s; authorizer calls=%d", noBrowser.Code, noBrowser.Body.String(), len(authorizer.calls))
	}

	missingAuth := httptest.NewRecorder()
	NewModule(store, nil, "module-secret").Handler().ServeHTTP(missingAuth, browserRequest(http.MethodPost, "/assets", body))
	if missingAuth.Code != http.StatusServiceUnavailable || len(store.current) != 0 {
		t.Fatalf("missing authorizer must fail closed, got %d %s", missingAuth.Code, missingAuth.Body.String())
	}
}

func TestPolicyAssetModuleAllSixTypesCanBeCreatedAndPublishedIntoRuntimeSnapshot(t *testing.T) {
	fixtures := []struct {
		typ     AssetType
		id      string
		content string
	}{
		{AssetModel, "model-1", `{"provider":"local","model":"m","max_tokens":1024,"temperature":0,"allow_external":false,"budget_cents":0,"input_micros_per_1k_tokens":0,"output_micros_per_1k_tokens":0}`},
		{AssetPrompt, "prompt-1", `{"template_hash":"prompt-sha","template":"approved prompt"}`},
		{AssetTool, "tool-1", `{"allowed_tools":["report"],"require_confirmation":[]}`},
		{AssetMemory, "memory-1", `{"working_ttl_seconds":60,"session_ttl_seconds":120,"task_ttl_seconds":30,"max_entries":20,"long_term_enabled":false,"semantic_enabled":false}`},
		{AssetKnowledge, "knowledge-1", `{"allowed_scopes":["platform-knowledge"],"require_references":true,"allow_partial_degraded":false,"allow_replay":false}`},
		{AssetRuntime, "runtime-1", `{"max_attempts":2,"task_timeout_seconds":30,"lease_seconds":60,"cancel_grace_seconds":5}`},
	}
	store := newMemoryControlStore()
	handler := NewModule(store, &testAuthorizer{}, "module-secret").Handler()
	refs := map[AssetType]AssetRef{}
	for _, fixture := range fixtures {
		create, _ := json.Marshal(map[string]any{"id": fixture.id, "type": fixture.typ, "scope": testScope, "content": json.RawMessage(fixture.content)})
		created := httptest.NewRecorder()
		handler.ServeHTTP(created, browserRequest(http.MethodPost, "/assets", string(create)))
		if created.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", fixture.typ, created.Code, created.Body.String())
		}
		publish := httptest.NewRecorder()
		payload := fmt.Sprintf(`{"scope":{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","agent_id":"qa","agent_version_id":"qa-v1"},"expected_revision":1}`)
		handler.ServeHTTP(publish, browserRequest(http.MethodPost, "/assets/"+string(fixture.typ)+"/"+fixture.id+"/publish", payload))
		if publish.Code != http.StatusOK {
			t.Fatalf("publish %s: %d %s", fixture.typ, publish.Code, publish.Body.String())
		}
		refs[fixture.typ] = AssetRef{ID: fixture.id, Revision: 2}
	}
	rule := RulePolicy{Version: "0.2.0", Checksum: strings.Repeat("a", 64)}
	for _, invalid := range []RulePolicy{{Version: "0.2.0"}, {Checksum: strings.Repeat("a", 64)}, {Version: "0.2.0", Checksum: strings.Repeat("z", 64)}, {Version: " 0.2.0", Checksum: strings.Repeat("a", 64)}} {
		body, _ := json.Marshal(PublishSnapshotRequest{Scope: testScope, Assets: refs, Rule: invalid})
		rejected := httptest.NewRecorder()
		handler.ServeHTTP(rejected, browserRequest(http.MethodPost, "/snapshots/publish", string(body)))
		if rejected.Code == http.StatusOK || len(store.snapshot) != 0 {
			t.Fatal("invalid rule binding published a snapshot")
		}
	}
	requestBody, err := json.Marshal(PublishSnapshotRequest{Scope: testScope, ExpectedRevision: 0, Assets: refs, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, browserRequest(http.MethodPost, "/snapshots/publish", string(requestBody)))
	if response.Code != http.StatusOK {
		t.Fatalf("snapshot publish: %d %s", response.Code, response.Body.String())
	}
	if got := store.snapshot[testScope]; got.Rule != rule || got.RuleBundleChecksum != rule.Checksum || got.RuleBundleVersion != rule.Version {
		t.Fatal("published snapshot lost immutable rule binding")
	}
	var published Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	if published.Revision != 1 || len(published.Hash) != 64 || published.ModelProfileID != "model-1" || published.PromptVersionID != "prompt-1" || published.Prompt.Template != "approved prompt" || published.Runtime.MaxAttempts != 2 {
		t.Fatalf("runtime snapshot did not materialize all six published assets: %+v", published)
	}
	query := httptest.NewRecorder()
	handler.ServeHTTP(query, browserRequest(http.MethodGet, "/snapshots/current?tenant_id=tenant-a&department_id=department-a&application_id=application-a&agent_id=qa&agent_version_id=qa-v1", ""))
	if query.Code != http.StatusOK || !strings.Contains(query.Body.String(), `"revision":1`) || !strings.Contains(query.Body.String(), `"model_profile_id":"model-1"`) {
		t.Fatalf("current runtime snapshot query = %d %s", query.Code, query.Body.String())
	}
}

func TestPolicyAssetModuleRequiresInternalGatewayToken(t *testing.T) {
	store := newMemoryControlStore()
	authorizer := &testAuthorizer{}
	handler := NewModule(store, authorizer, "module-secret").Handler()
	body := `{"id":"model-v1","type":"model","scope":{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","agent_id":"qa","agent_version_id":"qa-v1"},"content":{"provider":"local","model":"m","max_tokens":10,"temperature":0,"allow_external":false,"budget_cents":0,"input_micros_per_1k_tokens":0,"output_micros_per_1k_tokens":0}}`

	missing := browserRequest(http.MethodPost, "/assets", body)
	missing.Header.Del("X-Internal-Token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, missing)
	if response.Code != http.StatusUnauthorized || len(authorizer.calls) != 0 || len(store.current) != 0 {
		t.Fatalf("missing internal token response = %d %s", response.Code, response.Body.String())
	}

	wrong := browserRequest(http.MethodPost, "/assets", body)
	wrong.Header.Set("X-Internal-Token", "wrong-token")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, wrong)
	if response.Code != http.StatusUnauthorized || len(authorizer.calls) != 0 || len(store.current) != 0 {
		t.Fatalf("wrong internal token response = %d %s", response.Code, response.Body.String())
	}

	bearer := browserRequest(http.MethodPost, "/assets", body)
	bearer.Header.Del("X-Internal-Token")
	bearer.Header.Set("Authorization", "Bearer module-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, bearer)
	if response.Code != http.StatusCreated {
		t.Fatalf("valid internal Bearer token response = %d %s", response.Code, response.Body.String())
	}

	misconfigured := httptest.NewRecorder()
	if err := NewModule(store, authorizer, "").Start(context.Background()); err == nil {
		t.Fatal("module startup must reject a missing internal gateway token")
	}
	NewModule(store, authorizer, "").Handler().ServeHTTP(misconfigured, browserRequest(http.MethodPost, "/assets", body))
	if misconfigured.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing module token response = %d %s", misconfigured.Code, misconfigured.Body.String())
	}
}

func TestSnapshotPublicationRequiresEveryPublishedScopedAsset(t *testing.T) {
	req := PublishSnapshotRequest{Scope: testScope, Assets: map[AssetType]AssetRef{AssetModel: {ID: "model", Revision: 1}}}
	_, err := snapshotFromAssets(req, map[AssetType]Asset{})
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("incomplete bundle error = %v, want invalid snapshot", err)
	}
}

func TestValidateAssetContentRejectsCrossFamilyAndUnknownFields(t *testing.T) {
	if err := validateAssetContent(AssetRuntime, json.RawMessage(`{"max_attempts":1,"task_timeout_seconds":10,"lease_seconds":10,"surprise":true}`)); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("unknown policy content field error = %v", err)
	}
	if err := validateAssetContent(AssetModel, json.RawMessage(`{"provider":"local","model":"m","max_tokens":10,"temperature":0,"budget_cents":-1}`)); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("negative model budget error = %v", err)
	}
}
