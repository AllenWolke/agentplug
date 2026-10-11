package agentfactory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu        sync.Mutex
	templates map[string]Template
	versions  map[string]TemplateVersion
	mappings  map[string]Mapping
	evidence  []ConformanceEvidence
}

func newMemoryStore() *memoryStore {
	return &memoryStore{templates: map[string]Template{}, versions: map[string]TemplateVersion{}, mappings: map[string]Mapping{}}
}
func (s *memoryStore) EnsureSchema(context.Context) error { return nil }
func (s *memoryStore) Ping(context.Context) error         { return nil }
func (s *memoryStore) CreateTemplate(_ context.Context, row Template) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeHash(row.Scope) + ":" + row.TemplateID
	for _, old := range s.templates {
		if scopeHash(old.Scope)+":"+old.TemplateID == key {
			return ErrAlreadyExists
		}
	}
	s.templates[scopeHash(row.Scope)+":"+row.ID] = row
	return nil
}
func (s *memoryStore) GetTemplate(_ context.Context, scope Scope, id string) (Template, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.templates[scopeHash(scope)+":"+id]
	if !ok {
		return Template{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) ListTemplates(_ context.Context, scope Scope, limit int, after string) ([]Template, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []Template{}
	for _, row := range s.templates {
		if scopeHash(row.Scope) == scopeHash(scope) && (after == "" || row.ID < after) {
			items = append(items, row)
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
func (s *memoryStore) CreateTemplateVersion(_ context.Context, row TemplateVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[scopeHash(row.Scope)+":"+row.DefinitionID]; !ok {
		return ErrNotFound
	}
	for _, old := range s.versions {
		if scopeHash(old.Scope) == scopeHash(row.Scope) && old.DefinitionID == row.DefinitionID && old.SemanticVersion == row.SemanticVersion {
			return ErrAlreadyExists
		}
	}
	s.versions[scopeHash(row.Scope)+":"+row.ID] = row
	return nil
}
func (s *memoryStore) ListTemplateVersions(_ context.Context, scope Scope, parent string, limit int) ([]TemplateVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []TemplateVersion{}
	for _, row := range s.versions {
		if scopeHash(row.Scope) == scopeHash(scope) && row.DefinitionID == parent {
			items = append(items, row)
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
func (s *memoryStore) CreateMapping(_ context.Context, row Mapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeHash(row.Scope) + ":" + row.ID
	if _, ok := s.mappings[key]; ok {
		return ErrAlreadyExists
	}
	for _, old := range s.mappings {
		if scopeHash(old.Scope) == scopeHash(row.Scope) && old.MappingID == row.MappingID {
			return ErrAlreadyExists
		}
	}
	row.Spec = append([]byte(nil), row.Spec...)
	s.mappings[key] = row
	return nil
}
func (s *memoryStore) GetMapping(_ context.Context, scope Scope, id string) (Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.mappings[scopeHash(scope)+":"+id]
	if !ok {
		return Mapping{}, ErrNotFound
	}
	row.Spec = append([]byte(nil), row.Spec...)
	return row, nil
}
func (s *memoryStore) ListMappings(_ context.Context, scope Scope, limit int, after string) ([]Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []Mapping{}
	for _, row := range s.mappings {
		if scopeHash(row.Scope) == scopeHash(scope) && (after == "" || row.ID < after) {
			items = append(items, row)
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
func (s *memoryStore) SaveEvidence(_ context.Context, row ConformanceEvidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evidence = append(s.evidence, row)
	return nil
}
func (s *memoryStore) ListEvidence(_ context.Context, scope Scope, id string, limit int) ([]ConformanceEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []ConformanceEvidence{}
	for _, row := range s.evidence {
		if scopeHash(row.Scope) == scopeHash(scope) && row.MappingID == id {
			items = append(items, row)
		}
	}
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}
func (s *memoryStore) PublishMapping(_ context.Context, scope Scope, id string, expected uint64) (Mapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scopeHash(scope) + ":" + id
	row, ok := s.mappings[key]
	if !ok {
		return Mapping{}, ErrNotFound
	}
	if row.Status != StatusDraft || row.Revision != expected {
		return Mapping{}, ErrConflict
	}
	passed := false
	for _, e := range s.evidence {
		if scopeHash(e.Scope) == scopeHash(scope) && e.MappingID == id && e.MappingRevision == expected && e.MappingHash == row.ContentHash && e.Status == "passed" {
			passed = true
		}
	}
	if !passed {
		return Mapping{}, ErrConformanceNeeded
	}
	row.Status = StatusPublished
	row.Revision++
	row.UpdatedAt = time.Now().UTC()
	s.mappings[key] = row
	return row, nil
}

type allowAuthorizer struct {
	mu    sync.Mutex
	calls []struct {
		Actor  Actor
		Action Action
		Scope  Scope
	}
	deny bool
}

func (a *allowAuthorizer) AuthorizeAgentFactory(_ context.Context, actor Actor, action Action, scope Scope) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, struct {
		Actor  Actor
		Action Action
		Scope  Scope
	}{actor, action, scope})
	if a.deny {
		return ErrForbidden
	}
	if actor.TenantID != scope.TenantID || actor.DepartmentID != scope.DepartmentID || actor.ApplicationID != scope.ApplicationID {
		return ErrForbidden
	}
	return nil
}

var testScope = Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}

func signedRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("X-Internal-Token", "secret-token")
	request.Header.Set("X-Browser-Module", "1")
	request.Header.Set("X-Tenant-ID", testScope.TenantID)
	request.Header.Set("X-Department-ID", testScope.DepartmentID)
	request.Header.Set("X-Application-ID", testScope.ApplicationID)
	request.Header.Set("X-Principal-Type", "user")
	request.Header.Set("X-Principal-ID", "operator-1")
	return request
}
func decodeResponse[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
	}
	return value
}

func TestTemplateVersionStoresDigestOnlyAndUsesTrustedScope(t *testing.T) {
	store, auth := newMemoryStore(), &allowAuthorizer{}
	module := NewModule(store, auth, "secret-token")
	if err := module.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	created := httptest.NewRecorder()
	module.Handler().ServeHTTP(created, signedRequest(http.MethodPost, "/templates", `{"template_id":"python.langgraph","name":"Python / LangGraph","language":"python","framework":"LangGraph"}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("create template: status=%d body=%s", created.Code, created.Body.String())
	}
	template := decodeResponse[Template](t, created)
	if template.Scope != testScope || template.CreatedBy != "operator-1" {
		t.Fatalf("scope or actor not sourced from gateway: %#v", template)
	}
	artifactText := "sensitive artifact sample"
	requestBody, _ := json.Marshal(CreateTemplateVersionRequest{Version: "1.0.0", ArtifactURI: "oci://registry.local/agents/python@sha256:abc", ArtifactBase64: base64.StdEncoding.EncodeToString([]byte(artifactText))})
	versionRecorder := httptest.NewRecorder()
	module.Handler().ServeHTTP(versionRecorder, signedRequest(http.MethodPost, "/templates/"+template.ID+"/versions", string(requestBody)))
	if versionRecorder.Code != http.StatusCreated {
		t.Fatalf("create version: status=%d body=%s", versionRecorder.Code, versionRecorder.Body.String())
	}
	version := decodeResponse[TemplateVersion](t, versionRecorder)
	if version.ContentHash == "" || version.ArtifactSize != len(artifactText) || strings.Contains(versionRecorder.Body.String(), artifactText) {
		t.Fatalf("artifact body leaked or metadata missing: %s", versionRecorder.Body.String())
	}
	stored := store.versions[scopeHash(testScope)+":"+version.ID]
	raw, _ := json.Marshal(stored)
	if strings.Contains(string(raw), artifactText) || !strings.Contains(string(raw), version.ContentHash) {
		t.Fatalf("artifact bytes were stored: %s", raw)
	}
	other := Scope{TenantID: "tenant-b", DepartmentID: "dept-a", ApplicationID: "app-a"}
	if _, err := store.GetTemplate(context.Background(), other, template.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope read succeeded: %v", err)
	}
}

func TestMappingDryRunEvidenceAndCASPublish(t *testing.T) {
	store, auth := newMemoryStore(), &allowAuthorizer{}
	module := NewModule(store, auth, "secret-token")
	spec := json.RawMessage(`{"mapping_id":"legacy-qa","version":"1.0.0","kind":"legacy-http","request":{"message":{"source":"input.question","required":true,"max_length":64},"trace_id":"context.trace_id"},"response":{"answer":"body.output"}}`)
	createBody, _ := json.Marshal(CreateMappingRequest{MappingID: "legacy-qa", Kind: "legacy-http", Spec: spec})
	created := httptest.NewRecorder()
	module.Handler().ServeHTTP(created, signedRequest(http.MethodPost, "/mappings", string(createBody)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create mapping: %d %s", created.Code, created.Body.String())
	}
	mapping := decodeResponse[Mapping](t, created)
	dry := httptest.NewRecorder()
	module.Handler().ServeHTTP(dry, signedRequest(http.MethodPost, "/mappings/"+mapping.ID+"/dry-run", `{"input":{"question":"How much?"},"context":{"trace_id":"trace-1"},"body":{"output":"supported"}}`))
	if dry.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", dry.Code, dry.Body.String())
	}
	result := decodeResponse[DryRunResult](t, dry)
	if result.Request["message"] != "How much?" || result.Response["answer"] != "supported" || result.Evidence.Status != "passed" || result.Evidence.CheckCount < 3 {
		t.Fatalf("unexpected dry run: %#v", result)
	}
	evidenceRecorder := httptest.NewRecorder()
	module.Handler().ServeHTTP(evidenceRecorder, signedRequest(http.MethodGet, "/mappings/"+mapping.ID+"/evidence?limit=10", ""))
	if evidenceRecorder.Code != http.StatusOK || strings.Contains(evidenceRecorder.Body.String(), "How much?") || strings.Contains(evidenceRecorder.Body.String(), "supported") {
		t.Fatalf("evidence leaked fixture/result values: %d %s", evidenceRecorder.Code, evidenceRecorder.Body.String())
	}
	publish := httptest.NewRecorder()
	module.Handler().ServeHTTP(publish, signedRequest(http.MethodPost, "/mappings/"+mapping.ID+"/publish", `{"revision":1}`))
	if publish.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", publish.Code, publish.Body.String())
	}
	published := decodeResponse[struct {
		Status   string `json:"status"`
		Revision uint64 `json:"revision"`
	}](t, publish)
	if published.Status != StatusPublished || published.Revision != 2 {
		t.Fatalf("bad publish response: %#v", published)
	}
	stale := httptest.NewRecorder()
	module.Handler().ServeHTTP(stale, signedRequest(http.MethodPost, "/mappings/"+mapping.ID+"/publish", `{"revision":1}`))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale CAS accepted: %d %s", stale.Code, stale.Body.String())
	}
}

func TestMappingPublishRequiresPassingCurrentEvidence(t *testing.T) {
	store := newMemoryStore()
	scope := testScope
	spec := json.RawMessage(`{"mapping_id":"map1","version":"1.0.0","kind":"legacy-http","request":{"q":"input.question"},"response":{"answer":"body.answer"}}`)
	_, canonical, err := compileDocument(spec)
	if err != nil {
		t.Fatal(err)
	}
	_ = canonical
	row := Mapping{ID: "mapping-id", Scope: scope, MappingID: "map1", Kind: "legacy-http", Status: StatusDraft, Spec: spec, ContentHash: hashJSON(map[string]any{"spec": string(spec)}), Revision: 1}
	if err = store.CreateMapping(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PublishMapping(context.Background(), scope, row.ID, 1); !errors.Is(err, ErrConformanceNeeded) {
		t.Fatalf("published without conformance: %v", err)
	}
	store.evidence = append(store.evidence, ConformanceEvidence{Scope: scope, MappingID: row.ID, MappingRevision: 1, MappingHash: row.ContentHash, Status: "failed"})
	if _, err = store.PublishMapping(context.Background(), scope, row.ID, 1); !errors.Is(err, ErrConformanceNeeded) {
		t.Fatalf("failed evidence passed gate: %v", err)
	}
}

func TestTrustedGatewayIdentityIsMandatoryAndBodyCannotSetScope(t *testing.T) {
	module := NewModule(newMemoryStore(), &allowAuthorizer{}, "secret-token")
	noBrowser := httptest.NewRequest(http.MethodGet, "/templates", nil)
	noBrowser.Header.Set("X-Internal-Token", "secret-token")
	recorder := httptest.NewRecorder()
	module.Handler().ServeHTTP(recorder, noBrowser)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("untrusted caller accepted: %d", recorder.Code)
	}
	badBody := signedRequest(http.MethodPost, "/templates", `{"template_id":"t1","name":"T","language":"go","framework":"Eino","tenant_id":"victim"}`)
	recorder = httptest.NewRecorder()
	module.Handler().ServeHTTP(recorder, badBody)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("body-supplied identity accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	denied := &allowAuthorizer{deny: true}
	module = NewModule(newMemoryStore(), denied, "secret-token")
	recorder = httptest.NewRecorder()
	module.Handler().ServeHTTP(recorder, signedRequest(http.MethodGet, "/templates", ""))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("denied principal accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestInvalidAndTaintedMappingsAreRejected(t *testing.T) {
	bad := [][]byte{
		[]byte(`{"mapping_id":"a","mapping_id":"b","version":"1.0.0","kind":"legacy-http","request":{"q":"input.x"},"response":{"a":"body.y"}}`),
		[]byte(`{"mapping_id":"a","version":"1.0.0","kind":"legacy-http","request":{"tenant_id":"input.tenant_id"},"response":{"a":"body.y"}}`),
		[]byte(`{"mapping_id":"a","version":"1.0.0","kind":"legacy-http","request":{"q":{"source":"input.q","convert":"eval"}},"response":{"a":"body.y"}}`),
	}
	for _, spec := range bad {
		if _, _, err := compileDocument(spec); err == nil {
			t.Fatalf("unsafe mapping accepted: %s", spec)
		}
	}
	canonical := []byte(`{"api_version":"agent-mapping/v1","metadata":{"mapping_id":"canonical-qa","version":"1.0.0"},"spec":{"upstream_ref":"endpoint://qa-service","operations":{"invoke":{"request":{"method":"POST","path":"/ask","body":{"object":{"question":{"from_input":"question","required":true}}}},"response":{"success_status":[200],"output":{"from_body":"answer"}}}}}}`)
	doc, _, err := compileDocument(canonical)
	if err != nil {
		t.Fatalf("valid canonical mapping rejected: %v", err)
	}
	result, err := doc.Evaluate(DryRunRequest{Input: map[string]any{"question": "q"}, Body: map[string]any{"answer": "a"}}, 1)
	if err != nil || result.Request["question"] != "q" || result.Response["output"] != "a" {
		t.Fatalf("canonical dry-run mismatch: %#v %v", result, err)
	}
}

func TestArtifactURIRejectsCredentialsAndUnsafeSchemes(t *testing.T) {
	for _, value := range []string{"https://user:pass@registry.example/artifact", "http://registry.example/artifact", "file:///tmp/secret", "oci://registry.example/a?token=secret", "oci://registry.example/"} {
		if safeArtifactURI(value) {
			t.Fatalf("unsafe artifact URI accepted: %s", value)
		}
	}
	for _, value := range []string{"oci://registry.example/template@sha256:abcd", "https://registry.example/artifacts/a"} {
		if !safeArtifactURI(value) {
			t.Fatalf("valid artifact URI rejected: %s", value)
		}
	}
}

var _ Store = (*memoryStore)(nil)
var _ Authorizer = (*allowAuthorizer)(nil)
