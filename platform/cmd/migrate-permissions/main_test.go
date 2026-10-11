package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/identity"
)

func TestCanonicalActionsAreReadOnlyAndCannotBeMixedWithApply(t *testing.T) {
	t.Setenv("DB_DSN", "invalid-database-configuration")
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--permission-actions"}, &output); err != nil {
		t.Fatal("metadata attempted database access", err)
	}
	var actions []identity.PermissionAction
	if err := json.Unmarshal(output.Bytes(), &actions); err != nil || len(actions) != len(identity.BuiltinPermissionActions()) {
		t.Fatal("metadata did not use the canonical catalogue", err)
	}
	output.Reset()
	if err := run(context.Background(), []string{"--permission-actions", "--apply"}, &output); err == nil || output.Len() != 0 {
		t.Fatal("metadata command accepted a conflicting mutation flag")
	}
}

func TestMappingFileRejectsDuplicatesUnknownFieldsAndTrailingInput(t *testing.T) {
	valid := `{"mappings":[{"expected_source_digest":"fixture","basis":"reviewed","target":{"policy_mode":"v2","principal":{"type":"user","id":"u","tenant_id":"t"}}}]}`
	// Parsing does not authorize the target; real source/resource checks happen later.
	file, digest, err := readMappingFile(strings.NewReader(valid))
	if err != nil || len(file.Mappings) != 1 || len(digest) != 64 {
		t.Fatal(file, digest, err)
	}
	for _, input := range []string{valid + ` {}`, `{"mappings":[]}`, strings.Replace(valid, `"basis":"reviewed"`, `"basis":"reviewed","pretend_approved":true`, 1)} {
		if _, _, err := readMappingFile(strings.NewReader(input)); err == nil {
			t.Fatal("invalid mapping accepted")
		}
	}
	duplicate := strings.Replace(valid, `}]}`, `},{"expected_source_digest":"fixture","basis":"reviewed","target":{"policy_mode":"v2","principal":{"type":"user","id":"u","tenant_id":"t"}}}]}`, 1)
	if _, _, err := readMappingFile(strings.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate subject accepted")
	}
}

func TestShadowQueriesAreSubjectBoundAndIncludedInReviewedDigest(t *testing.T) {
	input := `{"mappings":[{"expected_source_digest":"fixture","basis":"reviewed","target":{"policy_mode":"v2","principal":{"type":"user","id":"u","tenant_id":"t"}}}],"shadow_queries":[{"principal_type":"user","subject_id":"u","queries":[{"action":"run","scope":{"scope_type":"agent_installation","tenant_id":"t","department_id":"d","application_id":"a","resource_id":"i"},"resource_type":"agent_installation","resource_id":"i"}]}]}`
	file, digest, err := readMappingFile(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_DSN", "invalid-database-configuration")
	path := filepath.Join(t.TempDir(), "shadow.json")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"--mapping-file", path, "--tenant", "t", "--department", "d", "--application", "a", "--actor", "admin", "--batch", "reviewed", "--apply", "--expected-input-digest", digest}, &bytes.Buffer{}); !errors.Is(err, identity.ErrInvalidResource) {
		t.Fatal("shadow diagnostics entered the apply/database path", err)
	}
	if queries := file.queriesFor(file.Mappings[0].Target.Principal); len(queries) != 1 || queries[0].Action != "run" {
		t.Fatal("diagnostics lost selected subject queries", queries)
	}
	if len(file.queriesFor(identity.Principal{Type: identity.PrincipalUser, ID: "other"})) != 0 {
		t.Fatal("diagnostics copied to an unrelated subject")
	}
	if len(file.queriesFor(identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "u"})) != 0 {
		t.Fatal("human diagnostics copied to machine with the same ID")
	}
	_, changed, err := readMappingFile(strings.NewReader(strings.Replace(input, `"action":"run"`, `"action":"cancel"`, 1)))
	if err != nil || changed == digest {
		t.Fatal("reviewed input digest did not bind diagnostic changes", err)
	}
	for _, invalid := range []string{
		strings.Replace(input, `"subject_id":"u"`, `"subject_id":"other"`, 1),
		strings.Replace(input, `"resource_id":"i"`, `"resource_id":"i","trust_me":true`, 1),
		strings.Replace(input, `"action":"run"`, `"action":""`, 1),
		strings.Replace(input, `"scope_type":"agent_installation"`, `"scope_type":"unknown"`, 1),
	} {
		if _, _, err := readMappingFile(strings.NewReader(invalid)); err == nil {
			t.Fatal("unreviewed or invalid diagnostic input accepted")
		}
	}
	file.ShadowQueries = append(file.ShadowQueries, file.ShadowQueries[0])
	raw, _ := json.Marshal(file)
	if _, _, err := readMappingFile(strings.NewReader(string(raw))); err == nil {
		t.Fatal("ambiguous duplicate subject samples accepted")
	}
	file.ShadowQueries = file.ShadowQueries[:1]
	query := file.ShadowQueries[0].Queries[0]
	file.ShadowQueries[0].Queries = make([]identity.PermissionQuery, 1001)
	for i := range file.ShadowQueries[0].Queries {
		file.ShadowQueries[0].Queries[i] = query
	}
	raw, _ = json.Marshal(file)
	if _, _, err := readMappingFile(strings.NewReader(string(raw))); err == nil {
		t.Fatal("unbounded diagnostic input accepted")
	}
}
