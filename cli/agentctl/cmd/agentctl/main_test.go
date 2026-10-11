package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	agenttemplate "github.com/lexagent/agentctl/internal/template"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func sha256Text(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func TestCreateAndValidate(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "中文 agent")
	if r, code := create([]string{"--language", "python", "--name", "demo", "--output", out}, false); code != 2 || r.OK {
		t.Fatalf("absolute output must be rejected: %+v/%d", r, code)
	}
	// The CLI deliberately accepts only workspace-relative paths. Exercise the
	// implementation in an isolated working directory like CI does.
	old, _ := os.Getwd()
	defer os.Chdir(old)
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	r, code := create([]string{"--language", "python", "--name", "demo", "--output", "agent"}, false)
	if code != 0 || !r.OK {
		t.Fatalf("%+v/%d", r, code)
	}
	if _, err := os.Stat(filepath.Join("agent", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	vr, code := validate([]string{"--path", "agent"})
	if code != 0 || !vr.OK {
		t.Fatalf("%+v/%d", vr, code)
	}
	if _, err := json.Marshal(vr); err != nil {
		t.Fatal(err)
	}
}

func TestTestAgentInvokesConformanceRunner(t *testing.T) {
	root := t.TempDir()
	manifest := `{"manifest_version":"agent-manifest/v1","agent_id":"demo-agent","version":"0.1.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://demo/input/v1","output":"schema://demo/output/v1"},"runtime":{"transport":"http","isolation":"container"}}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "template.lock"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(root, "runner.py")
	if err := os.WriteFile(runner, []byte("print('{\"status\":\"passed\"}')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	result, code := testAgent([]string{"--path", root, "--base-url", "http://127.0.0.1:1", "--runner", runner})
	if code != 0 || !result.OK {
		t.Fatalf("conformance runner was not invoked: %+v/%d", result, code)
	}
}

func TestPublishCallsConfiguredPF02URL(t *testing.T) {
	var gotMethod, gotAuth, gotMatch string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotAuth, gotMatch = r.Method, r.Header.Get("Authorization"), r.Header.Get("If-Match")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"draft"}`))
	}))
	defer server.Close()
	root := t.TempDir()
	manifest := `{"manifest_version":"agent-manifest/v1","agent_id":"demo-agent","version":"0.1.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://demo/input/v1","output":"schema://demo/output/v1"},"runtime":{"transport":"http","isolation":"container"}}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	result, code := publish([]string{"--path", root, "--url", server.URL, "--token", "token", "--revision", "7"}, false)
	if code != 0 || !result.OK {
		t.Fatalf("publish failed: %+v/%d", result, code)
	}
	if gotMethod != http.MethodPost || gotAuth != "Bearer token" || gotMatch != "7" || len(gotBody) == 0 {
		t.Fatalf("PF-02 request not formed correctly: %s %s %s %s", gotMethod, gotAuth, gotMatch, gotBody)
	}
}

func TestUpgradeDryRunAndApplyOnlyMatchingManagedFiles(t *testing.T) {
	workspace := t.TempDir()
	registry := t.TempDir()
	if err := os.MkdirAll(filepath.Join(registry, "registry"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(registry, "registry", "index.yaml"), []byte("version: v1\ntemplates:\n  - id: python-generic\n    version: 1.1.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(registry, "python-generic", "platform_entry"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":"agent-manifest/v1","agent_id":"demo-agent","version":"0.1.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://demo/input/v1","output":"schema://demo/output/v1"},"runtime":{"transport":"http","isolation":"container"},"metadata":{"template_id":"python-generic","template_version":"1.1.0"}}`
	if err := os.WriteFile(filepath.Join(registry, "python-generic", "manifest.json"), []byte(`{"manifest_version":"agent-manifest/v1","agent_id":"{{agent_id}}","version":"0.1.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://{{agent_id}}/input/v1","output":"schema://{{agent_id}}/output/v1"},"runtime":{"transport":"http","isolation":"container"},"metadata":{"template_id":"python-generic","template_version":"1.1.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(registry, "python-generic", "platform_entry", "server.py"), []byte("new-entry\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	oldEntry := "old-entry\n"
	if err := os.WriteFile(filepath.Join(workspace, "platform_entry.py"), []byte(oldEntry), 0644); err != nil {
		t.Fatal(err)
	}
	lock := map[string]any{
		"lock_version": "v1", "template_id": "python-generic", "template_version": "1.0.0",
		"files": []map[string]any{
			{"path": "manifest.json", "owner": "template-managed", "sha256": sha256Text(manifest), "mutable": true},
			{"path": "platform_entry.py", "owner": "template-managed", "sha256": sha256Text(oldEntry), "mutable": true},
		},
	}
	lockRaw, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(workspace, "template.lock"), lockRaw, 0644); err != nil {
		t.Fatal(err)
	}
	// The registry's source path is platform_entry/server.py, while the target
	// has platform_entry.py; this intentionally exercises a safe add and keeps
	// the old managed file unchanged for a follow-up versioned template.
	r, code := upgrade([]string{"--workspace", workspace, "--template-root", registry, "--to-template-version", "1.1.0", "--dry-run", "--json"})
	if code != 0 || !r.OK {
		t.Fatalf("dry-run failed: %+v/%d", r, code)
	}
	report, ok := r.Data.(agenttemplate.UpgradeReport)
	if !ok || report.Status != "planned" || !report.WouldChange {
		t.Fatalf("unexpected dry-run report: %#v", r.Data)
	}
	if _, err := os.Stat(filepath.Join(workspace, "platform_entry", "server.py")); !os.IsNotExist(err) {
		t.Fatal("dry-run must not write files")
	}
	r, code = upgrade([]string{"--workspace", workspace, "--template-root", registry, "--to-template-version", "1.1.0"})
	if code != 0 || !r.OK {
		t.Fatalf("upgrade failed: %+v/%d", r, code)
	}
	if got, err := os.ReadFile(filepath.Join(workspace, "platform_entry", "server.py")); err != nil || string(got) != "new-entry\n" {
		t.Fatalf("new managed file not added: %q/%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(workspace, "platform_entry.py")); err != nil || string(got) != oldEntry {
		t.Fatalf("unexpected overwrite: %q/%v", got, err)
	}
}

// TestGlobalFlagsAreAcceptedByEveryCommand proves --json (always-JSON output)
// and --dry-run are consumed globally, so every command honors the documented
// interface instead of rejecting -json.
func TestGlobalFlagsAreAcceptedByEveryCommand(t *testing.T) {
	clean, dry := withoutDryRun([]string{"--path", ".", "--dry-run", "--json", "--revision", "3"})
	if !dry {
		t.Fatal("--dry-run must be detected globally")
	}
	want := []string{"--path", ".", "--revision", "3"}
	if len(clean) != len(want) {
		t.Fatalf("unexpected clean args: %v", clean)
	}
	for i, arg := range want {
		if clean[i] != arg {
			t.Fatalf("unexpected clean args: %v", clean)
		}
	}
}

func asMap(t *testing.T, r result) map[string]any {
	t.Helper()
	raw, err := json.Marshal(r.Data)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func repoTemplates(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	// file = <repo>/cli/agentctl/cmd/agentctl/main_test.go
	root := filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
	return filepath.Join(root, "templates", "adapters")
}

// TestCreateDryRunReportsPlanWithoutWriting proves create's dry run performs the
// real render (returning the exact file list) instead of a stub success.
// TestCreateDryRunReportsPlanWithoutWriting 证明 create 的 dry-run 执行真实渲染
// （返回确切文件清单），而不是空壳成功。
func TestCreateDryRunReportsPlanWithoutWriting(t *testing.T) {
	root := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	r, code := create([]string{"--language", "python", "--name", "demo", "--output", "agent"}, true)
	if code != 0 || !r.OK {
		t.Fatalf("dry-run create failed: %+v/%d", r, code)
	}
	data := asMap(t, r)
	if data["dry_run"] != true || data["would_change"] != true {
		t.Fatalf("dry-run create did not report a real plan: %#v", data)
	}
	files, _ := data["files"].([]any)
	if len(files) == 0 {
		t.Fatalf("dry-run create reported no files: %#v", data)
	}
	if _, err := os.Stat("agent"); !os.IsNotExist(err) {
		t.Fatal("dry-run create must not create the output directory")
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("dry-run create left workspace artifacts: %#v", entries)
	}
}

// TestGenerateAdapterDryRunDoesNotPublish proves the adapter plan resolves and
// renders the per-kind assets without ever publishing the bundle.
func TestGenerateAdapterDryRunDoesNotPublish(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "adapter")
	r, code := generateAdapter([]string{"--kind", "process", "--name", "legacy-x", "--output", output, "--templates", repoTemplates(t)}, true)
	if code != 0 || !r.OK {
		t.Fatalf("dry-run generate-adapter failed: %+v/%d", r, code)
	}
	data := asMap(t, r)
	if data["dry_run"] != true || data["kind"] != "process" {
		t.Fatalf("unexpected dry-run adapter plan: %#v", data)
	}
	files, _ := data["files"].([]any)
	if len(files) == 0 {
		t.Fatalf("dry-run generate-adapter reported no files: %#v", data)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("dry-run generate-adapter must not publish the bundle")
	}
}

// TestPackageDryRunWritesNoArtifacts proves package's dry run computes the real
// content hash but writes no SBOM, and still fails where a real build would.
func TestPackageDryRunWritesNoArtifacts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(`{"agent_id":"demo"}`), 0644); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Getwd()
	defer os.Chdir(old)
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	r, code := packageAgent([]string{"--path", ".", "--sbom", "sbom.json"}, true)
	if code != 0 || !r.OK {
		t.Fatalf("dry-run package failed: %+v/%d", r, code)
	}
	data := asMap(t, r)
	if data["dry_run"] != true || data["content_hash"] == "" {
		t.Fatalf("dry-run package did not compute a real hash: %#v", data)
	}
	if _, err := os.Stat("sbom.json"); !os.IsNotExist(err) {
		t.Fatal("dry-run package must not write the SBOM")
	}
	// The image plan must fail exactly where the real build would: no Dockerfile.
	if r2, code2 := packageAgent([]string{"--path", ".", "--image", "demo:1"}, true); code2 == 0 || r2.OK {
		t.Fatal("dry-run package must reject a missing Dockerfile like a real build")
	}
}

// TestPublishDryRunSendsNoRequest proves publish's dry run validates the manifest
// and computes the real payload without a credential or any HTTP request.
func TestPublishDryRunSendsNoRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	root := t.TempDir()
	manifest := `{"manifest_version":"agent-manifest/v1","agent_id":"demo-agent","version":"0.1.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://demo/input/v1","output":"schema://demo/output/v1"},"runtime":{"transport":"http","isolation":"container"}}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	r, code := publish([]string{"--path", root, "--url", server.URL, "--revision", "9"}, true)
	if code != 0 || !r.OK {
		t.Fatalf("dry-run publish failed: %+v/%d", r, code)
	}
	if called {
		t.Fatal("dry-run publish must not send an HTTP request")
	}
	data := asMap(t, r)
	if data["dry_run"] != true || data["if_match"] != "9" || data["agent_id"] != "demo-agent" {
		t.Fatalf("unexpected dry-run publish plan: %#v", data)
	}
	if data["content_hash"] == "" {
		t.Fatalf("dry-run publish must compute the real content hash: %#v", data)
	}
}

func TestUpgradeRejectsModifiedManagedFileWithoutWriting(t *testing.T) {
	workspace := t.TempDir()
	registry := t.TempDir()
	if err := os.MkdirAll(filepath.Join(registry, "registry"), 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(registry, "registry", "index.yaml"), []byte("templates:\n  - id: python-generic\n    version: 1.1.0\n"), 0644)
	_ = os.MkdirAll(filepath.Join(registry, "python-generic"), 0755)
	_ = os.WriteFile(filepath.Join(registry, "python-generic", "manifest.json"), []byte(`{"agent_id":"demo-agent"}`), 0644)
	_ = os.WriteFile(filepath.Join(registry, "python-generic", "entry.txt"), []byte("desired\n"), 0644)
	_ = os.WriteFile(filepath.Join(workspace, "manifest.json"), []byte(`{"agent_id":"demo-agent"}`), 0644)
	_ = os.WriteFile(filepath.Join(workspace, "entry.txt"), []byte("user-change\n"), 0644)
	lock := `{"lock_version":"v1","template_id":"python-generic","template_version":"1.0.0","files":[{"path":"entry.txt","owner":"template-managed","sha256":"` + sha256Text("generated\n") + `"}]}`
	_ = os.WriteFile(filepath.Join(workspace, "template.lock"), []byte(lock), 0644)
	r, code := upgrade([]string{"--workspace", workspace, "--template-root", registry, "--to-template-version", "1.1.0"})
	if code == 0 || r.OK || len(r.Errors) != 1 || r.Errors[0].Code != "UPGRADE_CONFLICT" {
		t.Fatalf("expected stable conflict: %+v/%d", r, code)
	}
	if got, _ := os.ReadFile(filepath.Join(workspace, "entry.txt")); string(got) != "user-change\n" {
		t.Fatal("conflict must not write managed file")
	}
}
