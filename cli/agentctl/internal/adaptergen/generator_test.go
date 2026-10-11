package adaptergen

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testTemplates locates the checked-in adapter template root so every test
// exercises the real per-kind assets instead of an anonymous in-code default.
// testTemplates 定位仓库内的 Adapter 模板根，使每个测试都走真实的按 Kind 资产，
// 而不是代码内的匿名默认值。
func testTemplates(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the adaptergen source file")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file)))))
	templates := filepath.Join(root, "templates", "adapters")
	if _, err := os.Stat(templates); err != nil {
		t.Fatalf("adapter templates not found at %s: %v", templates, err)
	}
	return templates
}

func TestGenerateIsolatedBundle(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "legacy")
	if err := os.MkdirAll(old, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "source.py"), []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "adapter")
	if _, err := Generate(Options{AgentID: "legacy-agent", Kind: "legacy-http", Output: output, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "mapping.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Dockerfile", "adapter/go.mod", "adapter/main.go"} {
		if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(name))); err != nil {
			t.Fatalf("generated adapter artifact %s missing: %v", name, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(old, "source.py"))
	if err != nil || string(data) != "legacy" {
		t.Fatalf("legacy source changed: %v", err)
	}
}

// goldenRuntime is the per-kind transport and isolation every generated bundle
// must declare; a kind that silently claims another runtime breaks the
// deployment contract downstream.
// goldenRuntime 是每种 Kind 必须声明的传输与隔离；静默冒用其它运行时的 Kind 会破坏
// 下游部署契约。
var goldenRuntime = map[string]struct{ transport, isolation string }{
	"legacy-http": {"http", "container"},
	"grpc":        {"grpc", "container"},
	"process":     {"process", "sandbox"},
	"sidecar":     {"http", "sidecar"},
}

func TestGenerateGoldenBundlesPerKind(t *testing.T) {
	for kind, want := range goldenRuntime {
		kind, want := kind, want
		t.Run(kind, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "bundle")
			bundle, err := Generate(Options{AgentID: "legacy-agent", Kind: kind, Output: output, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)})
			if err != nil {
				t.Fatal(err)
			}
			if bundle.Kind != kind {
				t.Fatalf("bundle kind = %q want %q", bundle.Kind, kind)
			}
			if len(bundle.Files) == 0 {
				t.Fatal("bundle reported no files")
			}
			for _, name := range bundle.Files {
				if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(name))); err != nil {
					t.Fatalf("reported file %s missing: %v", name, err)
				}
			}
			// Every kind must ship its own deployment contract, Schema,
			// capability gap and lifecycle fixture; a kind that omits them is
			// only half generated.
			// 每种 Kind 都必须带上自己的部署契约、Schema、能力缺口与生命周期夹具；
			// 缺任意一项即为半成品。
			for _, name := range []string{"schema.json", "capabilities.json", "fixtures/lifecycle.json", "deploy/deployment.yaml", "deploy/networkpolicy.yaml"} {
				if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(name))); err != nil {
					t.Fatalf("kind %s is missing generated %s: %v", kind, name, err)
				}
				if !containsString(bundle.Files, name) {
					t.Fatalf("kind %s bundle did not report %s", kind, name)
				}
			}

			var manifest map[string]any
			readJSON(t, filepath.Join(output, "manifest.json"), &manifest)
			if manifest["isolation"] != want.isolation {
				t.Fatalf("manifest isolation = %v want %s", manifest["isolation"], want.isolation)
			}
			runtime, _ := manifest["runtime"].(map[string]any)
			if runtime["transport"] != want.transport || runtime["isolation"] != want.isolation {
				t.Fatalf("manifest runtime = %v want transport=%s isolation=%s", runtime, want.transport, want.isolation)
			}

			var descriptor map[string]any
			readJSON(t, filepath.Join(output, "descriptor.json"), &descriptor)
			if descriptor["isolation"] != want.isolation {
				t.Fatalf("descriptor isolation = %v want %s", descriptor["isolation"], want.isolation)
			}
			descriptorRuntime, _ := descriptor["runtime"].(map[string]any)
			if descriptorRuntime["transport"] != want.transport {
				t.Fatalf("descriptor transport = %v want %s", descriptorRuntime["transport"], want.transport)
			}

			var capabilities map[string]any
			readJSON(t, filepath.Join(output, "capabilities.json"), &capabilities)
			if capabilities["isolation"] != want.isolation {
				t.Fatalf("capabilities isolation = %v want %s", capabilities["isolation"], want.isolation)
			}
			if len(capabilities["unsupported"].([]any)) == 0 {
				t.Fatal("capability gap was not documented")
			}
		})
	}
}

func TestGenerateRejectsNativeScaffoldAndSourceOverlap(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy")
	if err := os.MkdirAll(filepath.Join(source, "platform_entry"), 0755); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Options{
		"platform_entry scaffold": {AgentID: "a", Kind: "legacy-http", Output: filepath.Join(root, "native", "platform_entry", "adapter")},
		"inside source":           {AgentID: "a", Kind: "legacy-http", Output: filepath.Join(source, "adapter"), Source: source},
		"source itself":           {AgentID: "a", Kind: "legacy-http", Output: source, Source: source},
		"unsupported kind":        {AgentID: "a", Kind: "plugin", Output: filepath.Join(root, "p")},
	}
	for name, options := range cases {
		if _, err := Generate(options); err == nil {
			t.Fatalf("%s: adapter bundle was generated", name)
		}
	}
}

func TestGenerateKeepsLegacySourceDigestStable(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy")
	if err := os.MkdirAll(source, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app.py", "requirements.txt"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte("print('hi')"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := Digest(source)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Generate(Options{AgentID: "legacy-agent", Kind: "legacy-http", Output: filepath.Join(root, "adapter"), EndpointRef: "endpoint://legacy", Source: source, Templates: testTemplates(t)})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SourceDigest != before || bundle.SourceDigest == "" {
		t.Fatalf("bundle source digest = %q want %q", bundle.SourceDigest, before)
	}
	after, err := Digest(source)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("legacy source digest changed: %s -> %s", before, after)
	}
	// A changed source between the two probes must abort the bundle.
	if err := os.WriteFile(filepath.Join(source, "app.py"), []byte("print('mutated')"), 0600); err != nil {
		t.Fatal(err)
	}
	mutated, err := Digest(source)
	if err != nil {
		t.Fatal(err)
	}
	if mutated == before {
		t.Fatal("digest did not track the source change")
	}
}

// TestGeneratePublishesAtomically proves the bundle is only visible under the
// final path once it is complete, and that a failure leaves neither a target
// directory nor staging leftovers.
// TestGeneratePublishesAtomically 证明适配包只在完整后才出现在最终路径，且失败时既不
// 留目标目录也不留暂存残留。
func TestGeneratePublishesAtomically(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(blocker, "adapter")
	if _, err := Generate(Options{AgentID: "legacy-agent", Kind: "legacy-http", Output: output, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)}); err == nil {
		t.Fatal("generation into an unusable parent unexpectedly succeeded")
	}
	// A failed generation must leave no published target. On POSIX a path whose
	// component is a regular file reports ENOTDIR (not ENOENT), so the earlier
	// os.IsNotExist-only form misjudged ENOTDIR as a leftover directory on
	// Linux/macOS. Any stat error means the bundle is absent; only a successful
	// stat proves the bundle leaked.
	// 生成失败不得发布目标。POSIX 在路径分量是普通文件时报 ENOTDIR（而非 ENOENT），
	// 因此仅用 os.IsNotExist 会把 ENOTDIR 误判为残留目录；此处任何 stat 错误都视为
	// “不存在”，只有 stat 成功才代表泄漏。
	if info, err := os.Stat(output); err == nil {
		t.Fatalf("failed generation left an output directory: is_dir=%v", info.IsDir())
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".adaptergen-") {
			t.Fatalf("failed generation left staging directory %s", entry.Name())
		}
	}

	// Once the parent exists the very same call must succeed and be complete.
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(Options{AgentID: "legacy-agent", Kind: "legacy-http", Output: output, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "mapping.json", "descriptor.json", "template.lock", "README.md", "schema.json", "capabilities.json", "fixtures/lifecycle.json", "deploy/deployment.yaml", "deploy/networkpolicy.yaml"} {
		if _, err := os.Stat(filepath.Join(output, filepath.FromSlash(name))); err != nil {
			t.Fatalf("published bundle missing %s: %v", name, err)
		}
	}
	// An existing target is never overwritten.
	if _, err := Generate(Options{AgentID: "legacy-agent", Kind: "legacy-http", Output: output, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)}); err == nil {
		t.Fatal("generation overwrote an existing bundle")
	}
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// copyKindAssets clones one kind's asset directory so a test can perturb a real
// asset and prove the generator renders it instead of an in-code default.
// copyKindAssets 复制某个 Kind 的资产目录，使测试可以扰动真实资产并证明生成器确实在
// 渲染资产，而不是代码内的默认值。
func copyKindAssets(t *testing.T, source, target, kind string) {
	t.Helper()
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(source, kind)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, content, 0644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestGeneratedDeployManifestsExpressKindIsolation proves each kind ships a real
// K8s Deployment and NetworkPolicy that encodes the isolation it declared; a
// kind that fell back to a shared placeholder would fail here.
// TestGeneratedDeployManifestsExpressKindIsolation 证明每种 Kind 都带上真正编码其
// 声明隔离的 K8s Deployment 与 NetworkPolicy；退化为共用占位文件的 Kind 会在此失败。
func TestGeneratedDeployManifestsExpressKindIsolation(t *testing.T) {
	cases := map[string][]string{
		"legacy-http": {"containerPort: 8080", "agent-adapter-isolation: container"},
		"grpc":        {"containerPort: 9090", "name: grpc", "port: 9090"},
		"process":     {"agent-adapter-isolation: sandbox", "PROCESS_SANDBOX_REQUIRE_CGROUP_MEMORY", "PROCESS_SANDBOX_MEMORY_BYTES", "memory: 128Mi"},
		"sidecar":     {"agent-adapter-isolation: sidecar", "SIDECAR_CLIENT_CERT_FILE", "adapter-mtls"},
	}
	for kind, markers := range cases {
		kind, markers := kind, markers
		t.Run(kind, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "bundle")
			if _, err := Generate(Options{AgentID: "legacy-agent", Kind: kind, Output: output, EndpointRef: "endpoint://legacy", Templates: testTemplates(t)}); err != nil {
				t.Fatal(err)
			}
			deployment, err := os.ReadFile(filepath.Join(output, "deploy", "deployment.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			network, err := os.ReadFile(filepath.Join(output, "deploy", "networkpolicy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range markers {
				if !strings.Contains(string(deployment), marker) && !strings.Contains(string(network), marker) {
					t.Fatalf("kind %s deploy manifests are missing %q", kind, marker)
				}
			}
			if !strings.Contains(string(network), "app: platform-app") || strings.Contains(string(network), "go-harness") {
				t.Fatalf("kind %s NetworkPolicy must accept current Platform calls and must not retain the retired Harness selector:\n%s", kind, network)
			}
			// No rendered manifest may leak an unsubstituted placeholder.
			for name, body := range map[string]string{"deployment": string(deployment), "networkpolicy": string(network)} {
				if strings.Contains(body, "{{") {
					t.Fatalf("kind %s %s still contains a template placeholder", kind, name)
				}
			}
			// Every kind must deny egress by default rather than allow all.
			if !strings.Contains(string(network), "policyTypes: [Ingress, Egress]") {
				t.Fatalf("kind %s NetworkPolicy does not restrict both directions", kind)
			}
		})
	}
}

// TestGenerateIsDrivenByKindAssets perturbs a real asset and proves the bundle
// follows it, which is the evidence that the four kinds are template-driven.
// TestGenerateIsDrivenByKindAssets 扰动真实资产并证明产物随之变化，这正是「四种 Kind
// 由模板驱动」的证据。
func TestGenerateIsDrivenByKindAssets(t *testing.T) {
	templates := filepath.Join(t.TempDir(), "adapters")
	copyKindAssets(t, testTemplates(t), templates, "legacy-http")
	profilePath := filepath.Join(templates, "legacy-http", "profile.json")
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	profile["port"] = 8443
	mutated, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, mutated, 0644); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(t.TempDir(), "bundle")
	if _, err := Generate(Options{AgentID: "asset-agent", Kind: "legacy-http", Output: output, EndpointRef: "endpoint://legacy", Templates: templates}); err != nil {
		t.Fatal(err)
	}
	network, err := os.ReadFile(filepath.Join(output, "deploy", "networkpolicy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(network), "port: 8443") {
		t.Fatalf("generated NetworkPolicy did not follow the edited asset:\n%s", network)
	}
	manifest, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `"adapter_id": "asset-agent"`) {
		t.Fatalf("manifest did not substitute the agent id:\n%s", manifest)
	}
}

// TestGenerateFailsClosedOnMissingOrContradictoryAssets proves the generator
// never silently emits a kind-agnostic bundle when the per-kind asset is absent
// or lies about its runtime contract.
// TestGenerateFailsClosedOnMissingOrContradictoryAssets 证明按 Kind 资产缺失或谎报
// 运行时契约时，生成器绝不静默产出与 Kind 无关的适配包。
func TestGenerateFailsClosedOnMissingOrContradictoryAssets(t *testing.T) {
	empty := t.TempDir()
	if _, err := Generate(Options{AgentID: "a", Kind: "process", Output: filepath.Join(t.TempDir(), "bundle"), EndpointRef: "endpoint://x", Templates: empty}); err == nil {
		t.Fatal("generation without the process asset unexpectedly succeeded")
	}

	contradictory := filepath.Join(t.TempDir(), "adapters")
	copyKindAssets(t, testTemplates(t), contradictory, "process")
	profilePath := filepath.Join(contradictory, "process", "profile.json")
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	profile["isolation"] = "container"
	mutated, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, mutated, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = Generate(Options{AgentID: "a", Kind: "process", Output: filepath.Join(t.TempDir(), "bundle"), EndpointRef: "endpoint://x", Templates: contradictory})
	if err == nil || !strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("a contradictory isolation asset was accepted: %v", err)
	}

	missingManifest := filepath.Join(t.TempDir(), "adapters")
	copyKindAssets(t, testTemplates(t), missingManifest, "grpc")
	if err := os.Remove(filepath.Join(missingManifest, "grpc", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(Options{AgentID: "a", Kind: "grpc", Output: filepath.Join(t.TempDir(), "bundle"), EndpointRef: "endpoint://x", Templates: missingManifest}); err == nil {
		t.Fatal("generation without the grpc manifest asset unexpectedly succeeded")
	}
}
