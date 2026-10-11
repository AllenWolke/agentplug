package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

// baselineFixture is the checked-in expectation for one legacy Agent. Only
// fixtures marked "onboarded" carry a path that must already exist and match a
// real scan; "pending-onboarding" fixtures describe Agents that have been placed
// in the tree but are not yet onboarding targets.
// baselineFixture 是某个存量 Agent 的登记期望。只有 status="onboarded" 的夹具必须
// 指向真实存在且能被真实扫描命中的目录；"pending-onboarding" 仅描述已放入目录、
// 但尚未接入的 Agent。
type baselineFixture struct {
	InventoryVersion  string `json:"inventory_version"`
	Source            string `json:"source"`
	Path              string `json:"path"`
	Status            string `json:"status"`
	ExpectedLanguage  string `json:"expected_language"`
	ExpectedFramework string `json:"expected_framework"`
	ExpectedTransport string `json:"expected_transport"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	// file = <root>/cli/agentctl/internal/inspect/baseline_test.go
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

// TestBaselineFixturesMatchRealScan proves the checked-in baselines are not
// pre-filled expectations: every onboarded fixture is scanned against the real
// legacy Agent source and the emitted inventory must match it.
// TestBaselineFixturesMatchRealScan 证明登记基线不是预填期望：每个「已接入」夹具
// 都会对真实存量 Agent 源码执行扫描，且产出的盘点结果必须与之一致。
func TestBaselineFixturesMatchRealScan(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "conformance", "fixtures", "inspection")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var fixture baselineFixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		if fixture.Path == "" {
			t.Fatalf("%s: inspection fixture requires an explicit source path", entry.Name())
		}
		if fixture.Status != "onboarded" {
			// Declared baseline for a not-yet-onboarded Agent: the scan must not
			// be asserted against it.
			continue
		}
		scanned++
		t.Run(fixture.Source, func(t *testing.T) {
			agentDir := filepath.Join(root, filepath.FromSlash(fixture.Path))
			if info, err := os.Stat(agentDir); err != nil || !info.IsDir() {
				t.Fatalf("onboarded fixture %s has no source at %s", fixture.Source, fixture.Path)
			}
			before := treeDigest(t, agentDir)
			report, err := Run(agentDir)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if len(report.ReadErrors) != 0 {
				t.Fatalf("scan reported read errors: %v", report.ReadErrors)
			}
			if report.Language != fixture.ExpectedLanguage {
				t.Fatalf("language = %q, expected %q", report.Language, fixture.ExpectedLanguage)
			}
			if fixture.ExpectedFramework != "" && report.Framework != fixture.ExpectedFramework {
				t.Fatalf("framework = %q, expected %q", report.Framework, fixture.ExpectedFramework)
			}
			if report.SuggestedAdapter != fixture.ExpectedTransport {
				t.Fatalf("suggested_adapter = %q, expected %q", report.SuggestedAdapter, fixture.ExpectedTransport)
			}
			if after := treeDigest(t, agentDir); before != after {
				t.Fatal("inspector modified the legacy Agent source")
			}
			assertSchemaConformant(t, report)
		})
	}
	if scanned == 0 {
		t.Fatal("no onboarded baseline fixtures were scanned")
	}
}

// treeDigest hashes the identity (relative path, size, mtime) of every file so a
// scan can prove it never wrote to the legacy Agent.
// treeDigest 对每个文件的身份（相对路径、大小、mtime）取哈希，使扫描能证明它从未
// 写入存量 Agent。
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Generated tool state is intentionally outside the inspected Agent
			// source contract. On Windows these cache directories can have ACLs
			// that deny traversal to a different test token; skip the same paths as
			// the production inspector instead of weakening source read failures.
			// 生成缓存不属于 Agent 源码契约；Windows 下不同测试令牌可能无法遍历这些目录。
			// 此处与生产扫描器一致跳过缓存，但仍对真实源码读取错误失败。
			if skipDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return walkErr
		}
		if entry.IsDir() {
			if path != root && skipDir(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s|%d|%d", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	digest := sha256.New()
	for _, line := range lines {
		_, _ = digest.Write([]byte(line))
		_, _ = digest.Write([]byte("\n"))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func TestTreeDigestIgnoresGeneratedAgentCaches(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".pytest_cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "agent.py")
	if err := os.WriteFile(source, []byte("def invoke(): return {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := treeDigest(t, root)
	if err := os.WriteFile(filepath.Join(root, ".pytest_cache", "generated"), []byte("cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	if after := treeDigest(t, root); before != after {
		t.Fatal("generated cache content must not affect the source-tree digest")
	}
}

// assertSchemaConformant checks the emitted report against the declared
// inventory contract without a third-party validator.
// assertSchemaConformant 在无第三方校验器的情况下，将产出的报告与声明的盘点契约
// 对齐检查。
func assertSchemaConformant(t *testing.T, report Report) {
	t.Helper()
	root := repoRoot(t)
	rawSchema, err := os.ReadFile(filepath.Join(root, "contracts", "agent-template", "v1", "inventory.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(rawSchema, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatal("inventory schema must keep additionalProperties:false")
	}
	rawReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(rawReport, &emitted); err != nil {
		t.Fatal(err)
	}
	for name := range emitted {
		if _, ok := schema.Properties[name]; !ok {
			t.Fatalf("report field %q is not declared in inventory.schema.json", name)
		}
	}
	for _, name := range schema.Required {
		if _, ok := emitted[name]; !ok {
			t.Fatalf("report is missing required field %q", name)
		}
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(emitted["findings"], &findings); err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		for _, required := range []string{"code", "status", "summary"} {
			if _, ok := finding[required]; !ok {
				t.Fatalf("finding is missing required field %q", required)
			}
		}
		for name := range finding {
			switch name {
			case "code", "status", "summary", "evidence", "confidence":
			default:
				t.Fatalf("finding field %q is not declared in inventory.schema.json", name)
			}
		}
	}
}
