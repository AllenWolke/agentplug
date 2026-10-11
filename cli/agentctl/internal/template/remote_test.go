package template

// remote_test.go covers the PF-04 remote immutable registry: signed index and
// artifact verification, safe extraction, and the complete malicious-archive
// matrix. Every negative case asserts the stable UpgradeError code and that no
// file ever lands outside the staging directory.
// remote_test.go 覆盖 PF-04 远端不可变注册表：签名 index 与工件校验、安全解压和
// 完整恶意压缩包矩阵。每个负例断言稳定的 UpgradeError 错误码，并确认没有任何文件
// 落在暂存目录之外。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type archiveEntry struct {
	name     string
	typeflag byte
	content  []byte
	linkname string
	size     int64
}

type remoteFixture struct {
	server    *httptest.Server
	serverURL string
	root      string
}

// buildArchive packs entries into a deterministic tar.gz stream.
// buildArchive 将条目打包成确定性的 tar.gz 流。
func buildArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, entry := range entries {
		size := entry.size
		if entry.typeflag == tar.TypeReg && size == 0 {
			size = int64(len(entry.content))
		}
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Size:     size,
			Linkname: entry.linkname,
			Mode:     0644,
		}
		if entry.typeflag == tar.TypeDir {
			header.Mode = 0755
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %q: %v", entry.name, err)
		}
		if entry.typeflag == tar.TypeReg {
			if _, err := tw.Write(entry.content); err != nil {
				t.Fatalf("write tar body %q: %v", entry.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func templateEntries(version string) []archiveEntry {
	// Templates never ship manifest.json: create writes it per agent and the
	// ownership lock keeps it template-managed without an archive copy.
	// 模板不携带 manifest.json：create 按 Agent 写入，所有权锁保持其为
	// template-managed，无需压缩包副本。
	return []archiveEntry{
		{name: "platform_entry/", typeflag: tar.TypeDir},
		{name: "platform_entry/server.py", typeflag: tar.TypeReg, content: []byte("# template " + version + "\n")},
	}
}

type indexEntrySpec struct {
	id        string
	version   string
	archive   string
	sha256    string
	signature string
}

// publishRegistry lays out a complete remote registry on disk and serves it
// over real HTTP. Explicit spec fields make it possible to craft malicious
// metadata without ever writing outside the fixture root.
// publishRegistry 在磁盘上布置完整远端注册表并用真实 HTTP 提供服务；显式 spec 字段
// 用于构造恶意元数据，且不会写到 fixture 根目录之外。
func publishRegistry(t *testing.T, priv ed25519.PrivateKey, archives map[string][]byte, index []indexEntrySpec) *remoteFixture {
	t.Helper()
	root := t.TempDir()
	indexDoc := RemoteIndex{RegistryVersion: remoteIndexFormat}
	byID := map[string]*RemoteTemplate{}
	var order []string
	for _, spec := range index {
		tpl, ok := byID[spec.id]
		if !ok {
			tpl = &RemoteTemplate{ID: spec.id}
			byID[spec.id] = tpl
			order = append(order, spec.id)
		}
		sig := spec.signature
		if data, ok := archives[spec.archive]; ok && sig == "" {
			sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
		}
		digest := spec.sha256
		if digest == "" {
			sum := sha256.Sum256(archives[spec.archive])
			digest = hex.EncodeToString(sum[:])
		}
		tpl.Versions = append(tpl.Versions, RemoteVersion{Version: spec.version, Archive: spec.archive, SHA256: digest, Signature: sig})
	}
	for _, id := range order {
		indexDoc.Templates = append(indexDoc.Templates, *byID[id])
	}
	raw, err := json.MarshalIndent(indexDoc, "", "  ")
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "registry"), 0755); err != nil {
		t.Fatalf("mkdir registry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "registry", "index.json"), raw, 0644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "registry", "index.json.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))+"\n"), 0644); err != nil {
		t.Fatalf("write index signature: %v", err)
	}
	for path, data := range archives {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir archive parent: %v", err)
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			t.Fatalf("write archive %s: %v", path, err)
		}
	}
	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	t.Cleanup(server.Close)
	return &remoteFixture{server: server, serverURL: server.URL, root: root}
}

// bootstrapWorkspace materializes a workspace exactly as agentctl create does
// for the given template version, lock included.
// bootstrapWorkspace 按 agentctl create 的产物结构落地一个工作区，含 template.lock。
func bootstrapWorkspace(t *testing.T, files map[string]string, templateID, version string) string {
	t.Helper()
	workspace := t.TempDir()
	for name, content := range files {
		full := filepath.Join(workspace, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	lock, err := BuildOwnershipLock(workspace, templateID, version)
	if err != nil {
		t.Fatalf("build lock: %v", err)
	}
	raw, _ := json.MarshalIndent(lock, "", "  ")
	if err := os.WriteFile(filepath.Join(workspace, "template.lock"), append(raw, '\n'), 0644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	return workspace
}

func fixtureFiles(version string) map[string]string {
	return map[string]string{
		"manifest.json":            `{"agent_id":"demo-agent","metadata":{"template_id":"python-remote-demo","template_version":"` + version + `"},"execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://demo-agent/input/v1"},"runtime":{"transport":"http","isolation":"container"}}` + "\n",
		"platform_entry/server.py": "# template " + version + "\n",
		"domain/business.py":       "# business owned, never touched\n",
	}
}

func mustUpgradeCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got none")
	}
	var upgradeErr *UpgradeError
	if !errors.As(err, &upgradeErr) {
		t.Fatalf("expected *UpgradeError, got %T: %v", err, err)
	}
	return upgradeErr.Code
}

// pubOf asserts the concrete ed25519 public key type out of a generated pair.
// pubOf 从生成的密钥对中断言出具体的 ed25519 公钥类型。
func pubOf(t *testing.T, priv ed25519.PrivateKey) ed25519.PublicKey {
	t.Helper()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("private key has no ed25519 public half")
	}
	return pub
}

// TestRemoteFetchAndUpgradeHappyPath drives the full positive flow: signed
// index, signed artifact, digest match, safe extraction and the existing
// ownership-lock upgrade on top of the staged registry.
// TestRemoteFetchAndUpgradeHappyPath 驱动完整正向链路：签名 index、签名工件、摘要
// 匹配、安全解压，并在暂存注册表之上执行既有的所有权锁升级。
func TestRemoteFetchAndUpgradeHappyPath(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v1 := buildArchive(t, templateEntries("1.0.0"))
	v2 := buildArchive(t, templateEntries("1.1.0"))
	fixture := publishRegistry(t, priv, map[string][]byte{
		"templates/python-remote-demo/1.0.0.tar.gz": v1,
		"templates/python-remote-demo/1.1.0.tar.gz": v2,
	}, []indexEntrySpec{
		{id: "python-remote-demo", version: "1.0.0", archive: "templates/python-remote-demo/1.0.0.tar.gz"},
		{id: "python-remote-demo", version: "1.1.0", archive: "templates/python-remote-demo/1.1.0.tar.gz"},
	})
	workspace := bootstrapWorkspace(t, fixtureFiles("1.0.0"), "python-remote-demo", "1.0.0")

	staging, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, priv)}, "python-remote-demo", "1.1.0")
	if fetchErr != nil {
		t.Fatalf("fetch: %v", fetchErr)
	}
	defer cleanup()
	report, upgradeErr := Upgrade(UpgradeOptions{Workspace: workspace, TemplateRoot: staging, ToVersion: "1.1.0"})
	if upgradeErr != nil {
		t.Fatalf("upgrade: %v", upgradeErr)
	}
	if report.Status != "upgraded" {
		t.Fatalf("expected upgraded, got %s", report.Status)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "platform_entry", "server.py"))
	if err != nil || string(data) != "# template 1.1.0\n" {
		t.Fatalf("platform file was not upgraded: %q %v", string(data), err)
	}
	lockRaw, err := os.ReadFile(filepath.Join(workspace, "template.lock"))
	if err != nil || !strings.Contains(string(lockRaw), `"template_version": "1.1.0"`) {
		t.Fatalf("lock was not bumped: %v", err)
	}
	business, err := os.ReadFile(filepath.Join(workspace, "domain", "business.py"))
	if err != nil || string(business) != "# business owned, never touched\n" {
		t.Fatalf("business file must stay untouched: %v", err)
	}
}

// TestRemoteUpgradeConflictPreservesWorkspace proves the remote path still
// funnels through the ownership lock: a locally modified generated file blocks
// the upgrade without any write.
// TestRemoteUpgradeConflictPreservesWorkspace 证明远端路径仍经过所有权锁：本地修改
// 过的生成文件会阻止升级且不产生任何写入。
func TestRemoteUpgradeConflictPreservesWorkspace(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v2 := buildArchive(t, templateEntries("1.1.0"))
	fixture := publishRegistry(t, priv, map[string][]byte{
		"templates/python-remote-demo/1.1.0.tar.gz": v2,
	}, []indexEntrySpec{{id: "python-remote-demo", version: "1.1.0", archive: "templates/python-remote-demo/1.1.0.tar.gz"}})
	workspace := bootstrapWorkspace(t, fixtureFiles("1.0.0"), "python-remote-demo", "1.0.0")
	if err := os.WriteFile(filepath.Join(workspace, "platform_entry", "server.py"), []byte("# hacked locally\n"), 0644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	staging, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, priv)}, "python-remote-demo", "1.1.0")
	if fetchErr != nil {
		t.Fatalf("fetch: %v", fetchErr)
	}
	defer cleanup()
	report, upgradeErr := Upgrade(UpgradeOptions{Workspace: workspace, TemplateRoot: staging, ToVersion: "1.1.0"})
	if code := mustUpgradeCode(t, upgradeErr); code != "UPGRADE_CONFLICT" {
		t.Fatalf("expected UPGRADE_CONFLICT, got %s", code)
	}
	if report.Status != "conflict" || len(report.Conflicts) != 1 || report.Conflicts[0].Path != "platform_entry/server.py" {
		t.Fatalf("unexpected conflict report: %+v", report)
	}
	data, _ := os.ReadFile(filepath.Join(workspace, "platform_entry", "server.py"))
	if string(data) != "# hacked locally\n" {
		t.Fatalf("conflict must not write: %q", string(data))
	}
}

// TestRemoteMaliciousMatrix walks the complete malicious-archive matrix. Each
// case publishes a registry that is malicious in exactly one way and asserts
// the stable error code plus that the sentinel file outside staging survives.
// TestRemoteMaliciousMatrix 遍历完整的恶意压缩包矩阵。每个用例只在一个维度上
// 恶意，断言稳定错误码，并确认暂存之外的哨兵文件原样保留。
func TestRemoteMaliciousMatrix(t *testing.T) {
	_, goodPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate good key: %v", err)
	}
	_, evilPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate evil key: %v", err)
	}
	goodArchive := buildArchive(t, templateEntries("1.1.0"))
	tamperedArchive := append([]byte(nil), goodArchive...)
	tamperedArchive[len(tamperedArchive)-10] ^= 0xff

	// A single file just past the default 8MB per-file cap: small on the wire,
	// fatal at extraction. / 单文件略超默认 8MB 上限：线上很小，解压即失败。
	bomb := buildArchive(t, []archiveEntry{{name: "bomb.bin", typeflag: tar.TypeReg, size: 9 << 20, content: make([]byte, 9<<20)}})

	cases := []struct {
		name     string
		archives map[string][]byte
		index    []indexEntrySpec
		code     string
	}{
		{
			name:     "path traversal entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{{name: "../evil.txt", typeflag: tar.TypeReg, content: []byte("pwn")}})},
			index:    []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:     "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name:     "absolute path entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{{name: "/etc/evil.txt", typeflag: tar.TypeReg, content: []byte("pwn")}})},
			index:    []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:     "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name:     "windows traversal entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{{name: `..\\evil.txt`, typeflag: tar.TypeReg, content: []byte("pwn")}})},
			index:    []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:     "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name: "symlink entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{
				{name: "real.txt", typeflag: tar.TypeReg, content: []byte("x")},
				{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
			})},
			index: []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:  "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name: "hardlink entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{
				{name: "real.txt", typeflag: tar.TypeReg, content: []byte("x")},
				{name: "hard", typeflag: tar.TypeLink, linkname: "real.txt"},
			})},
			index: []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:  "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name:     "character device entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{{name: "dev", typeflag: tar.TypeChar}})},
			index:    []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:     "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name:     "fifo entry",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{{name: "pipe", typeflag: tar.TypeFifo}})},
			index:    []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:     "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name: "duplicate path entries",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": buildArchive(t, []archiveEntry{
				{name: "a.txt", typeflag: tar.TypeReg, content: []byte("1")},
				{name: "a.txt", typeflag: tar.TypeReg, content: []byte("2")},
			})},
			index: []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:  "REGISTRY_ARCHIVE_UNSAFE",
		},
		{
			name:     "decompression bomb",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": bomb},
			index:    []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}},
			code:     "REGISTRY_ARCHIVE_TOO_LARGE",
		},
		{
			name:     "tampered archive digest mismatch",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": tamperedArchive},
			index: []indexEntrySpec{{
				id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz",
				sha256: func() string { sum := sha256.Sum256(goodArchive); return hex.EncodeToString(sum[:]) }(),
			}},
			code: "REGISTRY_DIGEST_MISMATCH",
		},
		{
			name:     "archive signed by wrong key",
			archives: map[string][]byte{"templates/e/1.1.0.tar.gz": goodArchive},
			index: []indexEntrySpec{{
				id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz",
				signature: base64.StdEncoding.EncodeToString(ed25519.Sign(evilPriv, goodArchive)),
			}},
			code: "REGISTRY_SIGNATURE_INVALID",
		},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			fixture := publishRegistry(t, goodPriv, testCase.archives, testCase.index)
			outside := filepath.Join(t.TempDir(), "outside-marker.txt")
			if err := os.WriteFile(outside, []byte("sentinel"), 0644); err != nil {
				t.Fatalf("write sentinel: %v", err)
			}
			_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, goodPriv)}, "e", "1.1.0")
			if cleanup != nil {
				cleanup()
			}
			if code := mustUpgradeCode(t, fetchErr); code != testCase.code {
				t.Fatalf("expected %s, got %s (%v)", testCase.code, code, fetchErr)
			}
			// The traversal sentinel must survive every case untouched.
			// 穿越哨兵文件必须在所有用例中原样保留。
			data, readErr := os.ReadFile(outside)
			if readErr != nil || string(data) != "sentinel" {
				t.Fatalf("outside file was touched: %q %v", string(data), readErr)
			}
		})
	}
}

// TestRemoteIndexAndMetadataMatrix covers the metadata-side defenses: index
// signatures, availability and schema validation.
// TestRemoteIndexAndMetadataMatrix 覆盖元数据侧防御：index 签名、可用性与结构校验。
func TestRemoteIndexAndMetadataMatrix(t *testing.T) {
	_, goodPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate good key: %v", err)
	}
	_, evilPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate evil key: %v", err)
	}
	goodArchive := buildArchive(t, templateEntries("1.1.0"))

	t.Run("index signed by wrong key", func(t *testing.T) {
		fixture := publishRegistry(t, goodPriv, map[string][]byte{"templates/e/1.1.0.tar.gz": goodArchive}, []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}})
		raw, err := os.ReadFile(filepath.Join(fixture.root, "registry", "index.json"))
		if err != nil {
			t.Fatalf("read index: %v", err)
		}
		if err := os.WriteFile(filepath.Join(fixture.root, "registry", "index.json.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(evilPriv, raw))), 0644); err != nil {
			t.Fatalf("rewrite index signature: %v", err)
		}
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, goodPriv)}, "e", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "REGISTRY_INDEX_SIGNATURE_INVALID" {
			t.Fatalf("expected REGISTRY_INDEX_SIGNATURE_INVALID, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("index missing", func(t *testing.T) {
		root := t.TempDir()
		server := httptest.NewServer(http.FileServer(http.Dir(root)))
		defer server.Close()
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: server.URL, PublicKey: pubOf(t, goodPriv)}, "e", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "REGISTRY_INDEX_UNAVAILABLE" {
			t.Fatalf("expected REGISTRY_INDEX_UNAVAILABLE, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("archive missing", func(t *testing.T) {
		fixture := publishRegistry(t, goodPriv, map[string][]byte{}, []indexEntrySpec{{
			id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz",
			sha256:    func() string { sum := sha256.Sum256(goodArchive); return hex.EncodeToString(sum[:]) }(),
			signature: base64.StdEncoding.EncodeToString(ed25519.Sign(goodPriv, goodArchive)),
		}})
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, goodPriv)}, "e", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "REGISTRY_ARCHIVE_UNAVAILABLE" {
			t.Fatalf("expected REGISTRY_ARCHIVE_UNAVAILABLE, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("template not registered", func(t *testing.T) {
		fixture := publishRegistry(t, goodPriv, map[string][]byte{"templates/e/1.1.0.tar.gz": goodArchive}, []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}})
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, goodPriv)}, "other", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "TEMPLATE_NOT_FOUND" {
			t.Fatalf("expected TEMPLATE_NOT_FOUND, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("version not registered", func(t *testing.T) {
		fixture := publishRegistry(t, goodPriv, map[string][]byte{"templates/e/1.1.0.tar.gz": goodArchive}, []indexEntrySpec{{id: "e", version: "1.1.0", archive: "templates/e/1.1.0.tar.gz"}})
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, goodPriv)}, "e", "9.9.9")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "TEMPLATE_VERSION_UNAVAILABLE" {
			t.Fatalf("expected TEMPLATE_VERSION_UNAVAILABLE, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("unsafe archive path in index", func(t *testing.T) {
		// The artifact itself is stored at a safe path; only the index entry
		// points outside, so the fixture never writes outside its root.
		// 工件本体存放在安全路径，仅 index 条目指向外部，因此 fixture 不会写到
		// 根目录之外。
		fixture := publishRegistry(t, goodPriv, map[string][]byte{"templates/e/1.1.0.tar.gz": goodArchive}, []indexEntrySpec{{id: "e", version: "1.1.0", archive: "../../evil/1.1.0.tar.gz"}})
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: fixture.serverURL, PublicKey: pubOf(t, goodPriv)}, "e", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "REGISTRY_INDEX_INVALID" {
			t.Fatalf("expected REGISTRY_INDEX_INVALID, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("missing public key", func(t *testing.T) {
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{BaseURL: "http://example.invalid"}, "e", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "REGISTRY_KEY_REQUIRED" {
			t.Fatalf("expected REGISTRY_KEY_REQUIRED, got %s (%v)", code, fetchErr)
		}
	})

	t.Run("missing base url", func(t *testing.T) {
		_, cleanup, fetchErr := FetchTemplate(context.Background(), FetchOptions{PublicKey: pubOf(t, goodPriv)}, "e", "1.1.0")
		if cleanup != nil {
			cleanup()
		}
		if code := mustUpgradeCode(t, fetchErr); code != "REGISTRY_URL_REQUIRED" {
			t.Fatalf("expected REGISTRY_URL_REQUIRED, got %s (%v)", code, fetchErr)
		}
	})
}

// TestExtractTarGzLimits proves the decompression bomb cap directly at the
// extractor level with a small limit.
// TestExtractTarGzLimits 以小上限直接在解压器层面证明解压炸弹上限有效。
func TestExtractTarGzLimits(t *testing.T) {
	bomb := buildArchive(t, []archiveEntry{{name: "bomb.bin", typeflag: tar.TypeReg, size: 1 << 22, content: make([]byte, 1<<22)}})
	dest := t.TempDir()
	err := extractTarGz(bomb, dest, extractLimits{uncompressedTotal: 1 << 20, perFile: 1 << 20, maxFiles: 10})
	if code := mustUpgradeCode(t, err); code != "REGISTRY_ARCHIVE_TOO_LARGE" {
		t.Fatalf("expected REGISTRY_ARCHIVE_TOO_LARGE, got %s (%v)", code, err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "bomb.bin")); statErr == nil {
		t.Fatalf("bomb file must not be written")
	}
}

// TestWorkspaceIdentity reads back the lock identity used to select the remote
// artifact.
// TestWorkspaceIdentity 验证用于选择远端工件的身份读取。
func TestWorkspaceIdentity(t *testing.T) {
	workspace := bootstrapWorkspace(t, fixtureFiles("1.0.0"), "python-remote-demo", "1.0.0")
	id, version, err := WorkspaceIdentity(workspace)
	if err != nil || id != "python-remote-demo" || version != "1.0.0" {
		t.Fatalf("unexpected identity: %s %s %v", id, version, err)
	}
	_, _, err = WorkspaceIdentity(filepath.Join(workspace, "does-not-exist"))
	if code := mustUpgradeCode(t, err); code != "WORKSPACE_NOT_FOUND" {
		t.Fatalf("expected WORKSPACE_NOT_FOUND, got %s (%v)", code, err)
	}
}

// TestLoadRemoteKey covers key material handling.
// TestLoadRemoteKey 覆盖密钥材料处理。
func TestLoadRemoteKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "registry.pub")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	loaded, loadErr := LoadRemoteKey(keyFile)
	if loadErr != nil || !bytes.Equal(loaded, pub) {
		t.Fatalf("key load failed: %v", loadErr)
	}
	if err := os.WriteFile(keyFile, []byte("not base64!!"), 0644); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	if _, loadErr = LoadRemoteKey(keyFile); loadErr == nil {
		t.Fatalf("invalid key material must fail")
	} else if code := mustUpgradeCode(t, loadErr); code != "REGISTRY_KEY_INVALID" {
		t.Fatalf("expected REGISTRY_KEY_INVALID, got %s", code)
	}
}
