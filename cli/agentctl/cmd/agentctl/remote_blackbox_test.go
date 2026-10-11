package main

// remote_blackbox_test.go is the PF-04 CLI upgrade black-box: it builds the
// real agentctl binary, serves a real signed HTTP registry, and drives the
// subprocess through create -> remote upgrade -> conflict -> malicious archive.
// Nothing is faked in-process: the binary runs as users run it and the registry
// is genuine HTTP.
// remote_blackbox_test.go 是 PF-04 的 CLI 升级黑盒：构建真实 agentctl 二进制，
// 提供真实签名 HTTP 注册表，并以子进程方式驱动 create -> 远端升级 -> 冲突 ->
// 恶意压缩包全链路。没有任何进程内伪造：二进制按用户方式运行，注册表是真实 HTTP。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const blackboxTemplateID = "python-remote-demo"

type blackboxCLI struct {
	t      *testing.T
	binary string
	env    []string
	dir    string
}

type blackboxOutput struct {
	OK     bool `json:"ok"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Data map[string]any `json:"data"`
}

func (c *blackboxCLI) run(args ...string) (blackboxOutput, int) {
	c.t.Helper()
	cmd := exec.Command(c.binary, args...)
	cmd.Dir = c.dir
	cmd.Env = append(os.Environ(), c.env...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			c.t.Fatalf("agentctl could not start: %v", err)
		}
		code = exitErr.ExitCode()
	}
	var out blackboxOutput
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &out); err != nil {
		c.t.Fatalf("agentctl emitted non-JSON output: %q (%v)", stdout.String(), err)
	}
	return out, code
}

// buildBlackboxBinary compiles the real CLI once per test run.
// buildBlackboxBinary 每轮测试编译一次真实 CLI。
func buildBlackboxBinary(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	// file = <module>/cmd/agentctl/remote_blackbox_test.go
	moduleRoot := filepath.Join(filepath.Dir(file), "..", "..")
	bin := filepath.Join(t.TempDir(), "agentctl-blackbox.exe")
	build := exec.Command("go", "build", "-o", bin, "./cmd/agentctl")
	build.Dir = moduleRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// blackboxArchive builds one tar.gz template artifact from flat files.
// blackboxArchive 从平铺文件构建一个 tar.gz 模板工件。
func blackboxArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range []string{"platform_entry/server.py", "platform_entry/extra.py"} {
		content, ok := files[name]
		if !ok {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0644}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar body: %v", err)
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

func blackboxMaliciousArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "../evil.txt", Typeflag: tar.TypeReg, Size: 3, Mode: 0644}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write([]byte("pwn")); err != nil {
		t.Fatalf("tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

type blackboxVersion struct {
	version string
	files   map[string]string
}

// publishBlackboxRegistry writes the signed remote registry layout and serves
// it over real HTTP. Malicious archives are included verbatim.
// publishBlackboxRegistry 写出签名远端注册表并用真实 HTTP 提供服务；恶意压缩包按
// 原样收录。
func publishBlackboxRegistry(t *testing.T, priv ed25519.PrivateKey, versions []blackboxVersion, malicious map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	type entry struct {
		version string
		archive string
		sha     string
		sig     string
	}
	var entries []entry
	byID := map[string][]entry{}
	archives := map[string][]byte{}
	for _, v := range versions {
		data := blackboxArchive(t, v.files)
		path := "templates/" + blackboxTemplateID + "/" + v.version + ".tar.gz"
		archives[path] = data
		sum := sha256.Sum256(data)
		entries = append(entries, entry{
			version: v.version, archive: path,
			sha: hex.EncodeToString(sum[:]),
			sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)),
		})
	}
	for version, data := range malicious {
		path := "templates/" + blackboxTemplateID + "/" + version + ".tar.gz"
		archives[path] = data
		sum := sha256.Sum256(data)
		entries = append(entries, entry{
			version: version, archive: path,
			sha: hex.EncodeToString(sum[:]),
			sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)),
		})
	}
	byID[blackboxTemplateID] = entries
	index := map[string]any{
		"registry_version": "agentctl-remote-registry/v1",
		"templates": []map[string]any{{
			"id": blackboxTemplateID,
			"versions": func() []map[string]any {
				var out []map[string]any
				for _, e := range byID[blackboxTemplateID] {
					out = append(out, map[string]any{"version": e.version, "archive": e.archive, "sha256": e.sha, "signature": e.sig})
				}
				return out
			}(),
		}},
	}
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "registry"), 0755); err != nil {
		t.Fatalf("mkdir registry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "registry", "index.json"), raw, 0644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "registry", "index.json.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))), 0644); err != nil {
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
	return server.URL
}

// TestUpgradeRemoteRegistryBlackbox drives the compiled CLI against a real
// signed HTTP registry: create from a local template, upgrade remotely, hit the
// ownership conflict, and refuse a malicious traversal archive.
// TestUpgradeRemoteRegistryBlackbox 用编译出的真实 CLI 对真实签名 HTTP 注册表执行
// 黑盒链路：本地模板 create、远端升级、所有权冲突、拒绝恶意穿越压缩包。
func TestUpgradeRemoteRegistryBlackbox(t *testing.T) {
	binary := buildBlackboxBinary(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "registry.pub")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// Local bootstrap registry for agentctl create (v1.0.0).
	// 供 agentctl create 使用的本地引导注册表（v1.0.0）。
	localRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localRoot, blackboxTemplateID, "platform_entry"), 0755); err != nil {
		t.Fatalf("mkdir local template: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(localRoot, "registry"), 0755); err != nil {
		t.Fatalf("mkdir local registry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localRoot, "registry", "index.yaml"), []byte("version: v1\ntemplates:\n  - id: "+blackboxTemplateID+"\n    version: 1.0.0\n"), 0644); err != nil {
		t.Fatalf("write local index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localRoot, blackboxTemplateID, "platform_entry", "server.py"), []byte("# template 1.0.0\n"), 0644); err != nil {
		t.Fatalf("write local template file: %v", err)
	}

	registryURL := publishBlackboxRegistry(t, priv, []blackboxVersion{
		{version: "1.1.0", files: map[string]string{
			"platform_entry/server.py": "# template 1.1.0\n",
			"platform_entry/extra.py":  "# added in 1.1.0\n",
		}},
		{version: "1.2.0", files: map[string]string{
			"platform_entry/server.py": "# template 1.2.0\n",
			"platform_entry/extra.py":  "# added in 1.2.0\n",
		}},
	}, map[string][]byte{"1.3.0": blackboxMaliciousArchive(t)})

	workdir := t.TempDir()
	cli := &blackboxCLI{t: t, binary: binary, dir: workdir, env: []string{"AGENTCTL_TEMPLATE_ROOT=" + localRoot}}

	// 1. Bootstrap the workspace with the real CLI.
	out, code := cli.run("create", "--template", blackboxTemplateID, "--language", "python", "--name", "demo", "--output", "agent")
	if code != 0 || !out.OK {
		t.Fatalf("create failed: %+v/%d", out, code)
	}
	workspace := filepath.Join(workdir, "agent")

	// 2. Remote upgrade v1.0.0 -> v1.1.0 through the signed HTTP registry.
	out, code = cli.run("upgrade", "--workspace", "agent", "--registry", registryURL, "--registry-key", keyFile, "--to-template-version", "1.1.0")
	if code != 0 || !out.OK {
		t.Fatalf("remote upgrade failed: %+v/%d", out, code)
	}
	if out.Data["status"] != "upgraded" {
		t.Fatalf("expected upgraded, got %#v", out.Data)
	}
	serverPy, err := os.ReadFile(filepath.Join(workspace, "platform_entry", "server.py"))
	if err != nil || string(serverPy) != "# template 1.1.0\n" {
		t.Fatalf("server.py not upgraded: %q %v", string(serverPy), err)
	}
	extraPy, err := os.ReadFile(filepath.Join(workspace, "platform_entry", "extra.py"))
	if err != nil || string(extraPy) != "# added in 1.1.0\n" {
		t.Fatalf("extra.py not added: %q %v", string(extraPy), err)
	}
	lockRaw, err := os.ReadFile(filepath.Join(workspace, "template.lock"))
	if err != nil || !strings.Contains(string(lockRaw), `"template_version": "1.1.0"`) {
		t.Fatalf("lock not bumped: %v", err)
	}

	// 3. A locally modified generated file must block the upgrade (conflict).
	if err := os.WriteFile(filepath.Join(workspace, "platform_entry", "extra.py"), []byte("# hacked\n"), 0644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	out, code = cli.run("upgrade", "--workspace", "agent", "--registry", registryURL, "--registry-key", keyFile, "--to-template-version", "1.2.0")
	if code == 0 || out.OK || len(out.Errors) == 0 || out.Errors[0].Code != "UPGRADE_CONFLICT" {
		t.Fatalf("expected stable UPGRADE_CONFLICT: %+v/%d", out, code)
	}
	hacked, err := os.ReadFile(filepath.Join(workspace, "platform_entry", "extra.py"))
	if err != nil || string(hacked) != "# hacked\n" {
		t.Fatalf("conflict must not write: %q %v", string(hacked), err)
	}

	// 4. A signed-but-malicious archive must be refused with a stable code and
	// no file outside the workspace may appear.
	out, code = cli.run("upgrade", "--workspace", "agent", "--registry", registryURL, "--registry-key", keyFile, "--to-template-version", "1.3.0")
	if code == 0 || out.OK || len(out.Errors) == 0 || out.Errors[0].Code != "REGISTRY_ARCHIVE_UNSAFE" {
		t.Fatalf("expected REGISTRY_ARCHIVE_UNSAFE: %+v/%d", out, code)
	}
	if _, err := os.Stat(filepath.Join(workdir, "evil.txt")); !os.IsNotExist(err) {
		t.Fatalf("traversal escaped the staging directory")
	}

	// 5. A registry without the trusted key must be refused before any fetch.
	out, code = cli.run("upgrade", "--workspace", "agent", "--registry", registryURL, "--to-template-version", "1.2.0")
	if code == 0 || out.OK || len(out.Errors) == 0 || out.Errors[0].Code != "REGISTRY_KEY_REQUIRED" {
		t.Fatalf("expected REGISTRY_KEY_REQUIRED: %+v/%d", out, code)
	}
}
