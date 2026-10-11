package template

// remote.go implements the PF-04 remote immutable template registry client.
// A registry is any static HTTP server publishing:
//
//	{base}/registry/index.json       - machine-readable version index
//	{base}/registry/index.json.sig   - base64 Ed25519 signature over index bytes
//	{base}/{archive}                - immutable tar.gz template artifact
//
// Every artifact carries its own Ed25519 signature and SHA-256 digest in the
// index, so a compromised host cannot swap archives even if the index itself is
// re-published. Extraction enforces the full malicious-archive matrix before a
// single byte reaches the workspace.
// remote.go 实现 PF-04 远端不可变模板注册表客户端。注册表可以是任何静态 HTTP 服务，
// 发布签名 index 与不可变 tar.gz 工件；每个工件在 index 中携带独立 Ed25519 签名和
// SHA-256 摘要，因此即使 index 被重新发布也无法偷换工件。解压在任何字节落盘前执行
// 完整的恶意压缩包防御矩阵。

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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	remoteIndexFormat      = "agentctl-remote-registry/v1"
	remoteIndexSizeLimit   = 4 << 20
	remoteSignatureLimit   = 1 << 16
	remoteArchiveSizeLimit = 64 << 20
	remoteFetchTimeout     = 60 * time.Second
	remoteMaxHTTPRedirs    = 3
)

// extractLimits bound the decompression of a downloaded archive. The defaults
// are deliberately generous for real templates yet small enough that a
// compressed bomb fails long before exhausting disk or memory.
// extractLimits 约束下载压缩包的解压行为。默认值对真实模板足够宽裕，又足以让压缩
// 炸弹在耗尽磁盘或内存之前失败。
type extractLimits struct {
	uncompressedTotal int64
	perFile           int64
	maxFiles          int
}

var defaultExtractLimits = extractLimits{
	uncompressedTotal: 256 << 20,
	perFile:           8 << 20,
	maxFiles:          4096,
}

// RemoteVersion is one immutable artifact entry of the remote index.
// RemoteVersion 是远端 index 中一个不可变工件条目。
type RemoteVersion struct {
	Version   string `json:"version"`
	Archive   string `json:"archive"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

type RemoteTemplate struct {
	ID       string          `json:"id"`
	Versions []RemoteVersion `json:"versions"`
}

type RemoteIndex struct {
	RegistryVersion string           `json:"registry_version"`
	Templates       []RemoteTemplate `json:"templates"`
}

// FetchOptions describes one remote registry lookup.
// FetchOptions 描述一次远端注册表获取。
type FetchOptions struct {
	BaseURL   string
	PublicKey ed25519.PublicKey
	Client    *http.Client
}

// LoadRemoteKey reads a base64-encoded raw Ed25519 public key from a file.
// LoadRemoteKey 从文件读取 base64 编码的裸 Ed25519 公钥。
func LoadRemoteKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, upgradeError("REGISTRY_KEY_UNREADABLE", err.Error())
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(data) != ed25519.PublicKeySize {
		return nil, upgradeError("REGISTRY_KEY_INVALID", "registry public key must be base64 raw ed25519")
	}
	return ed25519.PublicKey(data), nil
}

// WorkspaceIdentity reads the template id and version a workspace is locked to.
// It lets the CLI fetch the right artifact before calling Upgrade.
// WorkspaceIdentity 读取工作区锁定的模板 id 与版本，使 CLI 能在调用 Upgrade 前先获取
// 正确的工件。
func WorkspaceIdentity(workspace string) (string, string, error) {
	dir, err := resolveWorkspace(workspace)
	if err != nil {
		return "", "", err
	}
	lock, err := readLock(filepath.Join(dir, "template.lock"))
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(lock.TemplateID) == "" || !semverPattern.MatchString(lock.TemplateVersion) {
		return "", "", upgradeError("LOCK_INVALID", "template.lock has invalid template identity or version")
	}
	return lock.TemplateID, lock.TemplateVersion, nil
}

// FetchTemplate downloads, verifies and safely extracts a template artifact
// into a staging registry that Upgrade accepts as its template root. The
// returned cleanup removes the staging tree; call it after Upgrade finishes.
// FetchTemplate 下载、校验并安全解压模板工件到暂存注册表，其布局与 Upgrade 接受的
// template root 兼容。返回的 cleanup 在 Upgrade 结束后清除暂存树。
func FetchTemplate(ctx context.Context, options FetchOptions, templateID, version string) (string, func(), error) {
	base := strings.TrimRight(strings.TrimSpace(options.BaseURL), "/")
	if base == "" {
		return "", nil, upgradeError("REGISTRY_URL_REQUIRED", "registry base URL is required")
	}
	if len(options.PublicKey) != ed25519.PublicKeySize {
		return "", nil, upgradeError("REGISTRY_KEY_REQUIRED", "an ed25519 registry public key is required")
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: remoteFetchTimeout, CheckRedirect: limitedRedirects}
	}
	indexBytes, err := fetchLimited(ctx, client, base+"/registry/index.json", remoteIndexSizeLimit)
	if err != nil {
		return "", nil, upgradeError("REGISTRY_INDEX_UNAVAILABLE", err.Error())
	}
	sigBytes, err := fetchLimited(ctx, client, base+"/registry/index.json.sig", remoteSignatureLimit)
	if err != nil {
		return "", nil, upgradeError("REGISTRY_INDEX_UNAVAILABLE", err.Error())
	}
	if err := verifyDetached(options.PublicKey, indexBytes, strings.TrimSpace(string(sigBytes)), "REGISTRY_INDEX_SIGNATURE_INVALID"); err != nil {
		return "", nil, err
	}
	var index RemoteIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return "", nil, upgradeError("REGISTRY_INDEX_INVALID", "registry index must be valid JSON")
	}
	if index.RegistryVersion != remoteIndexFormat {
		return "", nil, upgradeError("REGISTRY_INDEX_INVALID", "unsupported registry format: "+index.RegistryVersion)
	}
	entry, err := findRemoteVersion(index, templateID, version)
	if err != nil {
		return "", nil, err
	}
	archiveBytes, err := fetchLimited(ctx, client, base+"/"+strings.TrimPrefix(entry.Archive, "/"), remoteArchiveSizeLimit)
	if err != nil {
		return "", nil, upgradeError("REGISTRY_ARCHIVE_UNAVAILABLE", err.Error())
	}
	if err := verifyDetached(options.PublicKey, archiveBytes, entry.Signature, "REGISTRY_SIGNATURE_INVALID"); err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(archiveBytes)
	if hex.EncodeToString(digest[:]) != strings.ToLower(entry.SHA256) {
		return "", nil, upgradeError("REGISTRY_DIGEST_MISMATCH", "archive digest does not match the signed index")
	}
	staging, err := os.MkdirTemp("", "agentctl-registry-*")
	if err != nil {
		return "", nil, upgradeError("REGISTRY_STAGING_FAILED", err.Error())
	}
	cleanup := func() { _ = os.RemoveAll(staging) }
	target := filepath.Join(staging, filepath.FromSlash(templateID), version)
	if err := extractTarGz(archiveBytes, target, defaultExtractLimits); err != nil {
		cleanup()
		return "", nil, err
	}
	// A local-format index makes the verified staging tree indistinguishable
	// from a reviewed local registry for the existing Upgrade code path.
	// 本地格式的 index 让已通过校验的暂存树在既有 Upgrade 代码路径看来与经过评审的
	// 本地注册表完全一致。
	localIndex := "# generated from the verified remote index\nversion: v1\ntemplates:\n  - id: " + templateID + "\n    version: " + version + "\n"
	if err := os.MkdirAll(filepath.Join(staging, "registry"), 0755); err != nil {
		cleanup()
		return "", nil, upgradeError("REGISTRY_STAGING_FAILED", err.Error())
	}
	if err := os.WriteFile(filepath.Join(staging, "registry", "index.yaml"), []byte(localIndex), 0644); err != nil {
		cleanup()
		return "", nil, upgradeError("REGISTRY_STAGING_FAILED", err.Error())
	}
	return staging, cleanup, nil
}

func limitedRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= remoteMaxHTTPRedirs {
		return errors.New("too many redirects")
	}
	return nil
}

func fetchLimited(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	return readAllLimited(resp.Body, limit)
}

func verifyDetached(key ed25519.PublicKey, data []byte, signature, failureCode string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return upgradeError(failureCode, "signature must be base64 ed25519")
	}
	if !ed25519.Verify(key, data, sig) {
		return upgradeError(failureCode, "ed25519 signature verification failed")
	}
	return nil
}

func findRemoteVersion(index RemoteIndex, templateID, version string) (RemoteVersion, error) {
	if !semverPattern.MatchString(strings.TrimSpace(version)) {
		return RemoteVersion{}, upgradeError("TEMPLATE_VERSION_INVALID", "--to-template-version must be MAJOR.MINOR.PATCH")
	}
	for _, template := range index.Templates {
		if strings.TrimSpace(template.ID) != templateID {
			continue
		}
		for _, entry := range template.Versions {
			if strings.TrimSpace(entry.Version) != version {
				continue
			}
			if _, relErr := safeRelative(entry.Archive); relErr != nil || !isSHA256(strings.ToLower(entry.SHA256)) {
				return RemoteVersion{}, upgradeError("REGISTRY_INDEX_INVALID", "index entry has an unsafe archive path or digest")
			}
			if strings.TrimSpace(entry.Signature) == "" {
				return RemoteVersion{}, upgradeError("REGISTRY_INDEX_INVALID", "index entry is missing an archive signature")
			}
			return entry, nil
		}
		return RemoteVersion{}, upgradeError("TEMPLATE_VERSION_UNAVAILABLE", "requested template version is not registered")
	}
	return RemoteVersion{}, upgradeError("TEMPLATE_NOT_FOUND", "template is not registered remotely: "+templateID)
}

// extractTarGz unpacks a verified archive into dest, refusing every dangerous
// entry type and bounding total decompressed size, per-file size and file
// count. Only regular files and directories are legal; symlinks, hardlinks,
// device nodes, fifos and duplicate paths are rejected before any write.
// extractTarGz 将已校验的压缩包解压到 dest，拒绝所有危险条目类型，并限制总解压
// 大小、单文件大小与文件数。仅允许普通文件与目录；symlink、hardlink、设备节点、
// fifo 与重复路径在任何写入之前即被拒绝。
func extractTarGz(archive []byte, dest string, limits extractLimits) error {
	if limits.uncompressedTotal <= 0 || limits.perFile <= 0 || limits.maxFiles <= 0 {
		return upgradeError("REGISTRY_ARCHIVE_UNSAFE", "extract limits must be positive")
	}
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return upgradeError("REGISTRY_ARCHIVE_INVALID", "artifact is not valid gzip")
	}
	defer zr.Close()
	total := &countingLimitReader{r: zr, remaining: limits.uncompressedTotal}
	tr := tar.NewReader(total)
	seen := make(map[string]bool)
	files := 0
	for {
		header, headerErr := tr.Next()
		if errors.Is(headerErr, io.EOF) {
			break
		}
		if headerErr != nil {
			return upgradeError("REGISTRY_ARCHIVE_UNSAFE", "tar stream is malformed")
		}
		// The conventional "./" root directory entry carries no data and is
		// skipped; every other name goes through the path safety gate.
		// 常见的 "./" 根目录条目不含数据直接跳过；其余名称都要经过路径安全门。
		if header.Typeflag == tar.TypeDir {
			trimmed := strings.TrimSuffix(strings.TrimSpace(header.Name), "/")
			if trimmed == "" || trimmed == "." {
				continue
			}
		}
		rel, pathErr := safeArchivePath(header.Name)
		if pathErr != nil {
			return upgradeError("REGISTRY_ARCHIVE_UNSAFE", fmt.Sprintf("unsafe archive entry: %q", header.Name))
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if rel == "." {
				continue
			}
			if seen[rel] {
				return upgradeError("REGISTRY_ARCHIVE_UNSAFE", "duplicate archive entry: "+rel)
			}
			seen[rel] = true
			if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(rel)), 0755); err != nil {
				return upgradeError("REGISTRY_STAGING_FAILED", err.Error())
			}
		case tar.TypeReg:
			files++
			if files > limits.maxFiles {
				return upgradeError("REGISTRY_ARCHIVE_TOO_LARGE", "archive exceeds the file count limit")
			}
			if seen[rel] {
				return upgradeError("REGISTRY_ARCHIVE_UNSAFE", "duplicate archive entry: "+rel)
			}
			seen[rel] = true
			if header.Size > limits.perFile {
				return upgradeError("REGISTRY_ARCHIVE_TOO_LARGE", "archive file exceeds the per-file limit: "+rel)
			}
			data, readErr := readAllLimited(tr, limits.perFile)
			if readErr != nil {
				return upgradeError("REGISTRY_ARCHIVE_TOO_LARGE", "archive file exceeds the per-file limit: "+rel)
			}
			if err := writeAtomic(filepath.Join(dest, filepath.FromSlash(rel)), data); err != nil {
				return upgradeError("REGISTRY_STAGING_FAILED", err.Error())
			}
		default:
			// Symlinks, hardlinks, char/block devices, fifos and any extension
			// type are refused outright: a template is plain files only.
			// symlink、hardlink、字符/块设备、fifo 及任何扩展类型一律拒绝：
			// 模板只允许普通文件。
			return upgradeError("REGISTRY_ARCHIVE_UNSAFE", fmt.Sprintf("entry %q has unsupported type %q", header.Name, header.Typeflag))
		}
	}
	if files == 0 {
		return upgradeError("REGISTRY_ARCHIVE_UNSAFE", "archive contains no template files")
	}
	if total.exceeded {
		return upgradeError("REGISTRY_ARCHIVE_TOO_LARGE", "archive exceeds the total uncompressed size limit")
	}
	return nil
}

// safeArchivePath validates one tar entry name: tar names use slash separators,
// so absolute paths, traversal, dot cleanup and Windows device names are all
// rejected before the path ever joins the destination.
// safeArchivePath 校验单个 tar 条目名：tar 名使用斜杠分隔，因此绝对路径、穿越、
// 点号清理与 Windows 设备名都会在路径拼接目标之前被拒绝。
func safeArchivePath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty archive entry name")
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\x00") {
		return "", errors.New("absolute or binary archive entry name")
	}
	return safeRelative(name)
}

// readAllLimited reads at most limit bytes and errors when more remain, so a
// lying Content-Length or tar header cannot turn into a silent truncation.
// readAllLimited 最多读取 limit 字节，超出即报错；虚假的 Content-Length 或 tar 头
// 因此不可能变成静默截断。
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("payload exceeds size limit")
	}
	return data, nil
}

// countingLimitReader fails the stream once the cumulative decompressed bytes
// pass the cap instead of truncating like io.LimitedReader.
// countingLimitReader 在累计解压字节超过上限时让流失败，而不是像 io.LimitedReader
// 那样静默截断。
type countingLimitReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
}

func (c *countingLimitReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.exceeded = true
		return 0, errors.New("archive exceeds the total uncompressed size limit")
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}
