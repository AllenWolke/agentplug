package template

// Upgrade contains the code-ownership aware template upgrade operation.
// Upgrade 负责按代码所有权和摘要执行安全的模板升级。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var semverPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// UpgradeOptions describes a single immutable template registry upgrade.
// UpgradeOptions 描述一次不可变模板注册表升级。
type UpgradeOptions struct {
	Workspace    string
	TemplateRoot string
	ToVersion    string
	DryRun       bool
}

// OwnershipLock is the v1 lock written by agentctl create.
// OwnershipLock 是 agentctl create 写出的 v1 文件所有权锁。
type OwnershipLock struct {
	LockVersion     string          `json:"lock_version"`
	TemplateID      string          `json:"template_id"`
	TemplateVersion string          `json:"template_version"`
	Files           []OwnershipFile `json:"files"`
	// These fields keep old locks readable so the CLI can report a stable
	// migration error instead of silently replacing user files.
	// 保留旧字段以便给出稳定迁移错误，绝不静默覆盖用户文件。
	ManagedPaths  []string `json:"managed_paths,omitempty"`
	BusinessPaths []string `json:"business_paths,omitempty"`
}

type OwnershipFile struct {
	Path    string `json:"path"`
	Owner   string `json:"owner"`
	SHA256  string `json:"sha256"`
	Mutable *bool  `json:"mutable,omitempty"`
}

// UpgradeConflict is intentionally hash based. It can be rendered by both a
// human CLI and an automation client without exposing file contents.
// UpgradeConflict 只输出摘要，既适合人工 CLI 也适合自动化客户端，避免泄露业务内容。
type UpgradeConflict struct {
	Path           string `json:"path"`
	Reason         string `json:"reason"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	DesiredSHA256  string `json:"desired_sha256,omitempty"`
}

// UpgradeReport is a stable, machine-readable report for --json.
// UpgradeReport 是 --json 的稳定机器可读结果。
type UpgradeReport struct {
	Status      string            `json:"status"`
	Workspace   string            `json:"workspace"`
	TemplateID  string            `json:"template_id"`
	FromVersion string            `json:"from_version"`
	ToVersion   string            `json:"to_version"`
	WouldChange bool              `json:"would_change"`
	Updated     []string          `json:"updated,omitempty"`
	Added       []string          `json:"added,omitempty"`
	Unchanged   []string          `json:"unchanged,omitempty"`
	Conflicts   []UpgradeConflict `json:"conflicts,omitempty"`
}

// UpgradeError exposes a stable code for CLI callers and tests.
// UpgradeError 向 CLI 调用方和测试暴露稳定错误码。
type UpgradeError struct {
	Code string
	Msg  string
}

func (e *UpgradeError) Error() string { return e.Msg }

func upgradeError(code, msg string) error { return &UpgradeError{Code: code, Msg: msg} }

// BuildOwnershipLock records a digest for every regular file in a generated
// workspace. It deliberately excludes template.lock itself because a lock
// cannot safely contain its own digest.
// BuildOwnershipLock 为生成工作区的每个普通文件记录摘要；刻意排除自身，避免自引用摘要。
func BuildOwnershipLock(workspace, templateID, templateVersion string) (OwnershipLock, error) {
	if strings.TrimSpace(templateID) == "" || !semverPattern.MatchString(templateVersion) {
		return OwnershipLock{}, upgradeError("LOCK_INVALID", "template identity or version is invalid")
	}
	if _, err := resolveWorkspace(workspace); err != nil {
		return OwnershipLock{}, err
	}
	lock := OwnershipLock{LockVersion: "v1", TemplateID: templateID, TemplateVersion: templateVersion}
	err := filepath.WalkDir(workspace, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("workspace symlink is not allowed")
		}
		rel, err := filepath.Rel(workspace, path)
		if err != nil {
			return err
		}
		rel, err = safeRelative(rel)
		if err != nil {
			return err
		}
		if rel == "template.lock" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		owner := ownershipForPath(rel)
		lock.Files = append(lock.Files, OwnershipFile{Path: rel, Owner: owner, SHA256: hex.EncodeToString(h[:]), Mutable: boolPtr(owner != "business-owned")})
		return nil
	})
	if err != nil {
		return OwnershipLock{}, upgradeError("LOCK_BUILD_FAILED", err.Error())
	}
	sort.Slice(lock.Files, func(i, j int) bool { return lock.Files[i].Path < lock.Files[j].Path })
	return lock, nil
}

func ownershipForPath(path string) string {
	path = filepath.ToSlash(path)
	for _, prefix := range []string{"domain/", "graph/", "prompts/", "eval/", "tools/"} {
		if strings.HasPrefix(path, prefix) {
			return "business-owned"
		}
	}
	if path == "manifest.json" || strings.HasPrefix(path, "platform_entry/") {
		return "template-managed"
	}
	return "generated"
}

// Upgrade performs a dry-run plan or applies only files that are both
// generator-owned and unchanged since the lock was written. Business-owned
// files are never touched. All target writes are path checked and each file is
// replaced through a same-directory temporary file.
// Upgrade 只计划或应用“生成器拥有且自锁定后未被修改”的文件；业务文件永不覆盖。
// 所有路径均校验，文件通过同目录临时文件替换，兼容 Windows/Linux/macOS。
func Upgrade(options UpgradeOptions) (UpgradeReport, error) {
	workspace, err := resolveWorkspace(options.Workspace)
	if err != nil {
		return UpgradeReport{}, err
	}
	if !semverPattern.MatchString(strings.TrimSpace(options.ToVersion)) {
		return UpgradeReport{}, upgradeError("TEMPLATE_VERSION_INVALID", "--to-template-version must be MAJOR.MINOR.PATCH")
	}
	lock, err := readLock(filepath.Join(workspace, "template.lock"))
	if err != nil {
		return UpgradeReport{}, err
	}
	manifestTemplateID, agentID, err := readManifestIdentity(filepath.Join(workspace, "manifest.json"))
	if err != nil {
		return UpgradeReport{}, err
	}
	if manifestTemplateID != "" && manifestTemplateID != lock.TemplateID {
		return UpgradeReport{}, upgradeError("MANIFEST_LOCK_MISMATCH", "manifest agent template id does not match template.lock")
	}
	if strings.TrimSpace(lock.TemplateID) == "" || !semverPattern.MatchString(lock.TemplateVersion) {
		return UpgradeReport{}, upgradeError("LOCK_INVALID", "template.lock has invalid template identity or version")
	}
	if len(lock.Files) == 0 {
		return UpgradeReport{}, upgradeError("LOCK_NEEDS_REGENERATE", "template.lock has no per-file ownership digests; regenerate with the current agentctl")
	}
	root := strings.TrimSpace(options.TemplateRoot)
	if root == "" {
		root = os.Getenv("AGENTCTL_TEMPLATE_ROOT")
	}
	if root == "" {
		for _, candidate := range []string{"templates", filepath.Join("..", "..", "..", "templates")} {
			if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
				root = candidate
				break
			}
		}
	}
	if root == "" {
		return UpgradeReport{}, upgradeError("TEMPLATE_REGISTRY_MISSING", "template registry unavailable")
	}
	root, err = filepath.Abs(filepath.Clean(root))
	if err != nil {
		return UpgradeReport{}, upgradeError("TEMPLATE_REGISTRY_MISSING", "template registry path is invalid")
	}
	if err := ensureDir(root); err != nil {
		return UpgradeReport{}, upgradeError("TEMPLATE_REGISTRY_MISSING", err.Error())
	}
	if err := verifyRegistryVersion(root, lock.TemplateID, options.ToVersion); err != nil {
		return UpgradeReport{}, err
	}
	source, err := resolveTemplate(root, lock.TemplateID, options.ToVersion)
	if err != nil {
		return UpgradeReport{}, err
	}
	files, err := readTemplateFiles(source, options.ToVersion, agentID)
	if err != nil {
		return UpgradeReport{}, err
	}

	lockByPath := make(map[string]OwnershipFile, len(lock.Files))
	for _, entry := range lock.Files {
		rel, relErr := safeRelative(entry.Path)
		if relErr != nil || !validOwner(entry.Owner) || !isSHA256(entry.SHA256) {
			return UpgradeReport{}, upgradeError("LOCK_INVALID", "template.lock contains an unsafe path, owner or digest")
		}
		if _, exists := lockByPath[rel]; exists {
			return UpgradeReport{}, upgradeError("LOCK_INVALID", "template.lock contains duplicate file paths")
		}
		entry.Path = rel
		lockByPath[rel] = entry
	}
	report := UpgradeReport{Status: "no_changes", Workspace: workspace, TemplateID: lock.TemplateID, FromVersion: lock.TemplateVersion, ToVersion: options.ToVersion}
	newLock := lock
	newLock.TemplateVersion = options.ToVersion
	newEntries := make(map[string]OwnershipFile, len(lockByPath)+len(files))
	for path, entry := range lockByPath {
		newEntries[path] = entry
	}
	for _, file := range files {
		entry, exists := lockByPath[file.Path]
		if !exists {
			target, targetErr := checkedTargetPath(workspace, file.Path)
			if targetErr != nil {
				return UpgradeReport{}, upgradeError("WORKSPACE_PATH_UNSAFE", targetErr.Error())
			}
			if _, statErr := os.Lstat(target); statErr == nil {
				report.Conflicts = append(report.Conflicts, UpgradeConflict{Path: file.Path, Reason: "unlocked target file would be overwritten", DesiredSHA256: file.SHA256})
				continue
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return UpgradeReport{}, upgradeError("WORKSPACE_READ_FAILED", statErr.Error())
			}
			entry = OwnershipFile{Path: file.Path, Owner: "template-managed", SHA256: file.SHA256, Mutable: boolPtr(true)}
			newEntries[file.Path] = entry
			report.Added = append(report.Added, file.Path)
			report.WouldChange = true
			continue
		}
		if !validOwner(entry.Owner) || (entry.Owner != "template-managed" && entry.Owner != "generated") {
			// Source files must never replace a business-owned or external file.
			// 模板源文件绝不能覆盖业务文件或外置适配器文件。
			continue
		}
		target, targetErr := checkedTargetPath(workspace, file.Path)
		if targetErr != nil {
			return UpgradeReport{}, upgradeError("WORKSPACE_PATH_UNSAFE", targetErr.Error())
		}
		actual, exists, statErr := fileDigest(target)
		if statErr != nil {
			return UpgradeReport{}, upgradeError("WORKSPACE_READ_FAILED", statErr.Error())
		}
		if !exists {
			report.Conflicts = append(report.Conflicts, UpgradeConflict{Path: file.Path, Reason: "managed file was deleted", ExpectedSHA256: entry.SHA256, DesiredSHA256: file.SHA256})
			continue
		}
		if actual != entry.SHA256 && actual != file.SHA256 {
			report.Conflicts = append(report.Conflicts, UpgradeConflict{Path: file.Path, Reason: "managed file was modified after generation", ExpectedSHA256: entry.SHA256, ActualSHA256: actual, DesiredSHA256: file.SHA256})
			continue
		}
		if actual == file.SHA256 {
			report.Unchanged = append(report.Unchanged, file.Path)
			entry.SHA256 = file.SHA256
			newEntries[file.Path] = entry
			continue
		}
		if entry.Mutable != nil && !*entry.Mutable {
			report.Conflicts = append(report.Conflicts, UpgradeConflict{Path: file.Path, Reason: "managed file is immutable", ExpectedSHA256: entry.SHA256, ActualSHA256: actual, DesiredSHA256: file.SHA256})
			continue
		}
		entry.SHA256 = file.SHA256
		newEntries[file.Path] = entry
		report.Updated = append(report.Updated, file.Path)
		report.WouldChange = true
	}
	// Keep sorted output stable for scripts, logs and golden tests.
	// 对输出排序，确保脚本、日志和 Golden Test 稳定。
	sort.Strings(report.Updated)
	sort.Strings(report.Added)
	sort.Strings(report.Unchanged)
	sort.Slice(report.Conflicts, func(i, j int) bool { return report.Conflicts[i].Path < report.Conflicts[j].Path })
	if len(report.Conflicts) > 0 {
		report.Status = "conflict"
		return report, upgradeError("UPGRADE_CONFLICT", "one or more generator-owned files changed; no files were written")
	}
	if !report.WouldChange {
		report.Status = "no_changes"
		return report, nil
	}
	report.Status = "planned"
	if options.DryRun {
		return report, nil
	}
	newLock.Files = make([]OwnershipFile, 0, len(newEntries))
	for _, entry := range newEntries {
		newLock.Files = append(newLock.Files, entry)
	}
	sort.Slice(newLock.Files, func(i, j int) bool { return newLock.Files[i].Path < newLock.Files[j].Path })
	for _, file := range files {
		if !contains(report.Updated, file.Path) && !contains(report.Added, file.Path) {
			continue
		}
		if err := writeAtomic(filepath.Join(workspace, filepath.FromSlash(file.Path)), file.Content); err != nil {
			return report, upgradeError("UPGRADE_WRITE_FAILED", err.Error())
		}
	}
	lockRaw, err := json.MarshalIndent(newLock, "", "  ")
	if err != nil {
		return report, upgradeError("UPGRADE_WRITE_FAILED", err.Error())
	}
	if err := writeAtomic(filepath.Join(workspace, "template.lock"), append(lockRaw, '\n')); err != nil {
		return report, upgradeError("UPGRADE_WRITE_FAILED", err.Error())
	}
	report.Status = "upgraded"
	return report, nil
}

type templateFile struct {
	Path    string
	Content []byte
	SHA256  string
}

func readTemplateFiles(source, version, agentID string) ([]templateFile, error) {
	var files []templateFile
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("template symlink is not allowed: %s", path)
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		rel, err = safeRelative(rel)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > 8<<20 {
			return fmt.Errorf("template file too large: %s", rel)
		}
		// Only the agent identity is rendered. No template file is executed.
		// 只渲染 Agent 身份，不执行任何模板文件。
		data = []byte(strings.ReplaceAll(string(data), "{{agent_id}}", agentID))
		h := sha256.Sum256(data)
		files = append(files, templateFile{Path: filepath.ToSlash(rel), Content: data, SHA256: hex.EncodeToString(h[:])})
		return nil
	})
	if err != nil {
		return nil, upgradeError("TEMPLATE_READ_FAILED", err.Error())
	}
	_ = version
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func readLock(path string) (OwnershipLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return OwnershipLock{}, upgradeError("LOCK_MISSING", "template.lock is required")
		}
		return OwnershipLock{}, upgradeError("LOCK_READ_FAILED", err.Error())
	}
	var lock OwnershipLock
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lock); err != nil {
		return OwnershipLock{}, upgradeError("LOCK_INVALID", "template.lock must be valid JSON")
	}
	if lock.LockVersion != "v1" {
		return OwnershipLock{}, upgradeError("LOCK_INVALID", "template.lock lock_version must be v1")
	}
	return lock, nil
}

func readManifestIdentity(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", upgradeError("MANIFEST_MISSING", "manifest.json is required")
		}
		return "", "", upgradeError("MANIFEST_READ_FAILED", err.Error())
	}
	var m struct {
		AgentID  string            `json:"agent_id"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return "", "", upgradeError("MANIFEST_INVALID", "manifest.json must be valid JSON")
	}
	return m.Metadata["template_id"], m.AgentID, nil
}

func resolveWorkspace(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", upgradeError("WORKSPACE_REQUIRED", "--workspace or --path is required")
	}
	path := filepath.Clean(raw)
	if strings.Contains(filepath.Base(path), "\x00") {
		return "", upgradeError("WORKSPACE_INVALID", "workspace path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", upgradeError("WORKSPACE_NOT_FOUND", err.Error())
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", upgradeError("WORKSPACE_INVALID", "workspace must be a real directory")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", upgradeError("WORKSPACE_INVALID", err.Error())
	}
	return filepath.Clean(abs), nil
}

func resolveTemplate(root, id, version string) (string, error) {
	versioned := filepath.Join(root, id, version)
	if info, err := os.Lstat(versioned); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return versioned, nil
	}
	plain := filepath.Join(root, id)
	if info, err := os.Lstat(plain); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", upgradeError("TEMPLATE_NOT_FOUND", id)
	}
	return plain, nil
}

func verifyRegistryVersion(root, id, version string) error {
	data, err := os.ReadFile(filepath.Join(root, "registry", "index.yaml"))
	if err != nil {
		return upgradeError("TEMPLATE_REGISTRY_INVALID", "registry/index.yaml is required")
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	found := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "- id:") {
			found = strings.TrimSpace(strings.TrimPrefix(trim, "- id:")) == id
			continue
		}
		if found && strings.HasPrefix(trim, "version:") {
			if strings.TrimSpace(strings.TrimPrefix(trim, "version:")) == version {
				return nil
			}
			// The next template begins before another version line.
			_ = i
		}
	}
	return upgradeError("TEMPLATE_VERSION_UNAVAILABLE", "requested template version is not registered")
}

func ensureDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}
	return nil
}

func safeRelative(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" || filepath.IsAbs(raw) || filepath.VolumeName(raw) != "" {
		return "", errors.New("unsafe relative path")
	}
	clean := filepath.Clean(filepath.FromSlash(raw))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe relative path")
	}
	for _, part := range strings.FieldsFunc(clean, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." || isWindowsDeviceName(part) {
			return "", errors.New("unsafe relative path")
		}
	}
	return filepath.ToSlash(clean), nil
}

func isWindowsDeviceName(part string) bool {
	base := strings.ToUpper(strings.TrimSuffix(part, "."))
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" {
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

func validOwner(owner string) bool {
	return owner == "business-owned" || owner == "template-managed" || owner == "generated" || owner == "external-adapter"
}

func isSHA256(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}
func boolPtr(v bool) *bool { return &v }
func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func fileDigest(path string) (string, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false, errors.New("managed target must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), true, nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agentctl-upgrade-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// checkedTargetPath prevents a managed relative path from traversing a
// symlinked directory (including Windows junctions exposed as symlinks).
// checkedTargetPath 防止受管相对路径穿过符号链接目录（包括表现为符号链接的 Windows Junction）。
func checkedTargetPath(workspace, raw string) (string, error) {
	rel, err := safeRelative(raw)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(workspace)
	parts := strings.Split(filepath.FromSlash(rel), string(os.PathSeparator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			// New files and directories are safe after all existing parents have
			// been checked; writeAtomic will create them on the same volume.
			// 新文件/目录在既有父级都检查后是安全的；writeAtomic 会在同一卷创建。
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("managed path contains a symlink")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", errors.New("managed path parent is not a directory")
		}
	}
	return filepath.Join(workspace, filepath.FromSlash(rel)), nil
}
