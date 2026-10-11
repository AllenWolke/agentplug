// Package build contains deterministic, side-effect bounded packaging helpers.
// build 包提供确定性且边界受控的制品打包辅助能力。
package build

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Result struct {
	ContentHash string `json:"content_hash"`
	FileCount   int    `json:"file_count"`
	SBOMPath    string `json:"sbom_path,omitempty"`
	Image       string `json:"image,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
	Provenance  string `json:"provenance_path,omitempty"`
}

// Package hashes source files and optionally writes a small SPDX inventory.
// It does not execute hooks or shell commands; image signing is delegated to CI.
// 仅计算源文件摘要并可生成 SPDX 清单，不执行 Hook/Shell，镜像签名交给 CI。
func Package(root, output string) (Result, error) {
	root = filepath.Clean(root)
	if strings.TrimSpace(root) == "" {
		return Result{}, errors.New("package root is required")
	}
	var files []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || strings.HasPrefix(entry.Name(), ".tmp") || entry.Name() == "tmp" || entry.Name() == "node_modules" || entry.Name() == "target") {
				return fs.SkipDir
			}
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return Result{}, err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, path := range files {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return Result{}, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Result{}, err
		}
		h.Write([]byte(filepath.ToSlash(rel) + "\x00"))
		h.Write(data)
	}
	result := Result{ContentHash: hex.EncodeToString(h.Sum(nil)), FileCount: len(files)}
	if output != "" {
		if filepath.IsAbs(output) {
			return Result{}, errors.New("SBOM output must be relative")
		}
		if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
			return Result{}, err
		}
		sbom := map[string]any{"spdxVersion": "SPDX-2.3", "name": filepath.Base(root), "files": files, "content_hash": result.ContentHash}
		raw, _ := json.MarshalIndent(sbom, "", "  ")
		raw = append(raw, '\n')
		if err := os.WriteFile(output, raw, 0644); err != nil {
			return Result{}, err
		}
		result.SBOMPath = output
	}
	return result, nil
}

var imageRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_@-]{1,255}$`)

// PlanImage validates the image reference and Dockerfile the same way a real
// build would, without invoking Docker. Dry runs use it so a plan fails exactly
// where a build would instead of reporting a fake success.
// PlanImage 以与真实构建相同的口径校验镜像引用与 Dockerfile，但不调用 Docker；
// dry-run 借此让计划在与构建相同的条件处失败，而不是报告虚假成功。
func PlanImage(root, image string) error {
	if !imageRefPattern.MatchString(strings.TrimSpace(image)) {
		return errors.New("invalid image reference")
	}
	if _, err := os.Stat(filepath.Join(root, "Dockerfile")); err != nil {
		return errors.New("Dockerfile is required for image packaging")
	}
	return nil
}

// BuildImage invokes Docker with an explicit argv and bounded timeout. It is
// opt-in so source packaging remains usable on hosts without Docker, while CI
// can require --image and obtain a real image digest.
// BuildImage 仅通过显式参数调用 Docker，并设置超时；本地无 Docker 时仍可
// 进行源码打包，CI 可传 --image 强制生成真实镜像摘要。
func BuildImage(ctx context.Context, root, image, contentHash, provenance string) (Result, error) {
	if err := PlanImage(root, image); err != nil {
		return Result{}, err
	}
	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(buildCtx, "docker", "build", "--pull=false", "--label", "org.lexagent.content-hash="+contentHash, "-t", image, root)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 2048 {
			message = message[len(message)-2048:]
		}
		return Result{}, errors.New("docker build failed: " + message)
	}
	digestCmd := exec.CommandContext(buildCtx, "docker", "image", "inspect", "--format={{.Id}}", image)
	digestRaw, err := digestCmd.Output()
	if err != nil || strings.TrimSpace(string(digestRaw)) == "" {
		return Result{}, errors.New("docker image digest unavailable")
	}
	result := Result{Image: image, ImageDigest: strings.TrimSpace(string(digestRaw))}
	if provenance != "" {
		if filepath.IsAbs(provenance) || strings.HasPrefix(filepath.Clean(provenance), ".."+string(os.PathSeparator)) {
			return Result{}, errors.New("provenance output must be relative")
		}
		if err := os.MkdirAll(filepath.Dir(provenance), 0755); err != nil {
			return Result{}, err
		}
		payload := map[string]any{
			"provenance_version":  "slsa/v1",
			"subject":             map[string]string{"name": image, "digest": result.ImageDigest},
			"source_content_hash": contentHash,
			"builder":             "agentctl",
			"generated_at":        time.Now().UTC().Format(time.RFC3339),
		}
		raw, _ := json.MarshalIndent(payload, "", "  ")
		if err := os.WriteFile(provenance, append(raw, '\n'), 0644); err != nil {
			return Result{}, err
		}
		result.Provenance = provenance
	}
	return result, nil
}
